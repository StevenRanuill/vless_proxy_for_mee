from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import requests
import yaml


# ============================================================
# Skibidi_tualet_proxy
# VLESS Subscription Fetcher
# ============================================================


PROJECT_NAME = "Skibidi_tualet_proxy"

BASE_DIR = Path(__file__).resolve().parent

SOURCES_FILE = BASE_DIR / "sources.yml"

OUTPUT_DIR = BASE_DIR / "output"
CHUNKS_DIR = OUTPUT_DIR / "chunks"

VALID_FILE = OUTPUT_DIR / "valid_vless.txt"
INVALID_FILE = OUTPUT_DIR / "invalid_vless.txt"
DUPLICATES_FILE = OUTPUT_DIR / "duplicates.txt"
STATS_FILE = OUTPUT_DIR / "stats.json"


DEFAULT_TIMEOUT = 30

USER_AGENT = (
    "Mozilla/5.0 "
    "(Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 "
    "(KHTML, like Gecko) "
    "Chrome/131.0 Safari/537.36"
)


VLESS_PATTERN = re.compile(
    r"vless://[^\s<>'\"`]+",
    re.IGNORECASE,
)


UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}$"
)


# ============================================================
# Logging
# ============================================================


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger(PROJECT_NAME)


# ============================================================
# Helpers
# ============================================================


def ensure_directories() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    CHUNKS_DIR.mkdir(parents=True, exist_ok=True)


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be an object: {path}")

    return data


def clean_text(value: str) -> str:
    value = value.strip()
    value = value.replace("\r", "")
    value = value.replace("\n", "")
    return value


def normalize_uri(uri: str) -> str:
    uri = clean_text(uri)

    uri = uri.rstrip(".,;:!?)]}>")

    return uri


def is_valid_uuid(value: str) -> bool:
    return bool(UUID_PATTERN.fullmatch(value))


def is_valid_port(value: str) -> bool:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return False

    return 1 <= port <= 65535


def is_valid_host(host: str) -> bool:
    if not host:
        return False

    host = host.strip("[]")

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    if len(host) > 253:
        return False

    if " " in host:
        return False

    if "." not in host and host.lower() != "localhost":
        return False

    labels = host.split(".")

    for label in labels:
        if not label:
            return False

        if len(label) > 63:
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

        if not re.fullmatch(r"[A-Za-z0-9-]+", label):
            return False

    return True


def decode_base64_text(value: str) -> str | None:
    value = value.strip()

    if not value:
        return None

    padding = "=" * (-len(value) % 4)

    try:
        decoded = base64.b64decode(
            value + padding,
            validate=False,
        )

        return decoded.decode("utf-8", errors="ignore")

    except Exception:
        return None


def extract_vless_uris(text: str) -> list[str]:
    if not text:
        return []

    found: list[str] = []

    for match in VLESS_PATTERN.finditer(text):
        uri = normalize_uri(match.group(0))

        if uri:
            found.append(uri)

    return found


def extract_from_text(text: str) -> list[str]:
    results = extract_vless_uris(text)

    if results:
        return results

    decoded = decode_base64_text(text)

    if decoded:
        return extract_vless_uris(decoded)

    return []


def fingerprint_uri(uri: str) -> str:
    parsed = urlparse(uri)

    query = parse_qs(
        parsed.query,
        keep_blank_values=True,
    )

    fingerprint_data = {
        "uuid": unquote(parsed.username or "").lower(),
        "host": (parsed.hostname or "").lower(),
        "port": parsed.port or 0,
        "query": {
            key: sorted(values)
            for key, values in sorted(query.items())
        },
    }

    raw = json.dumps(
        fingerprint_data,
        ensure_ascii=False,
        sort_keys=True,
    )

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()


# ============================================================
# Source Loading
# ============================================================


def get_sources(config: dict[str, Any]) -> list[dict[str, Any]]:
    sources = config.get("sources", [])

    if isinstance(sources, dict):
        normalized = []

        for name, value in sources.items():
            if isinstance(value, str):
                normalized.append(
                    {
                        "name": name,
                        "url": value,
                        "enabled": True,
                    }
                )

            elif isinstance(value, dict):
                item = dict(value)
                item.setdefault("name", name)
                normalized.append(item)

        return normalized

    if not isinstance(sources, list):
        return []

    result = []

    for index, source in enumerate(sources, start=1):

        if isinstance(source, str):
            result.append(
                {
                    "name": f"source_{index}",
                    "url": source,
                    "enabled": True,
                }
            )

        elif isinstance(source, dict):
            item = dict(source)
            item.setdefault(
                "name",
                f"source_{index}",
            )
            result.append(item)

    return result


# ============================================================
# HTTP Fetching
# ============================================================


def fetch_source(
    session: requests.Session,
    source: dict[str, Any],
) -> tuple[str, str]:

    name = str(
        source.get(
            "name",
            "unknown",
        )
    )

    url = str(
        source.get(
            "url",
            "",
        )
    ).strip()

    if not url:
        raise ValueError("Source URL is empty")

    timeout = source.get(
        "timeout",
        DEFAULT_TIMEOUT,
    )

    try:
        timeout = int(timeout)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT

    response = session.get(
        url,
        timeout=timeout,
        allow_redirects=True,
    )

    response.raise_for_status()

    return name, response.text


# ============================================================
# VLESS Validation
# ============================================================


def validate_vless_uri(
    uri: str,
) -> tuple[bool, str, dict[str, Any]]:

    try:
        parsed = urlparse(uri)

    except Exception as error:
        return (
            False,
            f"url_parse_error: {error}",
            {},
        )

    if parsed.scheme.lower() != "vless":
        return (
            False,
            "invalid_scheme",
            {},
        )

    uuid = unquote(
        parsed.username or ""
    ).strip()

    if not uuid:
        return (
            False,
            "missing_uuid",
            {},
        )

    if not is_valid_uuid(uuid):
        return (
            False,
            "invalid_uuid",
            {},
        )

    host = parsed.hostname

    if not host:
        return (
            False,
            "missing_host",
            {},
        )

    if not is_valid_host(host):
        return (
            False,
            "invalid_host",
            {},
        )

    try:
        port = parsed.port

    except ValueError:
        return (
            False,
            "invalid_port",
            {},
        )

    if port is None:
        return (
            False,
            "missing_port",
            {},
        )

    if not is_valid_port(str(port)):
        return (
            False,
            "invalid_port",
            {},
        )

    query = parse_qs(
        parsed.query,
        keep_blank_values=True,
    )

    security = query.get(
        "security",
        ["none"],
    )[0].lower()

    allowed_security = {
        "none",
        "tls",
        "reality",
    }

    if security not in allowed_security:
        return (
            False,
            "unsupported_security",
            {},
        )

    transport = query.get(
        "type",
        ["tcp"],
    )[0].lower()

    allowed_transports = {
        "tcp",
        "ws",
        "grpc",
        "http",
        "h2",
        "xhttp",
        "kcp",
        "quic",
    }

    if transport not in allowed_transports:
        return (
            False,
            "unsupported_transport",
            {},
        )

    if security == "reality":

        public_key = (
            query.get("pbk", [""])[0]
            or query.get("publicKey", [""])[0]
        )

        if not public_key:
            return (
                False,
                "reality_missing_public_key",
                {},
            )

        sni = (
            query.get("sni", [""])[0]
            or query.get("serverName", [""])[0]
        )

        if not sni:
            return (
                False,
                "reality_missing_sni",
                {},
            )

    if security == "tls":

        sni = query.get(
            "sni",
            [""],
        )[0]

        if not sni:

            server_name = query.get(
                "serverName",
                [""],
            )[0]

            if not server_name:
                return (
                    False,
                    "tls_missing_sni",
                    {},
                )

    if transport == "ws":

        path = query.get(
            "path",
            [""],
        )[0]

        if not path:
            logger.debug(
                "WebSocket URI without path: %s",
                uri,
            )

    if transport == "grpc":

        service_name = query.get(
            "serviceName",
            [""],
        )[0]

        if not service_name:
            logger.debug(
                "gRPC URI without serviceName: %s",
                uri,
            )

    metadata = {
        "uuid": uuid,
        "host": host,
        "port": port,
        "security": security,
        "transport": transport,
    }

    return (
        True,
        "",
        metadata,
    )


# ============================================================
# Output
# ============================================================


def write_lines(
    path: Path,
    lines: list[str],
) -> None:

    unique_lines = list(
        dict.fromkeys(lines)
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:

        if unique_lines:
            file.write(
                "\n".join(unique_lines)
            )

            file.write("\n")


def write_chunks(
    nodes: list[str],
    chunk_size: int = 1000,
) -> None:

    for old_file in CHUNKS_DIR.glob(
        "chunk_*.txt"
    ):
        old_file.unlink()

    if chunk_size <= 0:
        chunk_size = 1000

    for index in range(
        0,
        len(nodes),
        chunk_size,
    ):

        chunk = nodes[
            index:index + chunk_size
        ]

        chunk_number = (
            index // chunk_size
        ) + 1

        path = CHUNKS_DIR / (
            f"chunk_{chunk_number:03d}.txt"
        )

        write_lines(
            path,
            chunk,
        )


def write_statistics(
    stats: dict[str, Any],
) -> None:

    with STATS_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            stats,
            file,
            ensure_ascii=False,
            indent=2,
        )

        file.write("\n")


# ============================================================
# Main Parser
# ============================================================


def run() -> int:

    logger.info(
        "Starting %s",
        PROJECT_NAME,
    )

    ensure_directories()

    try:
        config = load_yaml(
            SOURCES_FILE
        )

    except Exception as error:

        logger.error(
            "Failed to load sources.yml: %s",
            error,
        )

        return 1

    sources = get_sources(
        config
    )

    enabled_sources = [
        source
        for source in sources
        if source.get(
            "enabled",
            True,
        )
    ]

    if not enabled_sources:

        logger.error(
            "No enabled sources found"
        )

        return 1

    logger.info(
        "Configured sources: %d",
        len(enabled_sources),
    )

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        }
    )

    valid_nodes: list[str] = []
    invalid_nodes: list[str] = []
    duplicate_nodes: list[str] = []

    seen_fingerprints: set[str] = set()

    source_statistics: dict[str, dict[str, Any]] = {}

    validation_errors = Counter()
    security_counter = Counter()
    transport_counter = Counter()

    total_downloaded = 0
    successful_sources = 0
    failed_sources = 0

    for source in enabled_sources:

        source_name = str(
            source.get(
                "name",
                "unknown",
            )
        )

        logger.info(
            "Fetching source: %s",
            source_name,
        )

        source_statistics[
            source_name
        ] = {
            "url": source.get(
                "url",
                "",
            ),
            "status": "pending",
            "extracted": 0,
            "valid": 0,
            "invalid": 0,
            "duplicates": 0,
        }

        try:

            _, text = fetch_source(
                session,
                source,
            )

            successful_sources += 1

            extracted = extract_from_text(
                text
            )

            total_downloaded += len(
                text.encode(
                    "utf-8",
                    errors="ignore",
                )
            )

            source_statistics[
                source_name
            ][
                "status"
            ] = "success"

            source_statistics[
                source_name
            ][
                "extracted"
            ] = len(extracted)

            logger.info(
                "%s: extracted %d VLESS URIs",
                source_name,
                len(extracted),
            )

        except Exception as error:

            failed_sources += 1

            source_statistics[
                source_name
            ][
                "status"
            ] = "error"

            source_statistics[
                source_name
            ][
                "error"
            ] = str(error)

            logger.warning(
                "%s: %s",
                source_name,
                error,
            )

            continue

        for raw_uri in extracted:

            uri = normalize_uri(
                raw_uri
            )

            is_valid, reason, metadata = (
                validate_vless_uri(uri)
            )

            if not is_valid:

                invalid_nodes.append(
                    f"{reason}\t{uri}"
                )

                validation_errors[
                    reason
                ] += 1

                source_statistics[
                    source_name
                ][
                    "invalid"
                ] += 1

                continue

            fingerprint = fingerprint_uri(
                uri
            )

            if fingerprint in seen_fingerprints:

                duplicate_nodes.append(
                    uri
                )

                source_statistics[
                    source_name
                ][
                    "duplicates"
                ] += 1

                continue

            seen_fingerprints.add(
                fingerprint
            )

            valid_nodes.append(
                uri
            )

            source_statistics[
                source_name
            ][
                "valid"
            ] += 1

            security_counter[
                metadata[
                    "security"
                ]
            ] += 1

            transport_counter[
                metadata[
                    "transport"
                ]
            ] += 1

    valid_nodes.sort()

    invalid_nodes.sort()

    duplicate_nodes.sort()

    chunk_size = config.get(
        "chunk_size",
        1000,
    )

    try:
        chunk_size = int(
            chunk_size
        )

    except (
        TypeError,
        ValueError,
    ):
        chunk_size = 1000

    write_lines(
        VALID_FILE,
        valid_nodes,
    )

    write_lines(
        INVALID_FILE,
        invalid_nodes,
    )

    write_lines(
        DUPLICATES_FILE,
        duplicate_nodes,
    )

    write_chunks(
        valid_nodes,
        chunk_size,
    )

    stats = {
        "project": PROJECT_NAME,
        "sources": {
            "configured": len(
                enabled_sources
            ),
            "successful": successful_sources,
            "failed": failed_sources,
        },
        "nodes": {
            "valid": len(
                valid_nodes
            ),
            "invalid": len(
                invalid_nodes
            ),
            "duplicates": len(
                duplicate_nodes
            ),
        },
        "download": {
            "bytes": total_downloaded,
        },
        "security": dict(
            security_counter
        ),
        "transports": dict(
            transport_counter
        ),
        "validation_errors": dict(
            validation_errors
        ),
        "sources": source_statistics,
    }

    write_statistics(
        stats
    )

    logger.info(
        "Finished %s",
        PROJECT_NAME,
    )

    logger.info(
        "Valid: %d",
        len(valid_nodes),
    )

    logger.info(
        "Invalid: %d",
        len(invalid_nodes),
    )

    logger.info(
        "Duplicates: %d",
        len(duplicate_nodes),
    )

    logger.info(
        "Output: %s",
        OUTPUT_DIR,
    )

    return 0


# ============================================================
# Entry Point
# ============================================================


if __name__ == "__main__":

    try:
        sys.exit(
            run()
        )

    except KeyboardInterrupt:

        logger.warning(
            "Interrupted by user"
        )

        sys.exit(130)

    except Exception as error:

        logger.exception(
            "Fatal error: %s",
            error,
        )

        sys.exit(1)
