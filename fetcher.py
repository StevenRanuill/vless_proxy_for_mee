
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import requests
import yaml


# ============================================================
# PROJECT
# ============================================================

PROJECT_NAME = "Skibidi_tualet_proxy"

BASE_DIR = Path(__file__).resolve().parent

SOURCES_FILE = BASE_DIR / "sources.yml"

MY_SUB_FILE = BASE_DIR / "my_sub.txt"

OUTPUT_DIR = BASE_DIR / "output"

VALID_FILE = OUTPUT_DIR / "valid_vless.txt"

INVALID_FILE = OUTPUT_DIR / "invalid_vless.txt"

DUPLICATES_FILE = OUTPUT_DIR / "duplicates.txt"

STATS_FILE = OUTPUT_DIR / "stats.json"

SOURCES_STATS_FILE = OUTPUT_DIR / "sources_stats.json"

CHUNKS_DIR = OUTPUT_DIR / "chunks"


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger(PROJECT_NAME)


# ============================================================
# DEFAULT SETTINGS
# ============================================================

DEFAULT_SETTINGS = {
    "workers": 20,
    "timeout": 30,
    "retries": 3,
    "retry_delay": 5,
    "chunk_size": 500,
    "decode_base64": True,
    "decode_url": True,
    "deduplicate": True,
}


# ============================================================
# REGEX
# ============================================================

VLESS_PATTERN = re.compile(
    r"vless://[^\s\"'<>]+",
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
# DIRECTORIES
# ============================================================

def prepare_directories() -> None:
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    CHUNKS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


# ============================================================
# CONFIG
# ============================================================

def load_config() -> dict[str, Any]:
    if not SOURCES_FILE.exists():
        raise FileNotFoundError(
            f"File not found: {SOURCES_FILE}"
        )

    with SOURCES_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:
        config = yaml.safe_load(file)

    if not isinstance(config, dict):
        return {}

    return config


def get_settings(
    config: dict[str, Any],
) -> dict[str, Any]:

    settings = DEFAULT_SETTINGS.copy()

    user_settings = config.get(
        "settings",
        {},
    )

    if isinstance(
        user_settings,
        dict,
    ):
        settings.update(
            user_settings
        )

    return settings


def get_sources(
    config: dict[str, Any],
) -> list[str]:

    sources = config.get(
        "sources",
        [],
    )

    if not isinstance(
        sources,
        list,
    ):
        return []

    result = []

    for source in sources:

        if isinstance(
            source,
            str,
        ):

            source = source.strip()

            if source:
                result.append(source)

    # Удаляем дубликаты URL,
    # сохраняя порядок
    return list(
        dict.fromkeys(result)
    )


# ============================================================
# HTTP
# ============================================================

def create_session() -> requests.Session:

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": (
                "Skibidi_tualet_proxy/2.0"
            ),
            "Accept": "*/*",
        }
    )

    return session


def download_source(
    url: str,
    settings: dict[str, Any],
) -> dict[str, Any]:

    result = {
        "url": url,
        "status": "failed",
        "download_time": 0,
        "bytes": 0,
        "content": "",
        "error": None,
        "attempts": 0,
    }

    started = time.time()

    retries = max(
        1,
        int(
            settings.get(
                "retries",
                3,
            )
        ),
    )

    timeout = int(
        settings.get(
            "timeout",
            30,
        )
    )

    retry_delay = int(
        settings.get(
            "retry_delay",
            5,
        )
    )

    for attempt in range(
        1,
        retries + 1,
    ):

        result["attempts"] = attempt

        try:

            session = create_session()

            response = session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
            )

            response.raise_for_status()

            content = response.text

            result.update(
                {
                    "status": "success",
                    "content": content,
                    "bytes": len(
                        content.encode(
                            "utf-8",
                            errors="ignore",
                        )
                    ),
                }
            )

            break

        except Exception as error:

            result["error"] = str(error)

            if attempt < retries:
                time.sleep(
                    retry_delay
                )

    result["download_time"] = round(
        time.time() - started,
        3,
    )

    return result


def download_all_sources(
    sources: list[str],
    settings: dict[str, Any],
) -> list[dict[str, Any]]:

    workers = max(
        1,
        int(
            settings.get(
                "workers",
                20,
            )
        ),
    )

    logger.info(
        "Downloading %s sources with %s workers",
        len(sources),
        workers,
    )

    results = []

    with ThreadPoolExecutor(
        max_workers=workers,
    ) as executor:

        tasks = {
            executor.submit(
                download_source,
                url,
                settings,
            ): url
            for url in sources
        }

        for future in as_completed(tasks):

            url = tasks[future]

            try:

                result = future.result()

            except Exception as error:

                result = {
                    "url": url,
                    "status": "failed",
                    "download_time": 0,
                    "bytes": 0,
                    "content": "",
                    "error": str(error),
                    "attempts": 0,
                }

            results.append(result)

            if result["status"] == "success":

                logger.info(
                    "OK | %s | %s bytes | %ss",
                    url,
                    result["bytes"],
                    result["download_time"],
                )

            else:

                logger.warning(
                    "FAIL | %s | %s",
                    url,
                    result["error"],
                )

    return results


# ============================================================
# DECODING
# ============================================================

def decode_base64(
    text: str,
) -> str | None:

    if not text:
        return None

    value = (
        text.strip()
        .replace(
            "\n",
            "",
        )
        .replace(
            "\r",
            "",
        )
    )

    # Base64 subscription обычно
    # не содержит пробелов
    if not value:
        return None

    padding = "=" * (
        -len(value) % 4
    )

    try:

        decoded = base64.b64decode(
            value + padding,
            validate=False,
        )

        result = decoded.decode(
            "utf-8",
            errors="ignore",
        )

        if result:
            return result

    except Exception:
        pass

    return None


def decode_url_text(
    text: str,
) -> str:

    if not text:
        return text

    try:
        return unquote(text)

    except Exception:
        return text


def clean_text(
    text: str,
) -> str:

    if not text:
        return ""

    return (
        text
        .replace(
            "\r",
            "",
        )
        .replace(
            "\x00",
            "",
        )
        .strip()
    )


# ============================================================
# VLESS EXTRACTION
# ============================================================

def normalize_vless(
    uri: str,
) -> str | None:

    if not uri:
        return None

    uri = uri.strip()

    # Убираем мусор после URI
    while uri and uri[-1] in (
        ",",
        ".",
        ";",
        ":",
        ")",
        "]",
        "}",
        "'",
        '"',
    ):
        uri = uri[:-1]

    if not uri.lower().startswith(
        "vless://"
    ):
        return None

    return uri


def extract_vless(
    text: str,
    settings: dict[str, Any],
) -> list[str]:

    if not text:
        return []

    variants = [text]

    if settings.get(
        "decode_url",
        True,
    ):

        decoded_url = decode_url_text(
            text
        )

        if decoded_url != text:
            variants.append(
                decoded_url
            )

    if settings.get(
        "decode_base64",
        True,
    ):

        decoded_b64 = decode_base64(
            text
        )

        if decoded_b64:
            variants.append(
                decoded_b64
            )

    result = []

    for variant in variants:

        variant = clean_text(
            variant
        )

        matches = VLESS_PATTERN.findall(
            variant
        )

        for match in matches:

            node = normalize_vless(
                match
            )

            if node:
                result.append(node)

    return list(
        dict.fromkeys(result)
    )


def extract_from_sources(
    downloads: list[dict[str, Any]],
    settings: dict[str, Any],
) -> tuple[
    list[str],
    list[dict[str, Any]],
]:

    all_nodes = []

    source_stats = []

    for source in downloads:

        stats = {
            "url": source["url"],
            "status": source["status"],
            "download_time": source[
                "download_time"
            ],
            "bytes": source["bytes"],
            "attempts": source[
                "attempts"
            ],
            "found": 0,
            "valid": 0,
            "duplicates": 0,
            "error": source["error"],
        }

        if source["status"] != "success":

            source_stats.append(
                stats
            )

            continue

        nodes = extract_vless(
            source["content"],
            settings,
        )

        stats["found"] = len(nodes)

        all_nodes.extend(nodes)

        source_stats.append(
            stats
        )

    return (
        all_nodes,
        source_stats,
    )


# ============================================================
# VALIDATION
# ============================================================

def valid_uuid(
    value: str,
) -> bool:

    return bool(
        UUID_PATTERN.fullmatch(
            value
        )
    )


def valid_host(
    host: str | None,
) -> bool:

    if not host:
        return False

    host = host.strip(
        "[]"
    )

    if " " in host:
        return False

    if len(host) > 253:
        return False

    return True


def valid_port(
    port: int | None,
) -> bool:

    if port is None:
        return False

    return 1 <= port <= 65535


def validate_vless(
    uri: str,
) -> dict[str, Any]:

    result = {
        "valid": False,
        "reason": "",
        "security": "",
        "transport": "",
    }

    try:

        parsed = urlparse(
            uri
        )

    except Exception as error:

        result["reason"] = (
            f"url_error:{error}"
        )

        return result

    if parsed.scheme.lower() != "vless":

        result["reason"] = (
            "wrong_scheme"
        )

        return result

    uuid = unquote(
        parsed.username or ""
    )

    if not valid_uuid(
        uuid
    ):

        result["reason"] = (
            "bad_uuid"
        )

        return result

    host = parsed.hostname

    if not valid_host(
        host
    ):

        result["reason"] = (
            "bad_host"
        )

        return result

    try:

        port = parsed.port

    except ValueError:

        result["reason"] = (
            "bad_port"
        )

        return result

    if not valid_port(
        port
    ):

        result["reason"] = (
            "bad_port"
        )

        return result

    query = parse_qs(
        parsed.query,
        keep_blank_values=True,
    )

    security = query.get(
        "security",
        ["none"],
    )[0].lower()

    transport = query.get(
        "type",
        ["tcp"],
    )[0].lower()

    result["security"] = security

    result["transport"] = transport

    allowed_transports = {
        "tcp",
        "ws",
        "grpc",
        "http",
        "h2",
        "xhttp",
        "quic",
        "kcp",
    }

    if transport not in allowed_transports:

        result["reason"] = (
            "unknown_transport"
        )

        return result

    # Reality
    if security == "reality":

        public_key = (
            query.get(
                "pbk",
                [""],
            )[0]
            or
            query.get(
                "publicKey",
                [""],
            )[0]
        )

        if not public_key:

            result["reason"] = (
                "reality_without_pbk"
            )

            return result

    # TLS
    elif security == "tls":

        sni = (
            query.get(
                "sni",
                [""],
            )[0]
            or
            query.get(
                "serverName",
                [""],
            )[0]
        )

        if not sni:

            result["reason"] = (
                "tls_without_sni"
            )

            return result

    result["valid"] = True

    return result


# ============================================================
# FINGERPRINT
# ============================================================

def node_hash(
    uri: str,
) -> str:

    try:

        parsed = urlparse(
            uri
        )

        query = parse_qs(
            parsed.query,
            keep_blank_values=True,
        )

        data = {
            "uuid": unquote(
                parsed.username or ""
            ).lower(),

            "host": (
                parsed.hostname or ""
            ).lower(),

            "port": parsed.port or 0,

            "type": query.get(
                "type",
                [""],
            )[0].lower(),

            "security": query.get(
                "security",
                [""],
            )[0].lower(),

        }

        raw = json.dumps(
            data,
            sort_keys=True,
        )

        return hashlib.sha256(
            raw.encode(
                "utf-8"
            )
        ).hexdigest()

    except Exception:

        return hashlib.sha256(
            uri.encode(
                "utf-8"
            )
        ).hexdigest()


# ============================================================
# VALIDATE + DEDUPLICATE
# ============================================================

def validate_nodes(
    nodes: list[str],
) -> dict[str, Any]:

    valid = []

    invalid = []

    duplicates = []

    seen = set()

    statistics = {
        "security": {},
        "transport": {},
        "errors": {},
    }

    for node in nodes:

        check = validate_vless(
            node
        )

        if not check["valid"]:

            reason = check[
                "reason"
            ]

            invalid.append(
                f"{node}\t{reason}"
            )

            statistics[
                "errors"
            ][reason] = (
                statistics[
                    "errors"
                ].get(
                    reason,
                    0,
                )
                + 1
            )

            continue

        fingerprint = node_hash(
            node
        )

        if fingerprint in seen:

            duplicates.append(
                node
            )

            continue

        seen.add(
            fingerprint
        )

        valid.append(
            node
        )

        security = (
            check["security"]
            or
            "none"
        )

        transport = (
            check["transport"]
            or
            "tcp"
        )

        statistics[
            "security"
        ][security] = (
            statistics[
                "security"
            ].get(
                security,
                0,
            )
            + 1
        )

        statistics[
            "transport"
        ][transport] = (
            statistics[
                "transport"
            ].get(
                transport,
                0,
            )
            + 1
        )

    return {
        "valid": valid,
        "invalid": invalid,
        "duplicates": duplicates,
        "statistics": statistics,
    }


# ============================================================
# OUTPUT
# ============================================================

def write_file(
    path: Path,
    data: list[str],
) -> None:

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:

        if data:

            file.write(
                "\n".join(data)
            )

            file.write(
                "\n"
            )


def write_json(
    path: Path,
    data: Any,
) -> None:

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            data,
            file,
            ensure_ascii=False,
            indent=2,
        )

        file.write(
            "\n"
        )


def create_chunks(
    nodes: list[str],
    chunk_size: int,
) -> None:

    for old_file in CHUNKS_DIR.glob(
        "*.txt"
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
            index:
            index + chunk_size
        ]

        number = (
            index // chunk_size
        ) + 1

        chunk_file = (
            CHUNKS_DIR
            /
            f"chunk_{number:03}.txt"
        )

        write_file(
            chunk_file,
            chunk,
        )


# ============================================================
# STATISTICS
# ============================================================

def build_stats(
    downloads: list[dict[str, Any]],
    validation: dict[str, Any],
) -> dict[str, Any]:

    successful = [
        item
        for item in downloads
        if item["status"]
        ==
        "success"
    ]

    failed = [
        item
        for item in downloads
        if item["status"]
        !=
        "success"
    ]

    return {
        "project": PROJECT_NAME,
        "updated_at": time.strftime(
            "%Y-%m-%d %H:%M:%S UTC",
            time.gmtime(),
        ),
        "sources": {
            "total": len(
                downloads
            ),
            "success": len(
                successful
            ),
            "failed": len(
                failed
            ),
        },
        "nodes": {
            "valid": len(
                validation[
                    "valid"
                ]
            ),
            "invalid": len(
                validation[
                    "invalid"
                ]
            ),
            "duplicates": len(
                validation[
                    "duplicates"
                ]
            ),
        },
        "protocols": validation[
            "statistics"
        ],
    }


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    logger.info(
        "Starting %s",
        PROJECT_NAME,
    )

    prepare_directories()

    config = load_config()

    settings = get_settings(
        config
    )

    sources = get_sources(
        config
    )

    if not sources:

        logger.error(
            "No sources found in sources.yml"
        )

        return 1

    logger.info(
        "Loaded %s unique sources",
        len(sources),
    )

    # --------------------------------------------------------
    # Download
    # --------------------------------------------------------

    downloads = download_all_sources(
        sources,
        settings,
    )

    # --------------------------------------------------------
    # Extract
    # --------------------------------------------------------

    nodes, source_stats = (
        extract_from_sources(
            downloads,
            settings,
        )
    )

    logger.info(
        "Extracted %s unique raw VLESS nodes",
        len(nodes),
    )

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    validation = validate_nodes(
        nodes
    )

    valid_nodes = sorted(
        validation[
            "valid"
        ]
    )

    invalid_nodes = (
        validation[
            "invalid"
        ]
    )

    duplicate_nodes = (
        validation[
            "duplicates"
        ]
    )

    # --------------------------------------------------------
    # Source statistics
    # --------------------------------------------------------

    # Распределяем статистику
    # по источникам по факту
    #
    # Для этого считаем найденные
    # URI до глобальной дедупликации.
    #
    # Точные source-level valid
    # будут доступны в следующем
    # улучшении с привязкой node -> source.

    for stat in source_stats:

        stat.setdefault(
            "valid",
            0,
        )

        stat.setdefault(
            "duplicates",
            0,
        )

    # --------------------------------------------------------
    # Write output
    # --------------------------------------------------------

    write_file(
        MY_SUB_FILE,
        valid_nodes,
    )

    write_file(
        VALID_FILE,
        valid_nodes,
    )

    write_file(
        INVALID_FILE,
        invalid_nodes,
    )

    write_file(
        DUPLICATES_FILE,
        duplicate_nodes,
    )

    chunk_size = int(
        settings.get(
            "chunk_size",
            1000,
        )
    )

    create_chunks(
        valid_nodes,
        chunk_size,
    )

    # --------------------------------------------------------
    # JSON statistics
    # --------------------------------------------------------

    global_stats = build_stats(
        downloads,
        validation,
    )

    write_json(
        STATS_FILE,
        global_stats,
    )

    write_json(
        SOURCES_STATS_FILE,
        source_stats,
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    logger.info(
        "================================"
    )

    logger.info(
        "Valid nodes: %s",
        len(valid_nodes),
    )

    logger.info(
        "Invalid nodes: %s",
        len(invalid_nodes),
    )

    logger.info(
        "Duplicates: %s",
        len(duplicate_nodes),
    )

    logger.info(
        "Subscription: %s",
        MY_SUB_FILE,
    )

    logger.info(
        "Finished successfully"
    )

    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        raise SystemExit(
            main()
        )

    except KeyboardInterrupt:

        logger.warning(
            "Interrupted by user"
        )

        raise SystemExit(
            130
        )

    except Exception:

        logger.exception(
            "Fatal error"
        )

        raise SystemExit(
            1
        )

