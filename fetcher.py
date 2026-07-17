# ============================================================
# Skibidi_tualet_proxy
# fetcher.py v2
#
# Part 1/4
# Config + Parallel Source Loader
# ============================================================


from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import time

from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)

from pathlib import Path

from typing import Any

from urllib.parse import (
    urlparse,
    parse_qs,
    unquote,
)

import requests
import yaml



# ============================================================
# Project
# ============================================================


PROJECT_NAME = "Skibidi_tualet_proxy"


BASE_DIR = Path(__file__).resolve().parent


SOURCES_FILE = BASE_DIR / "sources.yml"


OUTPUT_DIR = BASE_DIR / "output"


VALID_FILE = OUTPUT_DIR / "valid_vless.txt"

INVALID_FILE = OUTPUT_DIR / "invalid_vless.txt"

DUPLICATES_FILE = OUTPUT_DIR / "duplicates.txt"

STATS_FILE = OUTPUT_DIR / "stats.json"

SOURCES_STATS_FILE = (
    OUTPUT_DIR / "sources_stats.json"
)


CHUNKS_DIR = OUTPUT_DIR / "chunks"



# ============================================================
# Logging
# ============================================================


logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"
    ),
)


logger = logging.getLogger(
    PROJECT_NAME
)



# ============================================================
# Default settings
# ============================================================


DEFAULT_SETTINGS = {


    "workers": 20,


    "timeout": 30,


    "retries": 3,


    "retry_delay": 5,


    "chunk_size": 1000,


    "decode_base64": True,


    "decode_url": True,


    "deduplicate": True,


}



# ============================================================
# Prepare folders
# ============================================================


def prepare_directories():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


    CHUNKS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )



# ============================================================
# YAML loader
# ============================================================


def load_config() -> dict[str, Any]:


    if not SOURCES_FILE.exists():

        raise FileNotFoundError(
            "sources.yml not found"
        )


    with open(
        SOURCES_FILE,
        "r",
        encoding="utf-8",
    ) as file:

        config = yaml.safe_load(file)


    if not isinstance(
        config,
        dict,
    ):

        config = {}


    return config



# ============================================================
# Settings
# ============================================================


def get_settings(
    config: dict[str, Any],
):

    settings = DEFAULT_SETTINGS.copy()


    user_settings = (
        config.get(
            "settings",
            {}
        )
    )


    if isinstance(
        user_settings,
        dict,
    ):

        settings.update(
            user_settings
        )


    return settings



# ============================================================
# Sources
# ============================================================


def get_sources(
    config: dict[str, Any],
):

    sources = (
        config.get(
            "sources",
            []
        )
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

            result.append(
                source.strip()
            )


    return [
        s
        for s in result
        if s
    ]



# ============================================================
# HTTP session
# ============================================================


def create_session():

    session = requests.Session()


    session.headers.update(
        {

            "User-Agent":
            (
                "Skibidi_tualet_proxy/"
                "2.0"
            ),


            "Accept":
            "*/*",

        }
    )


    return session



# ============================================================
# Download one source
# ============================================================


def download_source(
    url: str,
    settings: dict[str, Any],
):


    result = {


        "url": url,


        "status": "failed",


        "time": 0,


        "bytes": 0,


        "content": "",


        "error": None,


    }


    start = time.time()


    retries = int(
        settings.get(
            "retries",
            3,
        )
    )


    timeout = int(
        settings.get(
            "timeout",
            30,
        )
    )


    delay = int(
        settings.get(
            "retry_delay",
            5,
        )
    )



    for attempt in range(
        1,
        retries + 1,
    ):


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


            result["error"] = str(
                error
            )


            if attempt < retries:

                time.sleep(
                    delay
                )



    result["time"] = round(
        time.time() - start,
        3,
    )


    return result



# ============================================================
# Parallel downloader
# ============================================================


def download_all_sources(
    sources,
    settings,
):


    workers = int(
        settings.get(
            "workers",
            20,
        )
    )


    results = []



    logger.info(
        "Downloading %s sources with %s workers",
        len(sources),
        workers,
    )



    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:


        tasks = [

            executor.submit(
                download_source,
                url,
                settings,
            )

            for url in sources

        ]



        for future in as_completed(
            tasks
        ):


            result = future.result()


            results.append(
                result
            )


            if result["status"] == "success":


                logger.info(
                    "OK %s (%s bytes)",
                    result["url"],
                    result["bytes"],
                )


            else:


                logger.warning(
                    "FAIL %s : %s",
                    result["url"],
                    result["error"],
                )



    return results

# ============================================================
# Part 2/4
# Decoder + VLESS Extractor
# ============================================================


# ============================================================
# Base64 decoder
# ============================================================


def decode_base64(
    text: str,
):

    if not text:

        return None


    value = (
        text
        .strip()
        .replace(
            "\n",
            "",
        )
        .replace(
            "\r",
            "",
        )
    )


    padding = (
        "="
        *
        (
            -len(value)
            %
            4
        )
    )


    try:

        decoded = base64.b64decode(
            value + padding,
            validate=False,
        )


        return decoded.decode(
            "utf-8",
            errors="ignore",
        )


    except Exception:

        return None



# ============================================================
# URL decoder
# ============================================================


def decode_url_text(
    text: str,
):

    if not text:

        return text


    try:

        return unquote(
            text
        )


    except Exception:

        return text



# ============================================================
# Remove garbage
# ============================================================


def clean_text(
    text: str,
):

    if not text:

        return ""


    text = (
        text
        .replace(
            "\r",
            "",
        )
        .replace(
            "\x00",
            "",
        )
    )


    return text.strip()



# ============================================================
# VLESS pattern
# ============================================================


VLESS_PATTERN = re.compile(

    r"vless://[^\s\"'<>]+",

    re.IGNORECASE,

)



# ============================================================
# Extract VLESS from text
# ============================================================


def extract_vless(
    text: str,
    settings: dict[str, Any],
):


    if not text:

        return []



    results = []



    variants = [

        text

    ]



    # URL decode

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



    # Base64 decode

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



    for variant in variants:


        variant = clean_text(
            variant
        )


        matches = (
            VLESS_PATTERN.findall(
                variant
            )
        )


        for item in matches:


            item = normalize_vless(
                item
            )


            if item:

                results.append(
                    item
                )



    return list(
        dict.fromkeys(
            results
        )
    )



# ============================================================
# Normalize VLESS URI
# ============================================================


def normalize_vless(
    uri: str,
):


    if not uri:

        return None



    uri = uri.strip()



    # remove ending garbage chars

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



# ============================================================
# Process downloaded sources
# ============================================================


def extract_from_sources(
    downloads,
    settings,
):


    all_nodes = []


    source_stats = []



    for source in downloads:


        stats = {


            "url":
            source["url"],


            "status":
            source["status"],


            "bytes":
            source["bytes"],


            "download_time":
            source["time"],


            "found":
            0,


            "error":
            source["error"],


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



        stats["found"] = len(
            nodes
        )



        all_nodes.extend(
            nodes
        )



        source_stats.append(
            stats
        )



    return (
        all_nodes,
        source_stats,
    )

# ============================================================
# Part 3/4
# Validator + Deduplicator
# ============================================================


# ============================================================
# UUID validation
# ============================================================


UUID_PATTERN = re.compile(

    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}$"

)



def valid_uuid(
    value: str,
):

    return bool(
        UUID_PATTERN.fullmatch(
            value
        )
    )



# ============================================================
# Host validation
# ============================================================


def valid_host(
    host: str,
):

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



# ============================================================
# Port validation
# ============================================================


def valid_port(
    port,
):

    try:

        port = int(
            port
        )


    except Exception:

        return False



    return (
        1 <= port <= 65535
    )



# ============================================================
# VLESS validator
# ============================================================


def validate_vless(
    uri: str,
):


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


    except Exception:


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



    # --------------------------------------------------------
    # Security checks
    # --------------------------------------------------------


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



        sni = query.get(
            "sni",
            [""],
        )[0]



        if not sni:


            result["reason"] = (
                "reality_without_sni"
            )


            return result



    elif security == "tls":


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


                result["reason"] = (
                    "tls_without_sni"
                )


                return result



    # --------------------------------------------------------
    # Transport checks
    # --------------------------------------------------------


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



    result["valid"] = True


    return result



# ============================================================
# Fingerprint
# ============================================================


def node_hash(
    uri: str,
):


    try:


        parsed = urlparse(
            uri
        )


        query = parse_qs(
            parsed.query,
            keep_blank_values=True,
        )



        data = {


            "uuid":
            unquote(
                parsed.username or ""
            ).lower(),


            "host":
            (
                parsed.hostname
                or ""
            ).lower(),


            "port":
            parsed.port or 0,


            "type":
            query.get(
                "type",
                [""],
            )[0],


            "security":
            query.get(
                "security",
                [""],
            )[0],


        }



        raw = json.dumps(
            data,
            sort_keys=True,
        )



        return hashlib.sha256(
            raw.encode()
        ).hexdigest()



    except Exception:


        return hashlib.sha256(
            uri.encode()
        ).hexdigest()



# ============================================================
# Validate all nodes
# ============================================================


def validate_nodes(
    nodes,
):


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


            invalid.append(
                node
                +
                "\t"
                +
                check["reason"]
            )



            statistics["errors"][
                check["reason"]
            ] = (

                statistics["errors"]
                .get(
                    check["reason"],
                    0,
                )
                +
                1

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



        statistics["security"][
            security
        ] = (

            statistics["security"]
            .get(
                security,
                0,
            )
            +
            1

        )



        statistics["transport"][
            transport
        ] = (

            statistics["transport"]
            .get(
                transport,
                0,
            )
            +
            1

        )



    return {


        "valid":
        valid,


        "invalid":
        invalid,


        "duplicates":
        duplicates,


        "statistics":
        statistics,


    }

# ============================================================
# Part 4/4
# Output + Main
# ============================================================



# ============================================================
# Write text file
# ============================================================


def write_file(
    path: Path,
    data,
):


    with open(
        path,
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



# ============================================================
# Create chunks
# ============================================================


def create_chunks(
    nodes,
    chunk_size,
):


    # clear old chunks

    for old in CHUNKS_DIR.glob(
        "*.txt"
    ):

        old.unlink()



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



        file = (
            CHUNKS_DIR
            /
            f"chunk_{number:03}.txt"
        )



        write_file(
            file,
            chunk,
        )



# ============================================================
# JSON writer
# ============================================================


def write_json(
    path: Path,
    data,
):


    with open(
        path,
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



# ============================================================
# Build global statistics
# ============================================================


def build_stats(
    downloads,
    source_stats,
    validation,
):


    return {


        "project":
        PROJECT_NAME,


        "time":
        time.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),


        "sources": {


            "total":
            len(downloads),


            "success":
            len(
                [
                    x
                    for x in downloads
                    if x["status"]
                    ==
                    "success"
                ]
            ),


            "failed":
            len(
                [
                    x
                    for x in downloads
                    if x["status"]
                    !=
                    "success"
                ]
            ),

        },



        "nodes": {


            "valid":
            len(
                validation["valid"]
            ),


            "invalid":
            len(
                validation["invalid"]
            ),


            "duplicates":
            len(
                validation["duplicates"]
            ),


        },



        "protocols":
        validation["statistics"],



    }



# ============================================================
# MAIN
# ============================================================


def main():



    logger.info(
        "Starting %s",
        PROJECT_NAME,
    )



    prepare_directories()



    # --------------------------------------------------------
    # Load config
    # --------------------------------------------------------


    config = load_config()



    settings = get_settings(
        config
    )



    sources = get_sources(
        config
    )



    if not sources:


        logger.error(
            "No sources found"
        )


        return 1



    logger.info(
        "Sources loaded: %s",
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
        "Extracted nodes: %s",
        len(nodes),
    )



    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------


    validation = validate_nodes(
        nodes
    )



    valid_nodes = (
        validation["valid"]
    )


    invalid_nodes = (
        validation["invalid"]
    )


    duplicate_nodes = (
        validation["duplicates"]
    )



    valid_nodes.sort()



    # --------------------------------------------------------
    # Output
    # --------------------------------------------------------


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
    # Statistics
    # --------------------------------------------------------


    for stat in source_stats:


        url = stat["url"]



        found = 0



        for node in valid_nodes:


            if url in node:

                found += 1



        stat["valid_after_filter"] = found



    global_stats = build_stats(
        downloads,
        source_stats,
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



    logger.info(
        "=========================="
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
        "Finished successfully"
    )



    return 0



# ============================================================
# Entry point
# ============================================================


if __name__ == "__main__":


    try:


        exit(
            main()
        )


    except KeyboardInterrupt:


        logger.warning(
            "Interrupted"
        )


        exit(130)



    except Exception as error:


        logger.exception(
            error
        )


        exit(1)
