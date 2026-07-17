# ============================================================
# VLESS FETCHER v2
# PART 1/4
# CONFIG + PARSER + VALIDATOR
# ============================================================

import os
import re
import json
import uuid
import yaml
import base64
import urllib.parse
from urllib.parse import urlparse, parse_qs


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)


PARSER_CONFIG = os.path.join(
    BASE_DIR,
    "config",
    "parser.yml"
)


OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "output"
)


os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)


# ============================================================
# LOAD YAML CONFIG
# ============================================================

def load_parser_config():

    if not os.path.isfile(
        PARSER_CONFIG
    ):

        raise FileNotFoundError(
            f"Config not found: {PARSER_CONFIG}"
        )


    with open(
        PARSER_CONFIG,
        "r",
        encoding="utf-8"
    ) as file:

        return yaml.safe_load(file)



# ============================================================
# VLESS EXTRACTION REGEX
# ============================================================

VLESS_REGEX = re.compile(
    r"vless://[^\s\"'<>\]]+",
    re.IGNORECASE
)



# ============================================================
# UUID VALIDATOR
# ============================================================

def validate_uuid(value):

    if not value:
        return False


    try:

        uuid.UUID(
            value
        )

        return True


    except Exception:

        return False



# ============================================================
# PORT VALIDATOR
# ============================================================

def validate_port(port):

    try:

        port = int(port)

        return (
            1 <= port <= 65535
        )


    except Exception:

        return False



# ============================================================
# VLESS PARSER
# ============================================================

def parse_vless(vless):

    try:

        # decode %XX
        vless = urllib.parse.unquote(
            vless.strip()
        )


        parsed = urlparse(
            vless
        )


        if parsed.scheme.lower() != "vless":

            return None


        query = parse_qs(
            parsed.query,
            keep_blank_values=True
        )


        def get(name, default=""):

            return query.get(
                name,
                [default]
            )[0]



        node = {

            "raw": vless,

            "uuid":
                parsed.username or "",


            "host":
                parsed.hostname or "",


            "port":
                parsed.port,


            "security":
                get(
                    "security",
                    "none"
                ).lower(),


            "network":
                get(
                    "type",
                    "tcp"
                ).lower(),


            "sni":
                get(
                    "sni",
                    ""
                ),


            "pbk":
                get(
                    "pbk",
                    ""
                ),


            "sid":
                get(
                    "sid",
                    ""
                ),


            "flow":
                get(
                    "flow",
                    ""
                ),


            "fp":
                get(
                    "fp",
                    "chrome"
                ),


            "path":
                get(
                    "path",
                    "/"
                ),


            "host_header":
                get(
                    "host",
                    ""
                ),


            "serviceName":
                get(
                    "serviceName",
                    ""
                ),


            "remark":

                urllib.parse.unquote(
                    parsed.fragment
                )
                if parsed.fragment
                else ""

        }


        return node



    except Exception:

        return None




# ============================================================
# NODE VALIDATOR
# ============================================================

def validate_vless(node, config):


    errors = []


    # -----------------------------
    # UUID
    # -----------------------------

    if config["validation"]["uuid"]["required"]:

        if not validate_uuid(
            node["uuid"]
        ):

            errors.append(
                "invalid_uuid"
            )



    # -----------------------------
    # HOST
    # -----------------------------

    if not node["host"]:

        errors.append(
            "empty_host"
        )



    # -----------------------------
    # PORT
    # -----------------------------

    if not validate_port(
        node["port"]
    ):

        errors.append(
            "invalid_port"
        )



    # -----------------------------
    # SECURITY
    # -----------------------------

    security = node["security"]



    if security == "reality":

        reality_cfg = (
            config["validation"]
            .get(
                "reality",
                {}
            )
        )


        required = (
            reality_cfg
            .get(
                "required",
                []
            )
        )


        for field in required:

            if not node.get(field):

                errors.append(
                    f"reality_missing_{field}"
                )



    elif security == "tls":

        tls_cfg = (
            config["validation"]
            .get(
                "tls",
                {}
            )
        )


        required = (
            tls_cfg
            .get(
                "required",
                []
            )
        )


        for field in required:

            if not node.get(field):

                errors.append(
                    f"tls_missing_{field}"
                )



    # -----------------------------
    # NETWORK
    # -----------------------------

    allowed_networks = (

        config["validation"]
        .get(
            "transport",
            {}
        )
        .get(
            "allowed",
            []
        )

    )


    if allowed_networks:

        if node["network"] not in allowed_networks:

            errors.append(
                "unsupported_transport"
            )



    # -----------------------------
    # RESULT
    # -----------------------------

    return {

        "valid":
            len(errors) == 0,


        "errors":
            errors,


        "node":
            node

    }

# ============================================================
# VLESS FETCHER v2
# PART 2/4
# SOURCE DOWNLOADER + EXTRACTION
# ============================================================

import aiohttp
import asyncio


# ============================================================
# HTTP DOWNLOADER
# ============================================================

async def download_url(
    session,
    url
):

    try:

        headers = {

            "User-Agent":
                "Mozilla/5.0 VLESS-Fetcher/2.0"

        }


        async with session.get(

            url,

            headers=headers,

            timeout=aiohttp.ClientTimeout(
                total=20
            )

        ) as response:


            if response.status != 200:

                print(
                    f"[HTTP ERROR] "
                    f"{response.status} "
                    f"{url}"
                )

                return ""



            content = await response.text(

                encoding="utf-8",

                errors="ignore"

            )


            return content



    except Exception as exc:


        print(

            f"[DOWNLOAD FAILED] "
            f"{url} | {exc}"

        )


        return ""





# ============================================================
# BASE64 DETECTOR
# ============================================================

def decode_base64_content(
    content
):

    try:


        cleaned = "".join(

            content.split()

        )


        # проверяем минимальную длину

        if len(cleaned) < 20:

            return content



        # добавляем padding

        padding = len(cleaned) % 4


        if padding:

            cleaned += "=" * (
                4 - padding
            )



        decoded = base64.b64decode(

            cleaned

        ).decode(

            "utf-8",

            errors="ignore"

        )


        # если после декода есть vless,
        # значит это подписка

        if "vless://" in decoded.lower():

            return decoded



    except Exception:

        pass



    return content





# ============================================================
# NORMALIZE TEXT
# ============================================================

def normalize_text(
    text
):

    if not text:

        return ""



    # URL decode

    text = urllib.parse.unquote(
        text
    )



    # заменяем мусорные символы

    text = text.replace(
        "\r",
        "\n"
    )



    return text





# ============================================================
# EXTRACT VLESS LINKS
# ============================================================

def extract_vless_links(
    text
):

    if not text:

        return []



    text = normalize_text(
        text
    )


    # пробуем base64

    decoded = decode_base64_content(
        text
    )


    if decoded != text:

        text = decoded



    matches = VLESS_REGEX.findall(
        text
    )



    result = []


    for item in matches:


        # убираем хвостовые символы

        item = item.rstrip(

            ".,;)]}>\"'"

        )


        if item.lower().startswith(

            "vless://"

        ):

            result.append(
                item
            )



    return result





# ============================================================
# LOAD ALL SOURCES
# ============================================================

async def collect_sources(
    config
):

    sources = []



    source_cfg = (

        config
        .get(
            "sources",
            {}
        )

    )



    # --------------------------------------------------------
    # URL SOURCES
    # --------------------------------------------------------

    url_list = (

        source_cfg
        .get(
            "urls",
            []
        )

    )


    if url_list:

        sources.extend(
            url_list
        )



    # --------------------------------------------------------
    # GITHUB SOURCES
    # --------------------------------------------------------

    github_cfg = (

        source_cfg
        .get(
            "github",
            {}
        )

    )


    if github_cfg.get(
        "enabled",
        False
    ):


        sources.extend(

            github_cfg
            .get(
                "urls",
                []
            )

        )



    # --------------------------------------------------------
    # TELEGRAM SOURCES
    # --------------------------------------------------------

    telegram_cfg = (

        source_cfg
        .get(
            "telegram",
            {}
        )

    )


    if telegram_cfg.get(
        "enabled",
        False
    ):


        sources.extend(

            telegram_cfg
            .get(
                "urls",
                []
            )

        )



    return sources





# ============================================================
# FETCH AND EXTRACT
# ============================================================

async def fetch_all_nodes(
    config
):


    urls = await collect_sources(
        config
    )


    if not urls:

        print(
            "[WARNING] No sources found"
        )

        return []



    all_nodes = []



    async with aiohttp.ClientSession() as session:


        tasks = [

            download_url(

                session,

                url

            )

            for url in urls

        ]



        responses = await asyncio.gather(
            *tasks
        )



        for source, content in zip(

            urls,

            responses

        ):


            if not content:

                continue



            found = extract_vless_links(

                content

            )


            print(

                f"[SOURCE] "
                f"{source} -> "
                f"{len(found)} nodes"

            )


            all_nodes.extend(
                found
            )



    return all_nodes

# ============================================================
# VLESS FETCHER v2
# PART 3/4
# VALIDATION + DEDUP + OUTPUT
# ============================================================


# ============================================================
# OUTPUT PATHS
# ============================================================

VALID_FILE = os.path.join(
    OUTPUT_DIR,
    "valid_vless.txt"
)


INVALID_FILE = os.path.join(
    OUTPUT_DIR,
    "invalid_vless.txt"
)


DUPLICATE_FILE = os.path.join(
    OUTPUT_DIR,
    "duplicates.txt"
)


STATS_FILE = os.path.join(
    OUTPUT_DIR,
    "stats.json"
)


CHUNKS_DIR = os.path.join(
    OUTPUT_DIR,
    "chunks"
)


os.makedirs(
    CHUNKS_DIR,
    exist_ok=True
)



# ============================================================
# NORMALIZE NODE
# ============================================================

def normalize_vless(
    vless
):

    return (
        urllib.parse.unquote(
            vless
        )
        .strip()
    )



# ============================================================
# PROCESS NODES
# ============================================================

def process_nodes(
    raw_nodes,
    config
):

    valid = []

    invalid = []

    duplicates = []


    seen = set()



    for raw in raw_nodes:


        normalized = normalize_vless(
            raw
        )


        # -----------------------------
        # DUPLICATES
        # -----------------------------

        if normalized in seen:

            duplicates.append(
                normalized
            )

            continue


        seen.add(
            normalized
        )



        # -----------------------------
        # PARSE
        # -----------------------------

        node = parse_vless(
            normalized
        )


        if not node:


            invalid.append({

                "node":
                    normalized,

                "reason":
                    [
                        "parse_failed"
                    ]

            })


            continue




        # -----------------------------
        # VALIDATE
        # -----------------------------

        result = validate_vless(

            node,

            config

        )



        if result["valid"]:


            valid.append(
                normalized
            )


        else:


            invalid.append({

                "node":
                    normalized,


                "reason":
                    result["errors"]

            })



    return {

        "valid":
            valid,


        "invalid":
            invalid,


        "duplicates":
            duplicates

    }





# ============================================================
# SAVE TEXT LIST
# ============================================================

def save_lines(
    path,
    lines
):

    with open(

        path,

        "w",

        encoding="utf-8"

    ) as file:


        for line in lines:

            file.write(

                line +

                "\n"

            )



# ============================================================
# SAVE INVALID
# ============================================================

def save_invalid(
    path,
    invalid
):

    with open(

        path,

        "w",

        encoding="utf-8"

    ) as file:


        for item in invalid:


            file.write(

                "ERROR: "

                +

                ",".join(
                    item["reason"]
                )

                +

                "\n"

            )


            file.write(

                item["node"]

                +

                "\n\n"

            )





# ============================================================
# CREATE CHUNKS
# ============================================================

def create_chunks(
    nodes,
    chunk_size=1000
):


    # очистка старых чанков

    for filename in os.listdir(

        CHUNKS_DIR

    ):

        if filename.startswith(

            "chunk_"

        ):

            os.remove(

                os.path.join(

                    CHUNKS_DIR,

                    filename

                )

            )



    counter = 1



    for index in range(

        0,

        len(nodes),

        chunk_size

    ):


        chunk = nodes[

            index:

            index +

            chunk_size

        ]



        filename = os.path.join(

            CHUNKS_DIR,

            f"chunk_{counter:03d}.txt"

        )



        save_lines(

            filename,

            chunk

        )


        counter += 1



    return counter - 1





# ============================================================
# SAVE STATISTICS
# ============================================================

def save_stats(
    stats
):

    with open(

        STATS_FILE,

        "w",

        encoding="utf-8"

    ) as file:


        json.dump(

            stats,

            file,

            indent=4,

            ensure_ascii=False

        )





# ============================================================
# BUILD DATABASE
# ============================================================

def build_database(
    raw_nodes,
    config
):


    result = process_nodes(

        raw_nodes,

        config

    )



    save_lines(

        VALID_FILE,

        result["valid"]

    )



    save_invalid(

        INVALID_FILE,

        result["invalid"]

    )



    save_lines(

        DUPLICATE_FILE,

        result["duplicates"]

    )



    chunk_size = (

        config
        .get(
            "output",
            {}
        )
        .get(
            "chunks",
            {}
        )
        .get(
            "size",
            1000
        )

    )



    chunks = create_chunks(

        result["valid"],

        chunk_size

    )



    stats = {


        "raw_found":

            len(raw_nodes),



        "valid":

            len(result["valid"]),



        "invalid":

            len(result["invalid"]),



        "duplicates":

            len(result["duplicates"]),



        "chunks":

            chunks

    }



    save_stats(

        stats

    )



    return stats

# ============================================================
# VLESS FETCHER v2
# PART 4/4
# MAIN + EXECUTION
# ============================================================


# ============================================================
# PRINT STATS
# ============================================================

def print_stats(
    stats
):

    print()

    print(
        "=" * 60
    )

    print(
        "VLESS FETCHER FINISHED"
    )

    print(
        "=" * 60
    )


    print(

        f"Raw found:      "
        f"{stats['raw_found']}"

    )


    print(

        f"Valid:          "
        f"{stats['valid']}"

    )


    print(

        f"Invalid:        "
        f"{stats['invalid']}"

    )


    print(

        f"Duplicates:     "
        f"{stats['duplicates']}"

    )


    print(

        f"Chunks created: "
        f"{stats['chunks']}"

    )


    print(
        "=" * 60
    )





# ============================================================
# MAIN
# ============================================================

async def main():


    try:


        print()

        print(
            "=" * 60
        )

        print(
            "VLESS FETCHER v2 STARTED"
        )

        print(
            "=" * 60
        )



        # --------------------------------
        # LOAD CONFIG
        # --------------------------------

        config = load_parser_config()



        print(

            "[OK] parser.yml loaded"

        )



        # --------------------------------
        # FETCH SOURCES
        # --------------------------------

        raw_nodes = await fetch_all_nodes(

            config

        )



        print()

        print(

            f"[INFO] Extracted nodes: "
            f"{len(raw_nodes)}"

        )



        if not raw_nodes:


            print(

                "[WARNING] No VLESS nodes found"

            )


            return



        # --------------------------------
        # BUILD DATABASE
        # --------------------------------

        stats = build_database(

            raw_nodes,

            config

        )



        # --------------------------------
        # OUTPUT
        # --------------------------------

        print_stats(

            stats

        )



    except FileNotFoundError as exc:


        print(

            "[CONFIG ERROR]",

            exc

        )


        raise



    except Exception as exc:


        print()

        print(

            "[FATAL ERROR]",

            str(exc)

        )


        raise





# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":


    asyncio.run(

        main()

    )
