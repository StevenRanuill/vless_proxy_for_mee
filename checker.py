from __future__ import annotations

import json
import logging
import socket
import subprocess
import tempfile
import time
import shutil
import uuid

from pathlib import Path
from urllib.parse import (
    urlparse,
    parse_qs,
    unquote,
)

import requests

# ==========================================================
# PROJECT
# ==========================================================

PROJECT_NAME = "Skibidi_tualet_proxy"

BASE_DIR = Path(__file__).resolve().parent

OUTPUT_DIR = BASE_DIR / "output"

CHUNKS_DIR = OUTPUT_DIR / "chunks"

TEMP_DIR = OUTPUT_DIR / "checker_temp"

XRAY_DIR = BASE_DIR / "Xray"

XRAY_PATH = XRAY_DIR / "xray.exe"

CHECKED_FILE = OUTPUT_DIR / "checked_vless.txt"

DEAD_FILE = OUTPUT_DIR / "dead_vless.txt"

STATS_FILE = OUTPUT_DIR / "checker_stats.json"

# ==========================================================
# SETTINGS
# ==========================================================

TEST_URL = "https://www.google.com/generate_204"

REQUEST_TIMEOUT = 10

XRAY_START_TIMEOUT = 8

CHUNK_DELAY = 1

REMOVE_TEMP_FILES = True

LOCAL_HOST = "127.0.0.1"

# ==========================================================
# LOGGING
# ==========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger(PROJECT_NAME)

# ==========================================================
# NETWORK
# ==========================================================

def get_free_port() -> int:

    with socket.socket() as sock:

        sock.bind(
            (
                LOCAL_HOST,
                0,
            )
        )

        return sock.getsockname()[1]

# ==========================================================
# FILESYSTEM
# ==========================================================

def prepare_directories():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    TEMP_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

def check_environment():

    logger.info(
        "Project directory: %s",
        BASE_DIR,
    )

    logger.info(
        "Xray: %s",
        XRAY_PATH,
    )

    if not XRAY_PATH.exists():

        raise FileNotFoundError(
            XRAY_PATH
        )

    if not CHUNKS_DIR.exists():

        raise FileNotFoundError(
            CHUNKS_DIR
        )

# ==========================================================
# CHUNKS
# ==========================================================

def get_chunks():

    chunks = sorted(
        CHUNKS_DIR.glob(
            "chunk_*.txt"
        )
    )

    if not chunks:

        raise RuntimeError(
            "Chunks not found."
        )

    logger.info(
        "Chunks: %d",
        len(chunks),
    )

    return chunks

def load_nodes(chunk: Path):

    with chunk.open(
        "r",
        encoding="utf-8",
    ) as file:

        nodes = [

            line.strip()

            for line in file

            if line.startswith(
                "vless://"
            )

        ]

    return list(
        dict.fromkeys(
            nodes
        )
    )

# ==========================================================
# GIT
# ==========================================================

def git_pull():

    logger.info(
        "Updating repository..."
    )

    subprocess.run(
        [
            "git",
            "pull",
            "--rebase",
        ],
        cwd=BASE_DIR,
        check=True,
    )

    logger.info(
        "Repository updated."
    )

# ==========================================================
# VLESS PARSER
# ==========================================================

def parse_vless(uri):

    try:

        parsed = urlparse(uri)

        query = parse_qs(
            parsed.query
        )


        if parsed.scheme.lower() != "vless":

            return None



        # ------------------------------
        # UUID decode
        # ------------------------------

        raw_uuid = parsed.username


        if not raw_uuid:

            logger.warning(
                "VLESS UUID empty"
            )

            return None



        uuid_value = raw_uuid


        for _ in range(3):

            decoded = unquote(
                uuid_value
            )


            if decoded == uuid_value:

                break


            uuid_value = decoded



        uuid_value = uuid_value.strip()



        try:

            uuid.UUID(
                uuid_value
            )


        except ValueError:


            logger.warning(

                "Invalid UUID skipped: %s",

                uuid_value,

            )

            return None



        # ------------------------------
        # Address
        # ------------------------------

        address = parsed.hostname


        if not address:

            logger.warning(
                "VLESS address empty"
            )

            return None



        # ------------------------------
        # Params helper
        # ------------------------------

        def get_param(
            name,
            default=""
        ):

            value = query.get(
                name,
                [default]
            )[0]

            return unquote(
                value
            )



        # ------------------------------
        # Result
        # ------------------------------

        return {


            "uuid":
            uuid_value,


            "address":
            address,


            "port":
            parsed.port or 443,


            "security":
            get_param(
                "security",
                "none",
            ),


            "network":
            get_param(
                "type",
                "tcp",
            ),


            "flow":
            get_param(
                "flow",
                "",
            ),


            "sni":
            get_param(
                "sni",
                get_param(
                    "serverName",
                    "",
                ),
            ),


            "fingerprint":
            get_param(
                "fp",
                "chrome",
            ),


            "public_key":
            get_param(
                "pbk",
                get_param(
                    "publicKey",
                    "",
                ),
            ),


            "short_id":
            get_param(
                "sid",
                get_param(
                    "shortId",
                    "",
                ),
            ),


            "path":
            get_param(
                "path",
                "/",
            ),


            "host":
            get_param(
                "host",
                "",
            ),


            "service_name":
            get_param(
                "serviceName",
                "",
            ),

        }



    except Exception as e:


        logger.warning(

            "VLESS parse error: %s",

            e,

        )


        return None
# ==========================================================
# STREAM SETTINGS
# ==========================================================

def build_stream_settings(node):


    stream = {

        "network":
        node["network"],


        "security":
        node["security"],

    }


    # --------------------------
    # TLS
    # --------------------------

    if node["security"] == "tls":


        stream[
            "tlsSettings"
        ] = {


            "serverName":
            node["sni"],


            "allowInsecure":
            True,


        }


    # --------------------------
    # REALITY
    # --------------------------

    elif node["security"] == "reality":


        stream[
            "realitySettings"
        ] = {


            "serverName":
            node["sni"],


            "fingerprint":
            node["fingerprint"],


            "publicKey":
            node["public_key"],


            "shortId":
            node["short_id"],


        }



    # --------------------------
    # WS
    # --------------------------

    if node["network"] == "ws":


        stream[
            "wsSettings"
        ] = {


            "path":
            node["path"],


            "headers":
            {

                "Host":
                node["host"]
                or
                node["sni"]

            }

        }



    # --------------------------
    # GRPC
    # --------------------------

    if node["network"] == "grpc":


        stream[
            "grpcSettings"
        ] = {


            "serviceName":
            node["service_name"],


        }


    return stream

# ==========================================================
# XRAY CONFIG BUILDER
# ==========================================================

def build_xray_config(
    node,
    socks_port,
):


    config = {


        "log":
        {

            "loglevel":
            "warning"

        },


        "inbounds":
        [

            {

                "listen":
                LOCAL_HOST,


                "port":
                socks_port,


                "protocol":
                "socks",


                "settings":
                {

                    "udp":
                    True,


                    "auth":
                    "noauth",

                }

            }

        ],



        "outbounds":
        [

            {

                "protocol":
                "vless",


                "settings":
                {

                    "vnext":
                    [

                        {


                            "address":
                            node["address"],


                            "port":
                            node["port"],


                            "users":
                            [

                                {


                                    "id":
                                    node["uuid"],


                                    "encryption":
                                    "none",


                                    "flow":
                                    node["flow"],


                                }

                            ]

                        }

                    ]

                },


                "streamSettings":
                build_stream_settings(
                    node
                ),


            }

        ]

    }


    return config

# ==========================================================
# TEMP CONFIG
# ==========================================================

def create_temp_config(
    config: dict,
    index: int,
):

    config_file = (
        TEMP_DIR
        /
        f"xray_test_{index}.json"
    )


    with config_file.open(
        "w",
        encoding="utf-8",
    ) as file:


        json.dump(
            config,
            file,
            ensure_ascii=False,
            indent=2,
        )


    return config_file

# ==========================================================
# XRAY START
# ==========================================================

def start_xray(
    config_file: Path,
):


    logger.debug(
        "Starting Xray with %s",
        config_file,
    )


    process = subprocess.Popen(

        [

            str(XRAY_PATH),

            "run",

            "-c",

            str(config_file),

        ],


        stdout=subprocess.PIPE,


        stderr=subprocess.PIPE,


        text=True,


        creationflags=(

            subprocess.CREATE_NO_WINDOW

            if hasattr(
                subprocess,
                "CREATE_NO_WINDOW"
            )

            else 0

        ),

    )


    return process

# ==========================================================
# XRAY STOP
# ==========================================================

def stop_xray(
    process,
):


    if process is None:

        return



    if process.poll() is None:


        process.terminate()


        try:

            process.wait(
                timeout=5
            )


        except subprocess.TimeoutExpired:


            process.kill()


            process.wait()

# ==========================================================
# PORT CHECK
# ==========================================================

def wait_port(
    host: str,
    port: int,
):


    deadline = (
        time.time()
        +
        XRAY_START_TIMEOUT
    )



    while time.time() < deadline:


        try:


            with socket.create_connection(

                (
                    host,
                    port,
                ),

                timeout=1,

            ):


                return True



        except OSError:


            time.sleep(
                0.2
            )


    return False

# ==========================================================
# CHECK ONE NODE
# ==========================================================

def check_node(
    uri: str,
    index: int,
):


    result = {


        "node":
        uri,


        "alive":
        False,


        "latency":
        None,


        "error":
        None,

    }



    start_time = time.time()



    node = parse_vless(
        uri
    )



    if not node:


        result["error"] = (
            "parse_failed"
        )


        return result



    socks_port = get_free_port()



    config = build_xray_config(

        node,

        socks_port,

    )



    config_file = None

    process = None



    try:


        config_file = create_temp_config(

            config,

            index,

        )



        process = start_xray(

            config_file

        )



        # ждём, не умер ли Xray

        time.sleep(
            0.5
        )



        if process.poll() is not None:


            stdout, stderr = process.communicate()


            result["error"] = (

                stderr

                or

                stdout

                or

                "xray_failed"

            )


            return result




        if not wait_port(

            LOCAL_HOST,

            socks_port,

        ):


            result["error"] = (

                "socks_not_started"

            )


            return result



        if test_proxy(socks_port):

            result["alive"] = True

        else:

            result["error"] = "http_test_failed"



        result["latency"] = round(

            (

                time.time()

                -

                start_time

            )

            *

            1000,

            2,

        )



    except Exception as error:


        result["error"] = str(
            error
        )



    finally:


        stop_xray(
            process
        )



        if (

            REMOVE_TEMP_FILES

            and

            config_file

            and

            config_file.exists()

        ):


            try:

                config_file.unlink()

            except Exception:

                pass



    return result

# ==========================================================
# HTTP TEST THROUGH SOCKS
# ==========================================================

def test_proxy(port: int):


    proxies = {

        "http":
        f"socks5h://{LOCAL_HOST}:{port}",


        "https":
        f"socks5h://{LOCAL_HOST}:{port}",

    }


    try:


        response = requests.get(

            TEST_URL,

            proxies=proxies,

            timeout=REQUEST_TIMEOUT,

            allow_redirects=False,

        )


        logger.info(

            "HTTP TEST: %s",

            response.status_code,

        )


        return True



    except Exception as e:


        logger.warning(

            "HTTP TEST ERROR: %s",

            repr(e),

        )


        return False

# ==========================================================
# CHUNKS PROCESSING
# ==========================================================

def process_chunk(
    chunk_file: Path,
    start_index: int,
):


    nodes = load_nodes(
        chunk_file
    )


    results = []


    logger.info(

        "Checking %s (%s nodes)",

        chunk_file.name,

        len(nodes),

    )



    for index, node in enumerate(

        nodes,

        start=start_index,

    ):


        result = check_node(

            node,

            index,

        )


        results.append(
            result
        )


        if result["alive"]:


            logger.info(

                "OK %sms | %s",

                result["latency"],

                node[:70],

            )


        else:


            logger.info(

                "FAIL | %s",

                result["error"],

            )


    return results

# ==========================================================
# SAVE RESULTS
# ==========================================================

def save_lines(
    path: Path,
    lines: list[str],
):


    with path.open(

        "w",

        encoding="utf-8",

        newline="\n",

    ) as file:


        file.write(

            "\n".join(lines)

        )


        if lines:

            file.write("\n")

# ==========================================================
# GIT
# ==========================================================

def git_pull():

    logger.info(
        "Git pull..."
    )


    subprocess.run(

        [

            "git",

            "pull",

            "--rebase",

        ],

        cwd=BASE_DIR,

        check=True,

    )



def git_push_results():

    subprocess.run(

        [

            "git",

            "add",

            "output",

        ],

        cwd=BASE_DIR,

        check=True,

    )


    subprocess.run(

        [

            "git",

            "commit",

            "-m",

            "checker: update proxy results",

        ],

        cwd=BASE_DIR,

        check=False,

    )


    subprocess.run(

        [

            "git",

            "push",

        ],

        cwd=BASE_DIR,

        check=True,

    )

# ==========================================================
# MAIN
# ==========================================================

def main():


    prepare_directories()


    git_pull()


    check_environment()



    chunks = get_chunks()



    alive = []

    dead = []



    total = 0



    start = time.time()



    for chunk in chunks:


        results = process_chunk(

            chunk,

            total,

        )


        total += len(results)



        for item in results:


            if item["alive"]:


                alive.append(

                    item["node"]

                )

            else:


                dead.append(

                    item["node"]

                )



        time.sleep(
            CHUNK_DELAY
        )



    save_lines(

        CHECKED_FILE,

        alive,

    )


    save_lines(

        DEAD_FILE,

        dead,

    )



    stats = {


        "project":
        PROJECT_NAME,


        "total":
        total,


        "alive":
        len(alive),


        "dead":
        len(dead),


        "time":

        round(

            time.time()

            -

            start,

            2,

        ),

    }



    with STATS_FILE.open(

        "w",

        encoding="utf-8",

    ) as file:


        json.dump(

            stats,

            file,

            indent=2,

            ensure_ascii=False,

        )



    logger.info(
        "Finished"
    )


    logger.info(
        stats
    )



    git_push_results()

if __name__ == "__main__":

    try:

        main()


    except KeyboardInterrupt:

        logger.warning(
            "Stopped"
        )


    except Exception as error:

        logger.exception(
            error
        )