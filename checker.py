# ==========================================================
# Skibidi_tualet_proxy
# VLESS Checker
# Part 1
# ==========================================================


import os
import sys
import json
import time
import uuid
import random
import shutil
import signal
import socket
import logging
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime


import requests


from urllib.parse import (
    urlparse,
    parse_qs,
    unquote,
    quote,
)



# ==========================================================
# BASE PATHS
# ==========================================================


BASE_DIR = Path(
    __file__
).resolve().parent



XRAY_PATH = (
    BASE_DIR
    /
    "Xray"
    /
    "xray.exe"
)



OUTPUT_DIR = (
    BASE_DIR
    /
    "output"
)



CHUNKS_DIR = (
    OUTPUT_DIR
    /
    "chunks"
)



TEMP_DIR = (
    OUTPUT_DIR
    /
    "checker_temp"
)



MY_SUB_FILE = (
    BASE_DIR
    /
    "my_sub.txt"
)



CHECKED_FILE = (
    OUTPUT_DIR
    /
    "checked_vless.txt"
)



STATS_FILE = (
    OUTPUT_DIR
    /
    "checker_stats.json"
)



# ==========================================================
# XRAY SETTINGS
# ==========================================================


XRAY_HOST = "127.0.0.1"


SOCKS_START_PORT = 10808



REQUEST_TIMEOUT = 15



XRAY_START_TIMEOUT = 10



# ==========================================================
# TEST TARGETS
# ==========================================================


TEST_TARGETS = {


    "telegram":
    "https://api.telegram.org",


    "youtube":
    "https://www.youtube.com/generate_204",


    "instagram":
    "https://www.instagram.com",


    "discord":
    "https://discord.com/api/v10/gateway",

}



# ==========================================================
# LOGGER
# ==========================================================


LOG_FILE = (
    BASE_DIR
    /
    "checker.log"
)



logging.basicConfig(

    level=logging.INFO,

    format=

    "%(asctime)s | "

    "%(levelname)s | "

    "%(message)s",

    handlers=[

        logging.FileHandler(

            LOG_FILE,

            encoding="utf-8"

        ),


        logging.StreamHandler()

    ]

)



logger = logging.getLogger(

    "Skibidi_tualet_proxy"

)



# ==========================================================
# CREATE DIRECTORIES
# ==========================================================


for folder in [

    OUTPUT_DIR,

    TEMP_DIR,

    CHUNKS_DIR,

]:

    folder.mkdir(

        exist_ok=True

    )



# ==========================================================
# STARTUP CHECK
# ==========================================================


def check_environment():


    if not XRAY_PATH.exists():

        logger.error(

            "Xray not found: %s",

            XRAY_PATH

        )

        sys.exit(1)



    logger.info(

        "Project: Skibidi_tualet_proxy"

    )


    logger.info(

        "Xray: %s",

        XRAY_PATH

    )

# ==========================================================
# PROXY NAME GENERATOR
# Skibidi_tualet_proxy
# ==========================================================


COUNTRY_FLAGS = {

    "US": "🇺🇸",
    "DE": "🇩🇪",
    "NL": "🇳🇱",
    "FI": "🇫🇮",
    "FR": "🇫🇷",
    "GB": "🇬🇧",
    "JP": "🇯🇵",
    "SG": "🇸🇬",
    "CA": "🇨🇦",
    "RU": "🇷🇺",
    "SE": "🇸🇪",
    "CH": "🇨🇭",
    "AU": "🇦🇺",
    "BR": "🇧🇷",
    "PL": "🇵🇱",
    "CZ": "🇨🇿",
    "TR": "🇹🇷",

}



SKIBIDI_HEROES = {


    "toilet": [

        "Astro Toilet",

        "G-Man Toilet",

        "Scientist Toilet",

        "Laser Toilet",

        "Shadow Toilet",

    ],



    "tv": [

        "Titan TV Man",

        "TV Man Ultra",

        "Mega TV Man",

        "Shadow TV Man",

    ],



    "camera": [

        "Titan Cameraman",

        "Cameraman Prime",

        "Dark Cameraman",

        "Shadow Cameraman",

    ],



    "speaker": [

        "Titan Speakerman",

        "Speakerman Prime",

        "Shadow Speakerman",

    ],

}



HERO_EMOJI = {


    "toilet":
    "🚽",


    "tv":
    "📺",


    "camera":
    "🎥",


    "speaker":
    "🔊",

}




def detect_country(address):

    """
    Временная версия.
    Позже заменим на geoip.dat.
    """


    return random.choice(

        list(
            COUNTRY_FLAGS.keys()
        )

    )





def generate_proxy_name(

        address,

        country=None

):


    """
    Создание стабильного имени.

    Один IP = одно имя
    """



    old_state = random.getstate()



    random.seed(

        address

    )



    if not country:


        country = detect_country(

            address

        )



    flag = COUNTRY_FLAGS.get(

        country,

        "🌐"

    )



    hero_type = random.choice(

        list(
            SKIBIDI_HEROES.keys()
        )

    )



    hero = random.choice(

        SKIBIDI_HEROES[hero_type]

    )



    emoji = HERO_EMOJI[hero_type]



    random.setstate(

        old_state

    )



    return (

        f"{flag} "

        f"{hero} "

        f"{emoji}"

    )

# ==========================================================
# GIT SYNC
# Skibidi_tualet_proxy
# ==========================================================


def run_git_command(args):

    try:

        result = subprocess.run(

            [

                "git",

            ]
            +
            args,


            cwd=BASE_DIR,


            capture_output=True,


            text=True,

            encoding="utf-8",

            errors="ignore"

        )


        if result.returncode != 0:


            logger.warning(

                "Git command failed: %s",

                result.stderr.strip()

            )


            return False



        return True



    except Exception as e:


        logger.warning(

            "Git error: %s",

            e

        )


        return False





def git_pull():


    logger.info(

        "Git pull..."

    )



    # проверяем есть ли локальные изменения

    status = subprocess.run(

        [

            "git",

            "status",

            "--porcelain"

        ],


        cwd=BASE_DIR,


        capture_output=True,


        text=True

    )



    if status.stdout.strip():


        logger.info(

            "Local changes detected, skip pull"

        )


        return False



    return run_git_command(

        [

            "pull",

            "--rebase"

        ]

    )





def git_commit_push(message):


    logger.info(

        "Git commit..."

    )



    run_git_command(

        [

            "add",

            "my_sub.txt",

            "output"

        ]

    )



    commit_ok = run_git_command(

        [

            "commit",

            "-m",

            message

        ]

    )



    if not commit_ok:


        logger.info(

            "Nothing to commit"

        )



    logger.info(

        "Git push..."

    )



    return run_git_command(

        [

            "push"

        ]

    )

# ==========================================================
# CHUNK LOADER
# Skibidi_tualet_proxy
# ==========================================================


def get_chunks():


    if not CHUNKS_DIR.exists():


        logger.error(

            "Chunks directory not found: %s",

            CHUNKS_DIR

        )


        return []



    chunks = sorted(

        CHUNKS_DIR.glob(

            "chunk_*.txt"

        )

    )


    logger.info(

        "Found chunks: %s",

        len(chunks)

    )


    return chunks





def load_chunk(

        chunk_file

):


    nodes = []

    seen = set()



    try:


        with open(

            chunk_file,

            "r",

            encoding="utf-8",

            errors="ignore"

        ) as f:



            for line in f:


                line = line.strip()



                if not line:


                    continue



                # поддерживаем только VLESS

                if not line.startswith(

                    "vless://"

                ):


                    continue



                # удаляем дубли

                clean = line.split(

                    "#"

                )[0]



                if clean in seen:


                    continue



                seen.add(

                    clean

                )



                nodes.append(

                    line

                )



    except Exception as e:


        logger.error(

            "Chunk load error %s: %s",

            chunk_file,

            e

        )



        return []



    logger.info(

        "%s loaded: %s nodes",

        chunk_file.name,

        len(nodes)

    )



    return nodes





def load_all_nodes():


    all_nodes = []

    seen = set()



    chunks = get_chunks()



    for chunk in chunks:


        nodes = load_chunk(

            chunk

        )



        for node in nodes:


            key = node.split(

                "#"

            )[0]



            if key not in seen:


                seen.add(

                    key

                )


                all_nodes.append(

                    node

                )



    logger.info(

        "Total unique VLESS nodes: %s",

        len(all_nodes)

    )


    return all_nodes

# ==========================================================
# VLESS PARSER
# Skibidi_tualet_proxy
# ==========================================================



def parse_vless(uri):


    try:


        parsed = urlparse(

            uri

        )



        if parsed.scheme.lower() != "vless":


            return None



        query = parse_qs(

            parsed.query

        )



        # ==================================================
        # UUID
        # ==================================================


        raw_uuid = parsed.username



        if not raw_uuid:


            logger.warning(

                "VLESS UUID empty"

            )


            return None




        uuid_value = raw_uuid



        for _ in range(5):


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

                uuid_value

            )


            return None




        # ==================================================
        # ADDRESS
        # ==================================================


        address = parsed.hostname



        if not address:


            return None



        port = parsed.port or 443




        # ==================================================
        # PARAM HELPER
        # ==================================================


        def get_param(

                name,

                default=""

        ):


            value = query.get(

                name,

                [

                    default

                ]

            )[0]


            return unquote(

                value

            )





        # ==================================================
        # NAME
        # ==================================================


        name = generate_proxy_name(

            address

        )





        # ==================================================
        # RESULT
        # ==================================================


        return {


            "uri":

            uri,



            "name":

            name,



            "uuid":

            uuid_value,



            "address":

            address,



            "port":

            port,



            "security":

            get_param(

                "security",

                "none"

            ),



            "network":

            get_param(

                "type",

                "tcp"

            ),



            "flow":

            get_param(

                "flow",

                ""

            ),



            "sni":

            get_param(

                "sni",

                get_param(

                    "serverName",

                    ""

                )

            ),



            "fingerprint":

            get_param(

                "fp",

                "chrome"

            ),



            "public_key":

            get_param(

                "pbk",

                get_param(

                    "publicKey",

                    ""

                )

            ),



            "short_id":

            get_param(

                "sid",

                get_param(

                    "shortId",

                    ""

                )

            ),



            "path":

            get_param(

                "path",

                "/"

            ),



            "host":

            get_param(

                "host",

                ""

            ),



            "service_name":

            get_param(

                "serviceName",

                ""

            ),



            "encryption":

            get_param(

                "encryption",

                "none"

            ),



        }




    except Exception as e:


        logger.warning(

            "VLESS parse error: %s",

            e

        )


        return None

# ==========================================================
# XRAY CONFIG BUILDER
# Skibidi_tualet_proxy
# ==========================================================


def build_xray_config(

        node,

        socks_port

):


    security = node.get(

        "security",

        "none"

    )


    network = node.get(

        "network",

        "tcp"

    )



    stream_settings = {



        "network":

        network,



        "security":

        security,



    }



    # ======================================================
    # TLS
    # ======================================================


    if security == "tls":


        stream_settings[

            "tlsSettings"

        ] = {


            "serverName":

            node.get(

                "sni",

                ""

            ),


            "fingerprint":

            node.get(

                "fingerprint",

                "chrome"

            ),

        }



    # ======================================================
    # REALITY
    # ======================================================


    if security == "reality":


        stream_settings[

            "realitySettings"

        ] = {


            "serverName":

            node.get(

                "sni",

                ""

            ),



            "fingerprint":

            node.get(

                "fingerprint",

                "chrome"

            ),



            "publicKey":

            node.get(

                "public_key",

                ""

            ),



            "shortId":

            node.get(

                "short_id",

                ""

            ),


        }



    # ======================================================
    # WS
    # ======================================================


    if network == "ws":


        stream_settings[

            "wsSettings"

        ] = {


            "path":

            node.get(

                "path",

                "/"

            ),



            "headers":

            {


                "Host":

                node.get(

                    "host",

                    ""

                )

            }

        }



    # ======================================================
    # GRPC
    # ======================================================


    if network == "grpc":


        stream_settings[

            "grpcSettings"

        ] = {


            "serviceName":

            node.get(

                "service_name",

                ""

            )

        }



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

                "127.0.0.1",



                "port":

                socks_port,



                "protocol":

                "socks",



                "settings":

                {


                    "udp":

                    True

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

                                    node.get(

                                        "encryption",

                                        "none"

                                    ),



                                    "flow":

                                    node.get(

                                        "flow",

                                        ""

                                    )

                                }



                            ]

                        }



                    ]

                },



                "streamSettings":

                stream_settings



            }



        ]

    }



    return config





# ==========================================================
# START XRAY
# ==========================================================



def start_xray(

        config_file

):


    try:


        process = subprocess.Popen(

            [

                str(XRAY_PATH),

                "run",

                "-config",

                str(config_file)

            ],



            stdout=subprocess.PIPE,


            stderr=subprocess.PIPE,


            creationflags=subprocess.CREATE_NO_WINDOW

        )



        return process



    except Exception as e:


        logger.error(

            "Xray start failed: %s",

            e

        )


        return None





def wait_port(

        port,

        timeout=10

):


    start = time.time()



    while time.time() - start < timeout:



        sock = socket.socket(

            socket.AF_INET,

            socket.SOCK_STREAM

        )



        try:


            sock.settimeout(

                1

            )


            sock.connect(

                (

                    XRAY_HOST,

                    port

                )

            )



            sock.close()



            return True



        except Exception:


            time.sleep(

                0.2

            )



        finally:


            sock.close()



    return False





def stop_xray(

        process

):


    if not process:


        return



    try:


        process.terminate()



        process.wait(

            timeout=3

        )



    except Exception:


        try:


            process.kill()


        except Exception:


            pass

# ==========================================================
# PROXY TESTER
# Skibidi_tualet_proxy
# ==========================================================



def test_service(

        name,

        url,

        socks_port

):


    proxies = {


        "http":

        f"socks5h://{XRAY_HOST}:{socks_port}",



        "https":

        f"socks5h://{XRAY_HOST}:{socks_port}",


    }



    try:


        start = time.time()



        response = requests.get(


            url,


            proxies=proxies,


            timeout=REQUEST_TIMEOUT,


            allow_redirects=True


        )



        latency = (

            time.time()

            -

            start

        ) * 1000



        return {


            "ok":

            True,



            "status":

            response.status_code,



            "latency":

            round(

                latency,

                0

            )

        }



    except Exception as e:


        return {


            "ok":

            False,



            "error":

            str(e)

        }







def test_proxy(

        socks_port

):


    results = {}



    for name, url in TEST_TARGETS.items():


        result = test_service(


            name,


            url,


            socks_port


        )


        results[name] = result




        if result["ok"]:


            logger.info(

                "%s OK %sms",

                name,

                result.get(

                    "latency",

                    "?"

                )

            )


        else:


            logger.warning(

                "%s FAIL %s",

                name,

                result.get(

                    "error",

                    ""

                )

            )



    return results





def calculate_score(

        results

):


    score = 0



    for service in results.values():



        if service.get(

            "ok",

            False

        ):


            score += 25



    return score





def check_node(

        node

):


    socks_port = (

        SOCKS_START_PORT

        +

        random.randint(

            1,

            500

        )

    )



    config = build_xray_config(


        node,


        socks_port


    )



    config_file = (

        TEMP_DIR

        /

        f"xray_test_{socks_port}.json"

    )



    with open(

        config_file,

        "w",

        encoding="utf-8"

    ) as f:



        json.dump(

            config,

            f,

            indent=4,

            ensure_ascii=False

        )



    process = start_xray(

        config_file

    )



    if not process:


        return {


            "ok":

            False,


            "error":

            "xray_start_failed"

        }





    try:



        if not wait_port(

            socks_port

        ):


            return {


                "ok":

                False,


                "error":

                "socks_not_started"

            }




        start = time.time()



        tests = test_proxy(

            socks_port

        )



        elapsed = (

            time.time()

            -

            start

        )



        score = calculate_score(

            tests

        )




        return {


            "ok":

            score > 0,



            "node":

            node,



            "name":

            node["name"],



            "score":

            score,



            "tests":

            tests,



            "time":

            round(

                elapsed,

                2

            )

        }




    finally:



        stop_xray(

            process

        )



        try:


            config_file.unlink()



        except Exception:


            pass

# ==========================================================
# CHUNK PROCESSOR
# Skibidi_tualet_proxy
# ==========================================================



MAX_NODES_PER_CHUNK = 1000



CHECK_DELAY = 0.2





def save_json(

        data

):


    try:


        with open(

            STATS_FILE,

            "w",

            encoding="utf-8"

        ) as f:


            json.dump(

                data,

                f,

                indent=4,

                ensure_ascii=False

            )



    except Exception as e:


        logger.warning(

            "Stats save error: %s",

            e

        )







def make_vless_link(

        node

):


    """

    Возвращаем ссылку с красивым именем

    """



    uri = node["uri"]



    base = uri.split(

        "#"

    )[0]



    return (

        base

        +

        "#"

        +

        quote(

            node["name"]

        )

    )







def save_results(

        good_nodes

):


    # сортировка:

    # лучшие сверху



    good_nodes.sort(

        key=lambda x:

        x.get(

            "score",

            0

        ),

        reverse=True

    )



    links = []



    for item in good_nodes:


        links.append(

            make_vless_link(

                item["node"]

            )

        )



    # checked_vless.txt


    with open(

        CHECKED_FILE,

        "w",

        encoding="utf-8"

    ) as f:



        for link in links:


            f.write(

                link

                +

                "\n"

            )



    # my_sub.txt


    with open(

        MY_SUB_FILE,

        "w",

        encoding="utf-8"

    ) as f:



        for link in links:


            f.write(

                link

                +

                "\n"

            )



    logger.info(

        "Saved nodes: %s",

        len(links)

    )








def process_chunk(

        chunk_file

):


    logger.info(

        "Checking %s",

        chunk_file.name

    )



    nodes = load_chunk(

        chunk_file

    )



    good = []



    for index, uri in enumerate(nodes):



        try:



            node = parse_vless(

                uri

            )



            if not node:


                continue




            result = check_node(

                node

            )




            if result.get(

                "ok",

                False

            ):



                good.append(

                    result

                )



                logger.info(

                    "OK %s | %s",

                    result["score"],

                    node["name"]

                )



            else:


                logger.info(

                    "FAIL | %s",

                    result.get(

                        "error",

                        ""

                    )

                )



        except Exception as e:


            logger.warning(

                "Node error: %s",

                e

            )



        time.sleep(

            CHECK_DELAY

        )



    return good








def process_all_chunks():


    all_good = []



    chunks = get_chunks()



    total = len(

        chunks

    )



    for number, chunk in enumerate(

        chunks,

        start=1

    ):



        logger.info(

            "Chunk %s/%s",

            number,

            total

        )



        result = process_chunk(

            chunk

        )



        all_good.extend(

            result

        )



        save_results(

            all_good

        )



        save_json(

            {


                "updated":

                datetime.now().isoformat(),



                "chunks_done":

                number,



                "alive":

                len(all_good)

            }

        )



    return all_good

# ==========================================================
# CLEANUP
# Skibidi_tualet_proxy
# ==========================================================



def cleanup_temp():


    try:


        if TEMP_DIR.exists():


            for item in TEMP_DIR.iterdir():


                try:


                    if item.is_file():


                        item.unlink()



                    elif item.is_dir():


                        shutil.rmtree(

                            item

                        )



                except Exception:


                    pass



    except Exception as e:


        logger.warning(

            "Cleanup error: %s",

            e

        )








def kill_xray_processes():


    try:


        subprocess.run(

            [

                "taskkill",

                "/F",

                "/IM",

                "xray.exe"

            ],


            stdout=subprocess.DEVNULL,


            stderr=subprocess.DEVNULL

        )



    except Exception:


        pass








# ==========================================================
# MAIN
# ==========================================================



def main():


    logger.info(

        "================================="

    )


    logger.info(

        "Skibidi_tualet_proxy START"

    )


    logger.info(

        "================================="

    )



    try:



        check_environment()



        cleanup_temp()



        git_pull()



        alive = process_all_chunks()



        logger.info(

            "Alive nodes: %s",

            len(alive)

        )



        save_results(

            alive

        )



        stats = {


            "finished":

            datetime.now().isoformat(),



            "alive":

            len(alive)

        }



        save_json(

            stats

        )



        git_commit_push(

            "Auto update proxy list"

        )



        logger.info(

            "Finished successfully"

        )



    except KeyboardInterrupt:


        logger.warning(

            "Stopped by user"

        )



    except Exception as e:


        logger.exception(

            "Fatal error: %s",

            e

        )



    finally:


        kill_xray_processes()



        cleanup_temp()



        logger.info(

            "Stopped"

        )







# ==========================================================
# ENTRY POINT
# ==========================================================



if __name__ == "__main__":


    main()