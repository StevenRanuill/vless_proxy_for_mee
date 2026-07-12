import asyncio
import aiohttp
import re
import html
import os
import hashlib
import json
import shutil
import base64
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

CONFIG = {
    "PROXY_REGEX": r'(vless://[^\s"\'<>\(\)]+|vmess://[^\s"\'<>\(\)]+|trojan://[^\s"\'<>\(\)]+|ss://[^\s"\'<>\(\)]+|hysteria2://[^\s"\'<>\(\)]+|tuic://[^\s"\'<>\(\)]+)',
    "CHUNK_SIZE": 1000,               # Оптимизировано: пачки строго по 1000 нод
    "CHUNKS_DIR": "raw_chunks",
    "HISTORY_FILE": "history_blacklist.json",
    "FILE_STAGE_1": "01_raw_all_downloaded.txt",
    "FILE_STAGE_2": "02_raw_unique_deduplicated.txt",
    "FILE_STAGE_3": "all_gathered_raw.txt",
    "RETAIN_DAYS": 3,
    "MAX_CONCURRENT_FETCH": 15
}


# Используем готовые, уже отфильтрованные авторами подписки (Борцы с ТСПУ)
ELITE_SUBSCRIPTIONS = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/ru-sni/vless.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/refs/heads/main/configs/vless.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/VOID-Anonymity/V.O.I.D-VPN_Bypass/refs/heads/main/url_work.txt",
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/refs/heads/master/result/nodes",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/refs/heads/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/refs/heads/main/sub/Mix/mix.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/refs/heads/main/sub/mix",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/refs/heads/main/sub/mix",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/Mr-Meshky/vify/refs/heads/main/configs/vless.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    "https://s3c3.001.gpucloud.ru/wlr/wl.txt",
    "https://etoneya.su/whitelist"    
]

ef normalize_github_url(url):
    url = url.strip()
    if "github.com" in url and "/raw/" in url:
        url = url.replace("github.com", "://githubusercontent.com").replace("/raw/", "/")
    if "github.com" in url and "/blob/" in url:
        url = url.replace("github.com", "://githubusercontent.com").replace("/blob/", "/")
    return url

def clean_and_extract(raw_text):
    unescaped = html.unescape(raw_text)
    clean_text = re.sub(r'[\u200b-\u200d\u200e\u200f\ufeff\u202a-\u202e]', '', unescaped)
    
    if not clean_text.strip().startswith(('vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'tuic://')):
        try:
            decoded = base64.b64decode(clean_text.strip()).decode('utf-8', errors='ignore')
            if decoded.startswith(('vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'tuic://')):
                clean_text = decoded
        except:
            pass

    found = re.findall(CONFIG["PROXY_REGEX"], clean_text)
    sanitized = []
    for node in found:
        clean_node = node.strip().strip('"').strip("'").strip('(').strip(')')
        if "@" in clean_node and "://" in clean_node:
            sanitized.append(clean_node)
    return sanitized

async def fetch_source(semaphore, session, url):
    async with semaphore:
        url = normalize_github_url(url)
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            async with session.get(url, headers=headers, timeout=12) as response:
                if response.status == 200:
                    text_content = await response.text(errors='ignore')
                    return clean_and_extract(text_content)
        except:
            pass
        return []

def optimize_node(proxy_link):
    try:
        node_str = proxy_link.strip().replace('&amp;', '&')
        if "://" not in node_str: return None, None
        scheme, body = node_str.split("://", 1)
        if "#" in body: body, _ = body.split("#", 1)
        if "?" in body: body, query_part = body.split("?", 1)
        else: query_part = ""
        if "@" in body: _, server_part = body.split("@", 1)
        else: server_part = body
        if "]" in server_part:
            host_part, port_part = server_part.split("]", 1)
            host = host_part + "]"
            port = port_part.replace(":", "") if ":" in port_part else "443"
        else:
            if ":" in server_part: host, port = server_part.split(":", 1)
            else: host, port = server_part, "443"
        port = "".join(filter(str.isdigit, port))
        port = port if port else "443"
        host = host.strip().lower()
        if not host: return None, None
        fingerprint = f"{host}:{port}"
        node_hash = hashlib.md5(host.encode()).hexdigest()[:8]
        rebuilt_query = f"?{query_part}" if query_part else ""
        cleaned_node = f"{scheme}://{body}{rebuilt_query}#NODE-{node_hash}"
        return fingerprint, cleaned_node
    except:
        return None, None

def load_and_clean_history():
    if not os.path.exists(CONFIG["HISTORY_FILE"]): return {}
    try:
        with open(CONFIG["HISTORY_FILE"], "r", encoding="utf-8") as f: history = json.load(f)
        now = datetime.now()
        clean_history = {}
        cutoff_date = now - timedelta(days=CONFIG["RETAIN_DAYS"])
        for fp_hash, date_str in history.items():
            if datetime.strptime(date_str, "%Y-%m-%d") > cutoff_date: clean_history[fp_hash] = date_str
        return clean_history
    except: return {}

async def async_main():
    history_db = load_and_clean_history()
    stage_1_list = []
    
    semaphore = asyncio.Semaphore(CONFIG["MAX_CONCURRENT_FETCH"])
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_source(semaphore, session, url) for url in ELITE_SUBSCRIPTIONS]
        results = await asyncio.gather(*tasks)
        for nodes in results:
            stage_1_list.extend(nodes)
            
    # [СТАДИЯ 1] Сохранение абсолютно всех скачанных сырых строк
    with open(CONFIG["FILE_STAGE_1"], "w", encoding="utf-8") as f: f.write("\n".join(stage_1_list))
    print(f"Шаг 1 выполнен. Всего скачано нод: {len(stage_1_list)}")
            
    seen_fps = set()
    stage_2_list = []
    final_pool = []
    
    for node in stage_1_list:
        fp, clean_node = optimize_node(node)
        if fp and fp not in seen_fps:
            seen_fps.add(fp)
            stage_2_list.append(clean_node)
            
            fp_hash = hashlib.md5(fp.encode()).hexdigest()
            if fp_hash not in history_db:
                final_pool.append(clean_node)
                
    # [СТАДИЯ 2] Сохранение уникальных отфильтрованных нод
    with open(CONFIG["FILE_STAGE_2"], "w", encoding="utf-8") as f: f.write("\n".join(stage_2_list))
    # [СТАДИЯ 3] Сохранение нод, готовых для текущей пачки чекера (минуя историю)
    with open(CONFIG["FILE_STAGE_3"], "w", encoding="utf-8") as f: f.write("\n".join(final_pool))
    
    print(f"Шаг 2 выполнен. Уникальных: {len(stage_2_list)}. Шаг 3 выполнен. К проверке: {len(final_pool)}")
            
    if os.path.exists(CONFIG["CHUNKS_DIR"]): shutil.rmtree(CONFIG["CHUNKS_DIR"])
    os.makedirs(CONFIG["CHUNKS_DIR"], exist_ok=True)
    
    if not final_pool:
        with open(os.path.join(CONFIG["CHUNKS_DIR"], "chunk_empty.txt"), "w", encoding="utf-8") as f: f.write("")
        return

    chunk_size = CONFIG["CHUNK_SIZE"]
    chunk_num = 0
    for i in range(0, len(final_pool), chunk_size):
        chunk_num = (i // chunk_size) + 1
        with open(os.path.join(CONFIG["CHUNKS_DIR"], f"chunk_{chunk_num}.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(final_pool[i:i + chunk_size]))
    print(f"Нарезано пачек по 1000 нод: {chunk_num}")

if __name__ == '__main__':
    asyncio.run(async_main())
