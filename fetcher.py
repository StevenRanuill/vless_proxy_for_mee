import urllib.request
import re
import html
import os
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

CONFIG = {
    "PROXY_REGEX": r'(vless://[^\s]+|vmess://[^\s]+|trojan://[^\s]+|ss://[^\s]+|hysteria2://[^\s]+|tuic://[^\s]+)',
    "CHUNK_SIZE": 300,
    "CHUNKS_DIR": "raw_chunks"
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

def clean_and_extract(raw_html):
    unescaped = html.unescape(raw_html)
    clean_text = re.sub(r'<[^>]+>', ' ', unescaped)
    clean_text = re.sub(r'[\u200b-\u200d\u200e\u200f\ufeff\u202a-\u202e]', '', clean_text)
    found = re.findall(CONFIG["PROXY_REGEX"], clean_text)
    sanitized = []
    for node in found:
        clean_node = node.strip().strip('"').strip("'").strip('(').strip(')')
        if "@" in clean_node and "://" in clean_node:
            sanitized.append(clean_node)
    return sanitized

def fetch_source(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return clean_and_extract(response.read().decode('utf-8', errors='ignore'))
    except:
        return []

def optimize_node(proxy_link):
    try:
        parsed = urlparse(proxy_link.strip().replace('&amp;', '&'))
        if not parsed.netloc or not parsed.scheme or not parsed.hostname:
            return None, None
        fingerprint = f"{parsed.hostname}:{parsed.port or 443}"
        allowed_params = ['security', 'sni', 'type', 'path', 'pbk', 'fp', 'flow', 'sid']
        query_pairs = parse_qsl(parsed.query)
        clean_query = [(k, v) for k, v in query_pairs if k in allowed_params]
        node_hash = hashlib.md5(parsed.hostname.encode()).hexdigest()[:8]
        cleaned_node = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(clean_query), f"NODE-{node_hash}"))
        return fingerprint, cleaned_node
    except:
        return None, None

def load_and_clean_history():
    if not os.path.exists(CONFIG["HISTORY_FILE"]):
        return {}
    try:
        with open(CONFIG["HISTORY_FILE"], "r", encoding="utf-8") as f:
            history = json.load(f)
        now = datetime.now()
        clean_history = {}
        cutoff_date = now - timedelta(days=CONFIG["RETAIN_DAYS"])
        for fp_hash, date_str in history.items():
            node_date = datetime.strptime(date_str, "%Y-%m-%d")
            if node_date > cutoff_date:
                clean_history[fp_hash] = date_str
        return clean_history
    except:
        return {}

def main():
    history_db = load_and_clean_history()
    raw_pool = set()
    
    print("1. Скачивание всех элитных подписок...")
    for url in ELITE_SUBSCRIPTIONS:
        found = fetch_source(url)
        raw_pool.update(found)
        print(f"-> Из {url[:45]}... извлечено {len(found)} нод.")
    
    seen_fps = set()
    final_pool = []
    all_raw_pool_for_txt = [] # Буфер для сохранения вообще всех уникальных сырых нод
    
    print("2. Фильтрация и дедупликация пула...")
    for node in raw_pool:
        fp, clean_node = optimize_node(node)
        if fp and fp not in seen_fps:
            seen_fps.add(fp)
            all_raw_pool_for_txt.append(clean_node) # Сюда идут все уникальные ноды до блэклиста
            
            # А сюда — только те, что не были заблокированы историей ротации
            fp_hash = hashlib.md5(fp.encode()).hexdigest()
            if fp_hash in history_db:
                continue
            final_pool.append(clean_node)
            
    # --- НОВЫЙ МЕХАНИЗМ: Сохранение файла со ВСЕМИ собранными уникальными серверами ---
    with open(CONFIG["ALL_RAW_FILE"], "w", encoding="utf-8") as f:
        f.write("\n".join(all_raw_pool_for_txt))
    print(f"-> Файл {CONFIG['ALL_RAW_FILE']} успешно создан (Всего уникальных нод: {len(all_raw_pool_for_txt)})")
            
    if os.path.exists(CONFIG["CHUNKS_DIR"]):
        shutil.rmtree(CONFIG["CHUNKS_DIR"])
    os.makedirs(CONFIG["CHUNKS_DIR"], exist_ok=True)
    
    # Защита от пустого пула пачек
    if not final_pool:
        with open(os.path.join(CONFIG["CHUNKS_DIR"], "chunk_empty.txt"), "w", encoding="utf-8") as f:
            f.write("")
        print("Новых нод нет. Создан пустой чанк-заглушка.")
        return

    chunk_size = CONFIG["CHUNK_SIZE"]
    chunk_num = 0
    for i in range(0, len(final_pool), chunk_size):
        chunk_num = (i // chunk_size) + 1
        chunk_data = final_pool[i:i + chunk_size]
        chunk_file = os.path.join(CONFIG["CHUNKS_DIR"], f"chunk_{chunk_num}.txt")
        with open(chunk_file, "w", encoding="utf-8") as f:
            f.write("\n".join(chunk_data))
            
    print(f"3. Успешно подготовлено пачек для отправки на ПК: {chunk_num}")

if __name__ == '__main__':
    main()
