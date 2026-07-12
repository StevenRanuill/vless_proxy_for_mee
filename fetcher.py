import urllib.request
import re
import html
import os
import hashlib
import json
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

CONFIG = {
    "PROXY_REGEX": r'(vless://[^\s]+|vmess://[^\s]+|trojan://[^\s]+|ss://[^\s]+|hysteria2://[^\s]+|tuic://[^\s]+)',
    "CHUNK_SIZE": 200,
    "CHUNKS_DIR": "raw_chunks",
    "HISTORY_FILE": "history_blacklist.json",
    "RETAIN_DAYS": 3  # Сколько дней не повторять один и тот же сервер
}

SOURCES_STATIC = [
    "https://ghfast.top",
    "https://v2gh.com",
    "https://ghfast.top",
    "https://githack.com"
]

SOURCES_TELEGRAM = ["v2ray_outline_config", "VPNCustm", "FreeVlessConfig", "v2rayNG_VPNo"]

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

def fetch_source(url_or_channel, is_tg=False):
    target_url = f"https://t.me{url_or_channel}" if is_tg else url_or_channel
    try:
        req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
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

# --- НОВЫЙ МЕХАНИЗМ: РАБОТА С ИСТОРИЕЙ И СКЛЕЙКА БЛЭКЛИСТА ---
def load_and_clean_history():
    """Загружает историю и удаляет записи старше RETAIN_DAYS."""
    if not os.path.exists(CONFIG["HISTORY_FILE"]):
        return {}
    try:
        with open(CONFIG["HISTORY_FILE"], "r", encoding="utf-8") as f:
            history = json.load(f)
        
        # Фильтрация устаревших записей
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
    print("1. Загрузка истории ротации серверов...")
    history_db = load_and_clean_history()
    print(f"-> В блэклисте истории сейчас активны: {len(history_db)} серверов.")

    print("2. Сбор баз серверами GitHub...")
    raw_pool = set()
    for url in SOURCES_STATIC:
        raw_pool.update(fetch_source(url, is_tg=False))
    for chan in SOURCES_TELEGRAM:
        raw_pool.update(fetch_source(chan, is_tg=True))
    
    print(f"3. Всего сырых строк: {len(raw_pool)}. Дедупликация и фильтрация истории...")
    seen_fps = set()
    final_pool = []
    skipped_by_history = 0
    
    for node in raw_pool:
        fp, clean_node = optimize_node(node)
        if fp and fp not in seen_fps:
            seen_fps.add(fp)
            
            # Хэшируем отпечаток 'хост:порт', чтобы проверять по базе истории
            fp_hash = hashlib.md5(fp.encode()).hexdigest()
            
            # Если сервер уже использовался недавно — пропускаем его
            if fp_hash in history_db:
                skipped_by_history += 1
                continue
                
            final_pool.append(clean_node)
            
    print(f"-> Отброшено дубликатов по истории прошлых запусков: {skipped_by_history}")
    print(f"-> Передано на этап нарезки: {len(final_pool)} новых уникальных нод.")
            
    # Очистка папки raw_chunks перед созданием новых
    if os.path.exists(CONFIG["CHUNKS_DIR"]):
        for f in os.listdir(CONFIG["CHUNKS_DIR"]):
            os.remove(os.path.join(CONFIG["CHUNKS_DIR"], f))
            
    # Нарезка пула на пачки
    os.makedirs(CONFIG["CHUNKS_DIR"], exist_ok=True)
    chunk_size = CONFIG["CHUNK_SIZE"]
    chunk_num = 0
    
    for i in range(0, len(final_pool), chunk_size):
        chunk_num = (i // chunk_size) + 1
        chunk_data = final_pool[i:i + chunk_size]
        chunk_file = os.path.join(CONFIG["CHUNKS_DIR"], f"chunk_{chunk_num}.txt")
        with open(chunk_file, "w", encoding="utf-8") as f:
            f.write("\n".join(chunk_data))
            
    print(f"4. Успешно нарезано {chunk_num} пачек по {chunk_size} нод в папку {CONFIG['CHUNKS_DIR']}")

if __name__ == '__main__':
    main()
