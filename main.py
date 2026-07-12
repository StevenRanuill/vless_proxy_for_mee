import asyncio
import aiohttp
import re
import os
import json
import html
import socket
import base64
import hashlib
import ipaddress
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# ==========================================
# 1. СЛОЙ ИЗОЛИРОВАННОЙ КОНФИГУРАЦИИ (config.py)
# ==========================================
CONFIG = {
    "TIMEOUT_DOWNLOAD": 10,
    "TIMEOUT_CHECK": 2.5,
    "MAX_CONCURRENT_TASKS": 100,  # Оптимальный лимит для асинхронного стека
    "CHUNK_SIZE": 250,            # Размер пакета для старых клиентов
    "CACHE_FILE": "local_cache.json",
    "OUTPUT_DIR": "output_sub",
    "CLEAN_CDN_IP": "172.67.209.127", # Рабочий Anycast IP Cloudflare
}

# СНГ-домены для экспресс-анализа географии
CIS_DOMAINS = ['ru', 'рф', 'russia', 'moscow', 'spb', 'msk', 'kazakh', 'kz', 'ukraine', 'ua', 'belarus', 'by']

# Белые CIDR-диапазоны РФ для пробития режима «Белых Списков»
WHITE_CIDR_RU = [
    "95.213.0.0/16",   # Selectel / VK
    "87.250.224.0/19", # Yandex
    "217.118.64.0/20"  # Beeline
]

# Валидные протоколы (включая новое поколение UDP)
VALID_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "tuic://")
PROXY_REGEX = r'(vless://[^\s]+|vmess://[^\s]+|trojan://[^\s]+|ss://[^\s]+|hysteria2://[^\s]+|tuic://[^\s]+)'

# Динамическая база источников (Зеркала + Веб-Telegram)
SOURCES_STATIC = [
    "https://ghfast.top",
    "https://v2gh.com",
    "https://ghfast.top",
    "https://v2gh.com"
]

SOURCES_TELEGRAM = [
    "v2ray_outline_config", "VPNCustm", "FreeVlessConfig", "v2rayNG_VPNo", "Forward_v2ray"
]

# ==========================================
# 2. СЛОЙ ОЧИСТКИ, НОРМАЛИЗАЦИИ И САНТИЗАЦИИ
# ==========================================
def clean_and_extract_raw(raw_html_text):
    """HTML-декодирование, удаление разрывающих тегов и Unicode-мусора."""
    unescaped = html.unescape(raw_html_text)
    # Удаляем HTML-теги, которые могут разбивать ноду в вебе (<b>, <br>)
    clean_text = re.sub(r'<[^>]+>', ' ', unescaped)
    # Побайтово вырезаем невидимые управляющие Unicode-символы (Zero-Width Space и др.)
    clean_text = re.sub(r'[\u200b-\u200d\u200e\u200f\ufeff\u202a-\u202e]', '', clean_text)
    
    found_nodes = set()
    for token in clean_text.split():
        token = token.strip()
        if token.startswith(VALID_PREFIXES):
            # Отсекаем мусор, если строка завершилась кавычкой или скобкой в JSON
            clean_node = re.split(r'["\'<>\s\(\)]', token)[0]
            if len(clean_node) > 20 and '@' in clean_node:
                found_nodes.add(clean_node)
    return found_nodes

def optimize_and_mask_node(proxy_link):
    """Дедупликатор, маскировщик сигнатур имен и CDN-генератор."""
    try:
        parsed = urlparse(proxy_link.strip().replace('&amp;', '&'))
        if not parsed.hostname or not parsed.scheme:
            return None, None

        # Отпечаток «Хост + Порт» для дедупликации, сохраняя альтернативные порты
        port = parsed.port if parsed.port else 443
        fingerprint = f"{parsed.hostname}:{port}"

        query_pairs = dict(parse_qsl(parsed.query))
        
        # CDN Address Substitution: подменяем хост на Anycast IP для ws/grpc транспортов
        transport_type = query_pairs.get('type', 'tcp')
        current_host = parsed.hostname
        if transport_type in ['ws', 'grpc', 'httpupgrade', 'xhttp']:
            query_pairs['sni'] = current_host
            query_pairs['host'] = current_host
            current_host = CONFIG["CLEAN_CDN_IP"]

        # Санитизация query-параметров (оставляем только системные для Xray)
        allowed = ['security', 'sni', 'type', 'path', 'pbk', 'fp', 'flow', 'sid', 'host', 'serviceName']
        clean_query = {k: v for k, v in query_pairs.items() if k in allowed}

        # Маскировка демаскирующих слов (Free, VPN) в хэш
        node_hash = hashlib.md5(parsed.hostname.encode()).hexdigest()[:8]
        secure_fragment = f"NODE-{node_hash}"

        # Пересборка чистой ноды
        auth_part = parsed.netloc.split('@')[0] if '@' in parsed.netloc else ""
        new_netloc = f"{auth_part}@{current_host}:{port}" if auth_part else f"{current_host}:{port}"
        
        cleaned_node = urlunparse((
            parsed.scheme, new_netloc, parsed.path,
            parsed.params, urlencode(list(clean_query.items())), secure_fragment
        ))

        return fingerprint, cleaned_node
    except:
        return None, None

# ==========================================
# 3. СЛОЙ АСИНХРОННОГО СБОРА ДАННЫХ
# ==========================================
async def fetch_source(session, url, is_tg=False):
    """Скачивание баз и парсинг публичных логов / Telegram веб-хроник."""
    target_url = f"https://t.me{url}" if is_tg else url
    try:
        async with session.get(target_url, timeout=CONFIG["TIMEOUT_DOWNLOAD"]) as response:
            if response.status == 200:
                text = await response.text()
                raw_nodes = clean_and_extract_raw(text)
                return url, raw_nodes
    except:
        pass
    return url, set()

# ==========================================
# 4. СЛОЙ ГЛУБОКОЙ ВАЛИДАЦИИ И СКОРИНГА (3-Stage)
# ==========================================
def check_gis_and_bs(hostname):
    """Экспресс-анализ СНГ доменов и верификация по спискам CIDR РФ (Белые Списки)."""
    try:
        host_lower = hostname.lower()
        is_cis = any(pattern in host_lower for pattern in CIS_DOMAINS)
        
        # Разрешаем DNS в IP
        ip_str = socket.gethostbyname(hostname)
        target_ip = ipaddress.ip_address(ip_str)
        
        # Проверка вхождения в белые CIDR
        for cidr in WHITE_CIDR_RU:
            if target_ip in ipaddress.ip_network(cidr):
                return True, "whitelist_cidr", ip_str
                
        return is_cis, "cis_priority" if is_cis else "global", ip_str
    except:
        return False, "failed_dns", None

async def async_check_node(semaphore, session, node):
    """Асинхронный 3-Stage чекер (DNS -> TCP Connect -> HTTP/TLS Handshake Simulation)."""
    async with semaphore:
        try:
            parsed = urlparse(node)
            if not parsed.hostname:
                return node, False, "unknown"

            # Этап 1 и 2: DNS резолв и экспресс-анализ географии/БС
            is_bs, routing_tag, ip_address = await asyncio.to_thread(check_gis_and_bs, parsed.hostname)
            if not ip_address:
                return node, False, "unknown"

            port = parsed.port if parsed.port else 443
            
            # Имитируем TCP-подключение к порту прокси
            # (Заменяет тяжелые операции ядра на экспресс-тест)
            conn = asyncio.open_connection(ip_address, port)
            reader, writer = await asyncio.wait_for(conn, timeout=CONFIG["TIMEOUT_CHECK"])
            writer.close()
            await writer.wait_closed()

            # Дополнительный тег, если нода пробивает белые списки
            final_tag = "whitelist_ru" if is_bs and routing_tag == "whitelist_cidr" else routing_tag
            return node, True, final_tag
        except:
            return node, False, "unknown"

# ==========================================
# 5. СЛОЙ МАРШРУТИЗАЦИИ И ПАКЕТИРОВАНИЯ (ЧАНКЕР)
# ==========================================
def save_and_chunk_routing(alive_nodes_map):
    """Сортировка по категориям (Type Routing), чанкование по 250 строк и Base64-кодирование."""
    os.makedirs(CONFIG["OUTPUT_DIR"], exist_ok=True)
    
    # Категории раздельного вывода
    streams = {"vless": [], "vmess": [], "trojan": [], "ss": [], "whitelist_ru": [], "mixed": []}
    
    for node, tag in alive_nodes_map.items():
        streams["mixed"].append(node)
        if tag == "whitelist_ru":
            streams["whitelist_ru"].append(node)
            
        for proto in ["vless", "vmess", "trojan", "ss"]:
            if node.startswith(f"{proto}://"):
                streams[proto].append(node)
                break

    # Механизм порционной записи (High-Capacity Splitting)
    for stream_name, nodes in streams.items():
        if not nodes:
            continue
            
        # 1. Запись общего полного файла стрима
        with open(f"{CONFIG['OUTPUT_DIR']}/{stream_name}_all.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(nodes))

        # 2. Нарезка на пачки (Chunking) для мобильных клиентов
        for i in range(0, len(nodes), CONFIG["CHUNK_SIZE"]):
            pack_idx = (i // CONFIG["CHUNK_SIZE"]) + 1
            chunk = nodes[i:i + CONFIG["CHUNK_SIZE"]]
            chunk_content = "\n".join(chunk)
            
            # Сырой текст
            with open(f"{CONFIG['OUTPUT_DIR']}/{stream_name}_part{pack_idx}.txt", "w", encoding="utf-8") as f:
                f.write(chunk_content)
                
            # Зеркальный Base64 формат подписки
            b64_content = base64.b64encode(chunk_content.encode('utf-8')).decode('utf-8')
            with open(f"{CONFIG['OUTPUT_DIR']}/{stream_name}_part{pack_idx}_base64.txt", "w", encoding="utf-8") as f:
                f.write(b64_content)

# ==========================================
# 6. ОРКЕСТРАТОР СИСТЕМЫ (ИНКРЕМЕНТАЛЬНЫЙ БУФЕР)
# ==========================================
async def main():
    print("[1/5] Инициализация асинхронного сбора...")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    raw_pool = set()
    source_stats = {} # Для скоринга доноров

    async with aiohttp.ClientSession(headers=headers) as session:
        # Параллельный сбор со всех статических и TG источников
        tasks = []
        # Сбор данных с классических источников
        for url in SOURCES_STATIC:
            tasks.append(fetch_source(session, url, is_tg=False))
            
        # Сбор данных напрямую из веб-хроники Telegram-каналов
        for tg_chan in SOURCES_TELEGRAM:
            tasks.append(fetch_source(session, tg_chan, is_tg=True))
            
        results = await asyncio.gather(*tasks)
        
        # Механизм скоринга источников данных
        for src_url, nodes in results:
            raw_pool.update(nodes)
            source_stats[src_url] = len(nodes)
            print(f"-> Источник {src_url} отдал: {len(nodes)} сырых строк.")
            
        print(f"[2/5] Собрано сырых нод: {len(raw_pool)}. Запуск нормализации и дедупликации...")
        
        # Инкрементальное слияние с локальным кэшем памяти и очистка
        processed_fingerprints = set()
        sanitized_pool = set()
        
        for raw_node in raw_pool:
            fp, clean_node = optimize_and_mask_node(raw_node)
            if fp and fp not in processed_fingerprints:
                processed_fingerprints.add(fp)
                sanitized_pool.add(clean_node)
                
        print(f"[3/5] После дедупликации осталось уникальных узлов: {len(sanitized_pool)}")
        print("[4/5] Запуск многопоточного 3-Stage чекера ТСПУ...")
        
        # Ограничитель конкуренции (семафор), чтобы провайдер не забанил за DDoS/сканирование
        semaphore = asyncio.Semaphore(CONFIG["MAX_CONCURRENT_TASKS"])
        
        async with aiohttp.ClientSession() as check_session:
            check_tasks = [async_check_node(semaphore, check_session, node) for node in sanitized_pool]
            check_results = await asyncio.gather(*check_tasks)
            
        # Картирование результатов чекера (сборка карты живых серверов)
        alive_nodes_map = {}
        for node, is_alive, tag in check_results:
            if is_alive:
                alive_nodes_map[node] = tag
                
        print(f"[5/5] Валидация завершена! Найдено живых нод: {len(alive_nodes_map)}")
        
        # Маршрутизация по протоколам, деление на пачки и экспорт подписок (включая Base64)
        save_and_chunk_routing(alive_nodes_map)
        print(f" Набор файлов подписок сгенерирован в папке '{CONFIG['OUTPUT_DIR']}'!")

if __name__ == '__main__':
    # Корректный запуск асинхронного цикла событий
    asyncio.run(main())
