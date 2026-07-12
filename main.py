import asyncio
import aiohttp
import re
import os
import base64
import json
import html
import socket
import ipaddress
import hashlib
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# =====================================================================
# 1. ГЛОБАЛЬНАЯ КОНФИГУРАЦИЯ (Паттерн Parameter Separation)
# =====================================================================
CONFIG = {
    "MAX_CONCURRENT_TASKS": 50,      # Ограничение потоков для чекера (Семафор)
    "TIMEOUT_FETCH": 10,             # Таймаут скачивания источников (секунды)
    "TIMEOUT_CHECK": 2.5,            # Таймаут проверки ноды сокетом (секунды)
    "OUTPUT_DIR": "output",          # Папка для сохранения готовых подписок
    "CHUNK_SIZE": 150,               # Размер пачки нод для мобильных клиентов
}

# Сверхширокий паттерн регулярного выражения для извлечения всех типов прокси
PROXY_REGEX = r'(vless://[^\s]+|vmess://[^\s]+|trojan://[^\s]+|ss://[^\s]+|hysteria2://[^\s]+|tuic://[^\s]+)'

# Проверенные и стабильные источники (GitHub + CDN Зеркала + Telegram)
SOURCES_STATIC = [
    "https://ghfast.top",
    "https://v2gh.com",
    "https://ghfast.top",
    "https://githack.com"
]

SOURCES_TELEGRAM = [
    "v2ray_outline_config",
    "VPNCustm",
    "FreeVlessConfig",
    "v2rayNG_VPNo"
]

# Белые CIDR-диапазоны РФ для БС-маршрутизации (Паттерн Whitelists Spoofing)
WHITE_CIDR_RU = [
    "95.213.0.0/16",    # Selectel / VK
    "87.250.224.0/19",  # Yandex
    "217.118.64.0/20"   # Beeline
]

# =====================================================================
# 2. СЛОЙ СБОРА И HTML/UNICODE САНИТИЗАЦИИ (Паттерн Lalatina/Epodonios)
# =====================================================================
def clean_and_extract_string(raw_html):
    """Механизм глубокой Unicode-очистки и извлечения URI-строк из HTML."""
    unescaped = html.unescape(raw_html)
    # Удаляем HTML-теги, разрывающие ноды в Telegram
    clean_text = re.sub(r'<[^>]+>', ' ', unescaped)
    # Побайтово вырезаем скрытые Unicode-артефакты (Zero-Width Space, RTL/LTR)
    clean_text = re.sub(r'[\u200b-\u200d\u200e\u200f\ufeff\u202a-\u202e]', '', clean_text)
    
    found = re.findall(PROXY_REGEX, clean_text)
    sanitized = []
    for node in found:
        # Убираем кавычки или скобки, если нода была внутри JSON-структур
        clean_node = node.strip().strip('"').strip("'").strip('(').strip(')')
        if "@" in clean_node and "://" in clean_node:
            sanitized.append(clean_node)
    return sanitized

async def fetch_source(session, url_or_channel, is_tg=False):
    """Асинхронный скрапер статических страниц и веб-хроник Telegram."""
    target_url = f"https://t.me{url_or_channel}" if is_tg else url_or_channel
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        async with session.get(target_url, headers=headers, timeout=CONFIG["TIMEOUT_FETCH"]) as response:
            if response.status == 200:
                html_content = await response.text()
                nodes = clean_and_extract_string(html_content)
                return url_or_channel, nodes
    except Exception:
        pass
    return url_or_channel, []
# =====================================================================
# 3. СЛОЙ ДЕДУПЛИКАЦИИ, САНАЦИИ И МАСКИРОВКИ СИГНАТУР (Паттерн VOID)
# =====================================================================
def optimize_and_mask_node(proxy_link):
    """
    Группирует ноды по отпечаткам 'Хост+Порт' (дедупликация).
    Стирает демаскирующие имена каналов и заменяет их на MD5 системные хэши.
    """
    try:
        proxy_link = proxy_link.strip().replace('&amp;', '&')
        parsed = urlparse(proxy_link)
        if not parsed.netloc or not parsed.scheme or not parsed.hostname:
            return None, None

        # Сохраняем уникальность пары хост:порт для защиты от веерных блокировок портов
        fingerprint = f"{parsed.hostname}:{parsed.port or 443}"

        # Фильтруем параметры, оставляя только критически важные для ядра Xray
        allowed_params = ['security', 'sni', 'type', 'path', 'pbk', 'fp', 'flow', 'sid']
        query_pairs = parse_qsl(parsed.query)
        clean_query = [(k, v) for k, v in query_pairs if k in allowed_params]

        # Генерируем нейтральное имя ноды вместо рекламы Telegram-каналов
        node_hash = hashlib.md5(parsed.hostname.encode()).hexdigest()[:8]
        secure_fragment = f"NODE-{node_hash}"

        cleaned_node = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(clean_query), secure_fragment
        ))
        return fingerprint, cleaned_node
    except Exception:
        return None, None

# =====================================================================
# 4. СЛОЙ МНОГОПОТОЧНОЙ ВАЛИДАЦИИ И АНАЛИЗА ТСПУ/CIDR (Паттерн sakha1370)
# =====================================================================
async def test_node_transport(semaphore, node):
    """
    Асинхронный 3-Stage чекер. Проверяет DNS-резолв, TCP-порт хоста 
    и маркирует ноду тегом 'CIDR-RU' при совпадении с белыми списками.
    """
    async with semaphore:
        try:
            parsed = urlparse(node)
            host = parsed.hostname
            port = int(parsed.port) if parsed.port else 443
            
            # Стадия 1 и 2: Асинхронный DNS-резолв и TCP-connect транспортного уровня
            loop = asyncio.get_event_loop()
            resolver_data = await loop.run_in_executor(None, socket.gethostbyname, host)
            target_ip = str(resolver_data)

            # Попытка установить асинхронное TCP-соединение
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port), 
                timeout=CONFIG["TIMEOUT_CHECK"]
            )
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)

            # Стадия 3: Валидация по белым спискам CIDR РФ (обход тотального блэкаута)
            ip_obj = ipaddress.ip_address(target_ip)
            for cidr in WHITE_CIDR_RU:
                if ip_obj in ipaddress.ip_network(cidr):
                    return node, True, "CIDR-RU"

            return node, True, "GLOBAL"
        except Exception:
            return node, False, "DEAD"
# =====================================================================
# 5. МАРШРУТИЗАЦИЯ, ДЕЛЕНИЕ НА ПАКЕТЫ И BASE64 ЭКСПОРТ (Паттерн Epodonios)
# =====================================================================
def save_and_chunk_routing(alive_map):
    """Разносит ноды по типам файлов, дробит на пачки и пишет Base64 зеркала."""
    out_dir = CONFIG["OUTPUT_DIR"]
    os.makedirs(out_dir, exist_ok=True)

    # Инициализация структуры категорий
    categories = {"vless": [], "vmess": [], "trojan": [], "ss": [], "cidr_ru": [], "all": []}
    
    for node, tag in alive_map.items():
        categories["all"].append(node)
        if tag == "CIDR-RU":
            categories["cidr_ru"].append(node)
        
        for proto in ["vless", "vmess", "trojan", "ss"]:
            if node.startswith(f"{proto}://"):
                categories[proto].append(node)
                break

    # Механизм порционной генерации и кодирования (Chunking Pipeline)
    for cat_name, nodes in categories.items():
        if not nodes:
            continue
            
        # 1. Запись монолитного файла категории
        main_file_path = os.path.join(out_dir, f"{cat_name}.txt")
        with open(main_file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(nodes))

        # 2. Нарезка на пачки под лимиты мобильных клиентов
        chunk_size = CONFIG["CHUNK_SIZE"]
        for i in range(0, len(nodes), chunk_size):
            chunk_num = (i // chunk_size) + 1
            chunk_nodes = nodes[i:i + chunk_size]
            chunk_text = "\n".join(chunk_nodes)

            # Сохраняем чистый текстовый чанк
            chunk_path = os.path.join(out_dir, f"{cat_name}_part{chunk_num}.txt")
            with open(chunk_path, "w", encoding="utf-8") as f:
                f.write(chunk_text)

            # Генерируем нативное Base64-зеркало подписки для старых клиентов
            b64_encoded = base64.b64encode(chunk_text.encode('utf-8')).decode('utf-8')
            b64_path = os.path.join(out_dir, f"{cat_name}_part{chunk_num}_base64.txt")
            with open(b64_path, "w", encoding="utf-8") as f:
                f.write(b64_encoded)

# =====================================================================
# 6. ГЛАВНЫЙ АСИНХРОННЫЙ ОРКЕСТРАТОР СИСТЕМЫ
# =====================================================================
async def main():
    print("[1/5] Запуск универсального асинхронного VPN-поисковика...")
    raw_pool = set()
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in SOURCES_STATIC:
            tasks.append(fetch_source(session, url, is_tg=False))
        for tg_chan in SOURCES_TELEGRAM:
            tasks.append(fetch_source(session, tg_chan, is_tg=True))
            
        results = await asyncio.gather(*tasks)
        for _, nodes in results:
            raw_pool.update(nodes)

    print(f"[2/5] Собрано сырых прокси-строк: {len(raw_pool)}")
    
    seen_fingerprints = set()
    unique_sanitized_pool = []
    
    for raw_node in raw_pool:
        fp, clean_node = optimize_and_mask_node(raw_node)
        if fp and fp not in seen_fingerprints:
            seen_fingerprints.add(fp)
            unique_sanitized_pool.append(clean_node)

    print(f"[3/5] Чистый пул уникальных хостов: {len(unique_sanitized_pool)}. Инициализация чекера.")
    print("[4/5] Тестирование портов и GeoIP/CIDR разметка под РФ...")
    
    # Запуск асинхронного распределенного семафор-чекера
    semaphore = asyncio.Semaphore(CONFIG["MAX_CONCURRENT_TASKS"])
    check_tasks = [test_node_transport(semaphore, node) for node in unique_sanitized_pool]
    check_results = await asyncio.gather(*check_tasks)
    
    alive_nodes_map = {}
    for node, is_alive, tag in check_results:
        if is_alive:
            alive_nodes_map[node] = tag

    print(f"[5/5] Проверка завершена! Найдено {len(alive_nodes_map)} живых прокси.")
    print("Запуск пакетного роутинга и генерации Base64 подписок...")
    
    save_and_chunk_routing(alive_nodes_map)
    print(f"🎉 Процесс завершен! Файлы сохранены в папку: '{CONFIG['OUTPUT_DIR']}'")

if __name__ == '__main__':
    # Запуск асинхронного цикла без конфликтов платформ Windows/Linux
    asyncio.run(main())
