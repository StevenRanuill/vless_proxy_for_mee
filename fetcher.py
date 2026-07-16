import asyncio
import os
import re
import html
import base64
import json
import hashlib
import shutil
import aiohttp
from datetime import datetime, timedelta

# =====================================================================
# ЧАСТЬ 1: ГЛОБАЛЬНАЯ КОНФИГУРАЦИЯ И ПАРСЕР ПРОКСИ-СТРОК
# =====================================================================

CONFIG = {
    # Регулярное выражение для поиска различных протоколов
    "PROXY_REGEX": r"(?:vless|vmess|ss|trojan|hysteria2|tuic)://[^\s\"']+",
    
    # Режим отладки для детального вывода в консоль GitHub Actions
    "DEBUG_MODE": True,
    
    "MAX_CONCURRENT_FETCH": 15,        # Ограничение параллельного скачивания
    "MAX_CONCURRENT_LIGHT_CHECK": 60,  # Скорость экспресс-скрининга портов
    "TIMEOUT_LIGHT_CHECK": 2.0,        # Быстрый таймаут для отсева мертвых нод
    "MAX_FILE_SIZE": 52428800,         # Защитный лимит в 50 МБ на файл подписки
    "CHUNK_SIZE": 1000,                # Размер нарезки чанков
    "CHUNKS_DIR": "raw_chunks", 
    "HISTORY_FILE": "core/history_blacklist.json",
    "RETAIN_DAYS": 7,                  # Ротация истории (7 дней)
    "FILE_STAGE_1": "logs/01_raw_all_downloaded.txt",
    "FILE_STAGE_2": "logs/02_raw_unique_deduplicated.txt",
    "FILE_STAGE_3": "logs/all_gathered_raw.txt"
}

# Отладочные счетчики сетевого состояния для дашборда
LIGHT_STATS = {
    "scanned": 0,
    "tcp_timeout": 0,
    "tcp_refused": 0,
    "tls_empty_bad": 0,
    "tspu_drop": 0,
    "passed": 0
}

# Вставьте сюда ваши источники подписок (Plain Text / Base64 ссылки)
ELITE_SUBSCRIPTIONS = [
    "https://githubusercontent.com",
    "https://githubusercontent.com",
    "https://githubusercontent.com"
]

def log_debug(message):
    """Вывод отладочных сообщений с принудительным сбросом буфера."""
    if CONFIG["DEBUG_MODE"]:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[ ДЕБАГ ФЕТЧЕРА {timestamp}] {message}", flush=True)

def parse_proxy_node(node_str):
    """Низкоуровневый разбор URI на Host и Port для TCP пинга."""
    try:
        if "://" not in node_str: return None, None
        _, body = node_str.split("://", 1)
        if "#" in body: body, _ = body.split("#", 1)
        if "?" in body: body, _ = body.split("?", 1)
        if "@" in body: _, server_part = body.split("@", 1)
        else: server_part = body
        
        if server_part.startswith("["):
            if "]" in server_part:
                host_part, port_part = server_part.split("]", 1)
                host = host_part + "]"
                port = port_part.replace(":", "") if ":" in port_part else "443"
            else: return None, None
        else:
            if ":" in server_part: host, port = server_part.split(":", 1)
            else: host, port = server_part, "443"
            
        return host.strip().lower(), int(port) if port else 443
    except: 
        return None, None
# =====================================================================
# ЧАСТЬ 2: АСИНХРОННЫЙ TCP-СКРИНИНГ И ДЕКОДЕР BASE64
# =====================================================================

async def light_ping_node(semaphore, node):
    """Быстрый экспресс-скрининг в облаке: проверка доступности TCP-порта ноды."""
    async with semaphore:
        LIGHT_STATS["scanned"] += 1
        host, port = parse_proxy_node(node)
        if not host: 
            LIGHT_STATS["tls_empty_bad"] += 1
            return None
        
        clean_host = host.strip("[]") if host.startswith("[") else host
        try:
            # Открываем чистое TCP соединение для проверки доступности порта
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(clean_host, port), 
                timeout=CONFIG["TIMEOUT_LIGHT_CHECK"]
            )
            writer.close()
            try: await writer.wait_closed()
            except: pass
            
            LIGHT_STATS["passed"] += 1
            return node
        except asyncio.TimeoutError:
            LIGHT_STATS["tcp_timeout"] += 1
            return None
        except ConnectionRefusedError:
            LIGHT_STATS["tcp_refused"] += 1
            return None
        except Exception:
            LIGHT_STATS["tspu_drop"] += 1
            return None

def normalize_github_url(url):
    """Приведение ссылок GitHub к raw-виду для прямого скачивания."""
    url = url.strip()
    if "github.com" in url and "/raw/" in url: 
        url = url.replace("github.com", "githubusercontent.com").replace("/raw/", "/")
    elif "github.com" in url and "/blob/" in url: 
        url = url.replace("github.com", "githubusercontent.com").replace("/blob/", "/")
    return url

def clean_and_extract(raw_text, url_source=""):
    """Очистка текста и автоматическое декодирование Base64 подписок."""
    unescaped = html.unescape(raw_text)
    if "://" not in unescaped[:200]: 
        try:
            b64_clean = "".join(unescaped.split())
            b64_clean = re.sub(r'[^A-Za-z0-9+/=]', '', b64_clean)
            b64_clean += "=" * ((4 - len(b64_clean) % 4) % 4)
            decoded = base64.b64decode(b64_clean).decode('utf-8', errors='ignore')
            if "://" in decoded: unescaped = decoded
        except: pass
        
    sanitized = []
    raw_lines = re.split(r'[\s"\'\(\)\{\}\[\]\t\r\n]+', unescaped)
    valid_protocols = ('vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'tuic://', 'shadowsocks://')
    
    for line in raw_lines:
        line_clean = line.strip()
        if line_clean.startswith(valid_protocols):
            if line_clean.startswith("shadowsocks://"): 
                line_clean = line_clean.replace("shadowsocks://", "ss://", 1)
            sanitized.append(line_clean)
            
    log_debug(f"Скачано из {url_source}: {len(sanitized)} строк.")
    return sanitized

async def fetch_source(semaphore, session, url):
    """Асинхронный загрузчик контента из удаленного источника."""
    async with semaphore:
        norm_url = normalize_github_url(url)
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            async with session.get(norm_url, headers=headers, timeout=15) as response:
                if response.status == 200:
                    text_content = await response.text(errors='ignore')
                    if len(text_content) > CONFIG["MAX_FILE_SIZE"]: return []
                    return clean_and_extract(text_content, norm_url)
        except: pass
        return []
# =====================================================================
# ЧАСТЬ 3: ОПТИМИЗАЦИЯ ИСТОРИИ, ДАШБОРД И НАРЕЗКА ЧАНКОВ
# =====================================================================

def optimize_node(proxy_link):
    """Генерирует стабильный фингерпринт и нормализует имя ноды."""
    try:
        node_str = proxy_link.strip().replace('&amp;', '&')
        if "://" not in node_str: return None, None
        scheme, body = node_str.split("://", 1)
        if "#" in body: body_clear, _ = body.split("#", 1)
        else: body_clear = body
        temp_body = body_clear
        if "?" in temp_body: temp_body, _ = temp_body.split("?", 1)
        if "@" in temp_body: _, server_part = temp_body.split("@", 1)
        else: server_part = temp_body
        
        if server_part.startswith("["):
            if "]" in server_part:
                host_part, port_part = server_part.split("]", 1)
                host = host_part + "]"
                port = port_part.replace(":", "") if ":" in port_part else "443"
            else: return None, None
        else:
            if ":" in server_part: host, port = server_part.split(":", 1)
            else: host, port = server_part, "443"
            
        port = "".join(filter(str.isdigit, port))
        port = port if port else "443"
        host = host.strip().lower()
        if not host: return None, None
        
        fingerprint = f"{host}:{port}"
        node_hash = hashlib.md5(host.encode()).hexdigest()[:8]
        return fingerprint, f"{scheme}://{body_clear}#NODE-{node_hash}"
    except: 
        return None, None

def load_and_clean_history():
    """Загрузка истории в облаке и полная очистка записей старше 7 дней."""
    if not os.path.exists(CONFIG["HISTORY_FILE"]): return {}
    try:
        with open(CONFIG["HISTORY_FILE"], "r", encoding="utf-8") as f: 
            history = json.load(f)
        now = datetime.now()
        clean_history = {}
        cutoff_date = now - timedelta(days=CONFIG["RETAIN_DAYS"])
        removed_count = 0
        
        for fp_hash, data in history.items():
            last_check_str = data["last_success"] if isinstance(data, dict) else data
            try:
                if datetime.strptime(last_check_str, "%Y-%m-%d") > cutoff_date:
                    clean_history[fp_hash] = {
                        "last_success": last_check_str,
                        "first_seen": data.get("first_seen", last_check_str) if isinstance(data, dict) else last_check_str
                    }
                else: removed_count += 1
            except: removed_count += 1
            
        log_debug(f"История загружена. Активных меток: {len(clean_history)}. Удалено по 7-дневной ротации: {removed_count}")
        return clean_history
    except: return {}

def save_history(history_db):
    """Сохранение базы истории на диск."""
    try:
        os.makedirs(os.path.dirname(CONFIG["HISTORY_FILE"]), exist_ok=True)
        with open(CONFIG["HISTORY_FILE"], "w", encoding="utf-8") as f: 
            json.dump(history_db, f, ensure_ascii=False, indent=2)
    except: pass

async def async_main():
    """Главный управляющий метод фетчера."""
    if not ELITE_SUBSCRIPTIONS: 
        print("[КРИТИЧЕСКАЯ ОШИБКА] Массив ELITE_SUBSCRIPTIONS пуст!", flush=True)
        return
        
    history_db = load_and_clean_history()
    stage_1_list = []
    
    print(f"[СТАРТ] Скачивание баз. Источников в списке: {len(ELITE_SUBSCRIPTIONS)}", flush=True)
    semaphore = asyncio.Semaphore(CONFIG["MAX_CONCURRENT_FETCH"])
    
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_source(semaphore, session, url) for url in ELITE_SUBSCRIPTIONS]
        results = await asyncio.gather(*tasks)
        for nodes in results: stage_1_list.extend(nodes)
        
    os.makedirs("logs", exist_ok=True)
    with open(CONFIG["FILE_STAGE_1"], "w", encoding="utf-8") as f: 
        f.write("\n".join(stage_1_list))
        
    seen_fps = set()
    stage_2_list = []
    pre_filtered_pool = []
    current_date_str = datetime.now().strftime("%Y-%m-%d")
    dup_count = 0
    
    for node in stage_1_list:
        fp, clean_node = optimize_node(node)
        if fp:
            if fp not in seen_fps:
                seen_fps.add(fp)
                stage_2_list.append(clean_node)
                pre_filtered_pool.append(clean_node)
            else: dup_count += 1
            
    with open(CONFIG["FILE_STAGE_2"], "w", encoding="utf-8") as f: 
        f.write("\n".join(stage_2_list))
    log_debug(f"Удалено дубликатов на Шаге 2: {dup_count} шт.")
    
    print(f" [ОБЛАКО] Запуск легкого экспресс-теста для {len(pre_filtered_pool)} уникальных нод...", flush=True)
    
    check_semaphore = asyncio.Semaphore(CONFIG["MAX_CONCURRENT_LIGHT_CHECK"])
    check_tasks = [light_ping_node(check_semaphore, node) for node in pre_filtered_pool]
    check_results = await asyncio.gather(*check_tasks)
    final_pool = [node for node in check_results if node is not None]
    
    # Синхронизация и дозапись истории по стандарту 7 дней
    for node in final_pool:
        fp, _ = optimize_node(node)
        if fp:
            fp_hash = hashlib.md5(fp.encode()).hexdigest()
            if fp_hash in history_db:
                if isinstance(history_db[fp_hash], dict): 
                    history_db[fp_hash]["last_success"] = current_date_str
                else: 
                    history_db[fp_hash] = {"last_success": current_date_str, "first_seen": history_db[fp_hash]}
            else: 
                history_db[fp_hash] = {"last_success": current_date_str, "first_seen": current_date_str}
                
    save_history(history_db)
    with open(CONFIG["FILE_STAGE_3"], "w", encoding="utf-8") as f: 
        f.write("\n".join(final_pool))
        
    # ИТОГОВЫЙ РАСШИРЕННЫЙ ДЕБАГ-ДАШБОРД В КОНСОЛЬ БИЛДА GITHUB ACTIONS
    print("\n" + "="*60)
    print(" ИТОГОВЫЙ ОТЧЕТ ОБЛАЧНОГО СКРИНИНГА ПОРТОВ:")
    print(f" Скачано сырых строк всего: {len(stage_1_list)}")
    print(f" ❌Удалено строк-дубликатов: {dup_count}")
    print(f" Всего отправлено на экспресс-тест: {LIGHT_STATS['scanned']}")
    print("-"*60)
    print(f" Падение по таймауту TCP порта: {LIGHT_STATS['tcp_timeout']}")
    print(f" Отклонено сервером (Connection Refused): {LIGHT_STATS['tcp_refused']}")
    print(f" Сетевой дроп / Неизвестные сбои: {LIGHT_STATS['tspu_drop']}")
    print(f" Битый формат / Невалидные прокси: {LIGHT_STATS['tls_empty_bad']}")
    print("-"*60)
    print(f" Успешно прошли скрининг (Передано на ПК): {LIGHT_STATS['passed']}")
    print("="*60 + "\n", flush=True)
    
    # Принудительно чистим старые чанки перед генерацией новых
    if os.path.exists(CONFIG["CHUNKS_DIR"]):
        try: shutil.rmtree(CONFIG["CHUNKS_DIR"])
        except: pass
    os.makedirs(CONFIG["CHUNKS_DIR"], exist_ok=True)
    
    if not final_pool:
        log_debug("Пул проверки пуст. Создаем пустой маркер-чанк.")
        with open(os.path.join(CONFIG["CHUNKS_DIR"], "chunk_empty.txt"), "w", encoding="utf-8") as f: 
            f.write("")
    else:
        chunk_size = CONFIG["CHUNK_SIZE"]
        chunks = [final_pool[i:i + chunk_size] for i in range(0, len(final_pool), chunk_size)]
        log_debug(f"Нарезка пула завершена. Всего создано чанков: {len(chunks)}")
        for idx, chunk in enumerate(chunks, 1):
            with open(os.path.join(CONFIG["CHUNKS_DIR"], f"chunk_{idx:03d}.txt"), "w", encoding="utf-8") as f: 
                f.write("\n".join(chunk))

if __name__ == "__main__":
    asyncio.run(async_main())
