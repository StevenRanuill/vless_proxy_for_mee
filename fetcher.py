import asyncio
import os
import re
import html
import base64
import json
import hashlib
import shutil
import aiohttp
from datetime import datetime, timedelta  # ИСПРАВЛЕНО: Добавлен timedelta

# Заглушка конфигурации (подставьте ваши реальные значения)
CONFIG = {
    "DEBUG_MODE": True,
    # ИСПРАВЛЕНО: Добавлено ?:, чтобы re.findall возвращал ВСЮ строку прокси целиком, а не только имя протокола
    "PROXY_REGEX": r"(?:vless|vmess|ss|trojan|hysteria2|tuic)://[^\s\"']+",
    
    # Лимиты и нарезка
    "MAX_CONCURRENT_FETCH": 15,           
    "MAX_FILE_SIZE": 52428800,  # 50 MB (с запасом для любых подписок)       
    "CHUNK_SIZE": 1000,                   
    "CHUNKS_DIR": "raw_chunks",           
    
    # Ротация истории (мягкий фильтр)
    "HISTORY_FILE": "core/history_blacklist.json",
    "RETAIN_DAYS": 3,                     
    
    # Логи стадий сборки
    "FILE_STAGE_1": "logs/01_raw_all_downloaded.txt",
    "FILE_STAGE_2": "logs/02_raw_unique_deduplicated.txt",
    "FILE_STAGE_3": "logs/all_gathered_raw.txt"
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

def log_debug(message):
    """Вывод отладочных сообщений, если включен DEBUG_MODE."""
    if CONFIG["DEBUG_MODE"]:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[⚙️ ДЕБАГ {timestamp}] {message}")

def normalize_github_url(url):
    url = url.strip()
    if "github.com" in url and "/raw/" in url:
        url = url.replace("github.com", "githubusercontent.com").replace("/raw/", "/")
    elif "github.com" in url and "/blob/" in url:
        url = url.replace("github.com", "githubusercontent.com").replace("/blob/", "/")
    return url

def clean_and_extract(raw_text, url_source=""):
    unescaped = html.unescape(raw_text)
    
    if "://" not in unescaped[:200]:  
        try:
            b64_clean = "".join(unescaped.split())
            b64_clean = re.sub(r'[^A-Za-z0-9+/=]', '', b64_clean)
            b64_clean += "=" * ((4 - len(b64_clean) % 4) % 4)
            decoded = base64.b64decode(b64_clean).decode('utf-8', errors='ignore')
            if "://" in decoded:
                unescaped = decoded
        except:
            pass

    sanitized = []
    raw_lines = re.split(r'[\s"\'\(\)\{\}\[\]\t\r\n]+', unescaped)
    valid_protocols = ('vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://', 'tuic://', 'shadowsocks://')

    for line in raw_lines:
        line_clean = line.strip()
        if line_clean.startswith(valid_protocols):
            if line_clean.startswith("shadowsocks://"):
                line_clean = line_clean.replace("shadowsocks://", "ss://", 1)
            sanitized.append(line_clean)
            
    log_debug(f"Извлечено из источника {url_source}: {len(sanitized)} нод.")
    return sanitized

async def fetch_source(semaphore, session, url):
    async with semaphore:
        norm_url = normalize_github_url(url)
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            async with session.get(norm_url, headers=headers, timeout=15) as response:
                if response.status == 200:
                    text_content = await response.text(errors='ignore')
                    if len(text_content) > CONFIG["MAX_FILE_SIZE"]:
                        print(f"[ОШИБКА] Файл {norm_url} превысил лимит размера.")
                        return []
                    return clean_and_extract(text_content, norm_url)
                else:
                    print(f"[ОШИБКА СЕТИ] {norm_url} вернул статус {response.status}")
        except Exception as e:
            print(f"[СБОЙ СОЕДИНЕНИЯ] Не удалось подключиться к {norm_url}: {e}")
        return []

def optimize_node(proxy_link):
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
        cleaned_node = f"{scheme}://{body_clear}#NODE-{node_hash}"
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
        
        initial_count = len(history)
        for fp_hash, date_str in history.items():
            try:
                if datetime.strptime(date_str, "%Y-%m-%d") > cutoff_date: 
                    clean_history[fp_hash] = date_str
            except: pass
            
        removed = initial_count - len(clean_history)
        log_debug(f"Загружена история. Всего меток: {initial_count}. Удалено по ротации (> {CONFIG['RETAIN_DAYS']} дн.): {removed}")
        return clean_history
    except: 
        print("[ОШИБКА] Не удалось прочитать файл истории блеклиста.")
        return {}

def save_history(history_db):
    try:
        os.makedirs(os.path.dirname(CONFIG["HISTORY_FILE"]), exist_ok=True)
        with open(CONFIG["HISTORY_FILE"], "w", encoding="utf-8") as f:
            json.dump(history_db, f, ensure_ascii=False, indent=2)
    except: pass

async def async_main():
    if not ELITE_SUBSCRIPTIONS:
        print("[КРИТИЧЕСКАЯ ОШИБКА] Массив ELITE_SUBSCRIPTIONS пуст!")
        return

    history_db = load_and_clean_history()
    stage_1_list = []
    
    print(f"[СТАРТ] Опрос источников. Всего в списке: {len(ELITE_SUBSCRIPTIONS)}")
    semaphore = asyncio.Semaphore(CONFIG["MAX_CONCURRENT_FETCH"])
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_source(semaphore, session, url) for url in ELITE_SUBSCRIPTIONS]
        results = await asyncio.gather(*tasks)
        for nodes in results:
            stage_1_list.extend(nodes)
            
    os.makedirs("logs", exist_ok=True)
    with open(CONFIG["FILE_STAGE_1"], "w", encoding="utf-8") as f: f.write("\n".join(stage_1_list))
    
    # МЕТРИКИ ШАГА 1
    total_downloaded = len(stage_1_list)
    print(f"📊 [ШАГ 1] Всего сырых записей скачано: {total_downloaded}")
            
    seen_fps = set()
    stage_2_list = []
    final_pool = []
    current_date_str = datetime.now().strftime("%Y-%m-%d")
    
    # Счетчики для отладки фильтрации
    dup_filtered = 0
    history_filtered = 0
    invalid_filtered = 0
    
    for node in stage_1_list:
        fp, clean_node = optimize_node(node)
        if not fp:
            invalid_filtered += 1
            continue
            
        if fp in seen_fps:
            dup_filtered += 1
            continue
            
        seen_fps.add(fp)
        stage_2_list.append(clean_node)
        
        fp_hash = hashlib.md5(fp.encode()).hexdigest()
        
        # Проверка по блеклисту истории (чекались ли сегодня)
        if fp_hash in history_db and history_db[fp_hash] == current_date_str:
            history_filtered += 1
        else:
            final_pool.append(clean_node)
            history_db[fp_hash] = current_date_str
                
    save_history(history_db)
                
    with open(CONFIG["FILE_STAGE_2"], "w", encoding="utf-8") as f: f.write("\n".join(stage_2_list))
    with open(CONFIG["FILE_STAGE_3"], "w", encoding="utf-8") as f: f.write("\n".join(final_pool))
    
    # ИТОГОВЫЙ ОТЧЕТ СТАТИСТИКИ ФИЛЬТРАЦИИ ДЛЯ БИЛДА
    print("\n" + "="*50)
    print("📈 ИТОГОВЫЙ ОТЧЕТ ИНКРЕМЕНТАЛЬНОЙ ФИЛЬТРАЦИИ:")
    print(f"  📥 Всего получено строк (Шаг 1):        {total_downloaded}")
    print(f"  ❌ Отфильтровано битых/невалидных ссылок: {invalid_filtered}")
    print(f"  ❌ Отфильтровано дубликатов (Шаг 2):     {dup_filtered}")
    print(f"  ❌ Отфильтровано историей (уже чекались сегодня): {history_filtered}")
    print(f"  🚀 Итого отправлено в пул проверки (Шаг 3): {len(final_pool)}")
    print("="*50 + "\n")
            
    if os.path.exists(CONFIG["CHUNKS_DIR"]): 
        try: shutil.rmtree(CONFIG["CHUNKS_DIR"])
        except: pass
    os.makedirs(CONFIG["CHUNKS_DIR"], exist_ok=True)
    
    if not final_pool:
        log_debug("Пул проверки пуст. Создаем пустой маркер-чанк.")
        with open(os.path.join(CONFIG["CHUNKS_DIR"], "chunk_empty.txt"), "w", encoding="utf-8") as f:
            f.write("")
    else:
        # Корректная нарезка пула на чанки по CHUNK_SIZE строк
        chunk_size = CONFIG["CHUNK_SIZE"]
        chunks = [final_pool[i:i + chunk_size] for i in range(0, len(final_pool), chunk_size)]
        log_debug(f"Нарезка пула. Всего будет создано чанков: {len(chunks)}")
        
        for idx, chunk in enumerate(chunks, 1):
            chunk_file = os.path.join(CONFIG["CHUNKS_DIR"], f"chunk_{idx:03d}.txt")
            with open(chunk_file, "w", encoding="utf-8") as f:
                f.write("\n".join(chunk))
        log_debug("Все чанки успешно нарезаны и сохранены.")

 if __name__ == '__main__':
    asyncio.run(async_main())
