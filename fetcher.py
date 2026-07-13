print("[ИНИЦИАЛИЗАЦИЯ] Скрипт fetcher.py успешно запущен интерпретатором Python", flush=True)

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


CONFIG = {
    "PROXY_REGEX": r"(?:vless|vmess|ss|trojan|hysteria2|tuic)://[^\s\"']+",
    "DEBUG_MODE": True,
    "MAX_CONCURRENT_FETCH": 15,           
    "MAX_CONCURRENT_LIGHT_CHECK": 50,     # Высокая скорость для легкого скрининга в облаке
    "TIMEOUT_LIGHT_CHECK": 1.5,           # Очень быстрый таймаут для отсева мертвецов
    "MAX_FILE_SIZE": 52428800,            
    "CHUNK_SIZE": 1000,                   
    "CHUNKS_DIR": "raw_chunks",           
    "HISTORY_FILE": "core/history_blacklist.json",
    "RETAIN_DAYS": 3,                     
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
    if CONFIG["DEBUG_MODE"]:
        print(f"[⚙️ ДЕБАГ {datetime.now().strftime('%H:%M:%S')}] {message}", flush=True)

def parse_proxy_node(node_str):
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
    except: return None, None

def make_light_client_hello(sni_domain):
    sni_bytes = sni_domain.encode('utf-8')
    sni_len = len(sni_bytes)
    sni_extension = b'\x00\x00' + (sni_len + 5).to_bytes(2, 'big') + (sni_len + 3).to_bytes(2, 'big') + b'\x00' + sni_len.to_bytes(2, 'big') + sni_bytes
    cipher_suites = b'\x00\x04\x13\x01\x13\x02' 
    extensions = sni_extension + b'\x00\x0d\x00\x04\x00\x02\x04\x03'
    handshake_body = b'\x03\x03' + os.urandom(32) + b'\x00' + cipher_suites + b'\x01\x00' + len(extensions).to_bytes(2, 'big') + extensions
    handshake_packet = b'\x01' + len(handshake_body).to_bytes(3, 'big') + handshake_body
    return b'\x16\x03\x01' + len(handshake_packet).to_bytes(2, 'big') + handshake_packet

async def light_ping_node(semaphore, node):
    """Легкая облачная проверка: только коннект и фрагментированный пинг ядра Telegram."""
    async with semaphore:
        host, port = parse_proxy_node(node)
        if not host: return None
        clean_host = host.strip("[]") if host.startswith("[") else host
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(clean_host, port), timeout=CONFIG["TIMEOUT_LIGHT_CHECK"]
            )
            packet = make_light_client_hello("api.telegram.org")
            # Обход ТСПУ фрагментацией для облака гитхаба
            chunk_size = 3
            for i in range(0, len(packet), chunk_size):
                writer.write(packet[i:i+chunk_size])
                await writer.drain()
            response = await asyncio.wait_for(reader.read(1), timeout=CONFIG["TIMEOUT_LIGHT_CHECK"])
            writer.close()
            try: await writer.wait_closed()
            except: pass
            return node if response else None
        except: return None

# ... (Оставляем функции clean_and_extract, fetch_source, optimize_node, load_and_clean_history, save_history) ...
def normalize_github_url(url):
    url = url.strip()
    if "github.com" in url and "/raw/" in url: url = url.replace("github.com", "githubusercontent.com").replace("/raw/", "/")
    elif "github.com" in url and "/blob/" in url: url = url.replace("github.com", "githubusercontent.com").replace("/blob/", "/")
    return url

def clean_and_extract(raw_text, url_source=""):
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
            if line_clean.startswith("shadowsocks://"): line_clean = line_clean.replace("shadowsocks://", "ss://", 1)
            sanitized.append(line_clean)
    return sanitized

async def fetch_source(semaphore, session, url):
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
        port = "".join(filter(str.isdigit, port)); port = port if port else "443"; host = host.strip().lower()
        if not host: return None, None
        fingerprint = f"{host}:{port}"
        node_hash = hashlib.md5(host.encode()).hexdigest()[:8]
        return fingerprint, f"{scheme}://{body_clear}#NODE-{node_hash}"
    except: return None, None

def load_and_clean_history():
    """Загрузка истории в облаке и полная очистка записей старше 7 дней."""
    if not os.path.exists(CONFIG["HISTORY_FILE"]): return {}
    try:
        with open(CONFIG["HISTORY_FILE"], "r", encoding="utf-8") as f: 
            history = json.load(f)
        
        now = datetime.now()
        clean_history = {}
        cutoff_date = now - timedelta(days=7) # Жесткий лимит удаления: 7 дней
        removed_count = 0

        for fp_hash, data in history.items():
            # Поддерживаем и старый формат (строка даты), и новый формат (словарь)
            last_check_str = data["last_success"] if isinstance(data, dict) else data
            try:
                if datetime.strptime(last_check_str, "%Y-%m-%d") > cutoff_date:
                    clean_history[fp_hash] = {
                        "last_success": last_check_str,
                        "first_seen": data.get("first_seen", last_check_str) if isinstance(data, dict) else last_check_str
                    }
                else:
                    removed_count += 1
            except:
                removed_count += 1

        if CONFIG["DEBUG_MODE"]:
            print(f"[⚙️ ДЕБАГ] История загружена. Активных нод: {len(clean_history)}. Удалено записей без изменений (>7 дней): {removed_count}", flush=True)
        return clean_history
    except: 
        return {}


def save_history(history_db):
    try:
        os.makedirs(os.path.dirname(CONFIG["HISTORY_FILE"]), exist_ok=True)
        with open(CONFIG["HISTORY_FILE"], "w", encoding="utf-8") as f: json.dump(history_db, f, ensure_ascii=False, indent=2)
    except: pass

async def async_main():
    if not ELITE_SUBSCRIPTIONS: return
    history_db = load_and_clean_history()
    stage_1_list = []
    
    print(f"[СТАРТ] Скачивание баз...")
    semaphore = asyncio.Semaphore(CONFIG["MAX_CONCURRENT_FETCH"])
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_source(semaphore, session, url) for url in ELITE_SUBSCRIPTIONS]
        results = await asyncio.gather(*tasks)
        for nodes in results: stage_1_list.extend(nodes)
            
    os.makedirs("logs", exist_ok=True)
    with open(CONFIG["FILE_STAGE_1"], "w", encoding="utf-8") as f: f.write("\n".join(stage_1_list))
            
    seen_fps = set()
    stage_2_list = []
    pre_filtered_pool = []
    current_date_str = datetime.now().strftime("%Y-%m-%d")
    
    for node in stage_1_list:
        fp, clean_node = optimize_node(node)
        if fp and fp not in seen_fps:
            seen_fps.add(fp)
            stage_2_list.append(clean_node)
            fp_hash = hashlib.md5(fp.encode()).hexdigest()
            if fp_hash not in history_db or history_db[fp_hash] != current_date_str:
                pre_filtered_pool.append(clean_node)
                
    with open(CONFIG["FILE_STAGE_2"], "w", encoding="utf-8") as f: f.write("\n".join(stage_2_list))

    # 🔥 БЫСТРЫЙ ЛЕГКИЙ СКРИНИНГ В ОБЛАКЕ ГИТХАБА
    print(f"⚡ [ОБЛАКО] Запуск легкого экспресс-теста для {len(pre_filtered_pool)} уникальных нод...")
    check_semaphore = asyncio.Semaphore(CONFIG["MAX_CONCURRENT_LIGHT_CHECK"])
    check_tasks = [light_ping_node(check_semaphore, node) for node in pre_filtered_pool]
    check_results = await asyncio.gather(*check_tasks)
    
    final_pool = [node for node in check_results if node is not None]
    
    # Записываем в историю только те, что пустили дальше
    # 🔥 ОБНОВЛЕНИЕ И ДОЗАПИСЬ ИСТОРИИ (Только прошедшие легкий SNI-тест)
    for node in final_pool:
        fp, _ = optimize_node(node)
        if fp:
            fp_hash = hashlib.md5(fp.encode()).hexdigest()
            if fp_hash in history_db:
                # Нода уже была — обновляем дату последней успешной экспресс-проверки
                if isinstance(history_db[fp_hash], dict):
                    history_db[fp_hash]["last_success"] = current_date_str
                else:
                    # Корректно переводим старый формат строки в словарь
                    history_db[fp_hash] = {
                        "last_success": current_date_str,
                        "first_seen": history_db[fp_hash]
                    }
            else:
                # Абсолютно новая нода — создаем запись с двумя датами
                history_db[fp_hash] = {
                    "last_success": current_date_str,
                    "first_seen": current_date_str
                }
                
    # Сохраняем обновленную и очищенную базу истории
    save_history(history_db)

    with open(CONFIG["FILE_STAGE_3"], "w", encoding="utf-8") as f:
        f.write("\n".join(final_pool))
        
    print("\n" + "="*50)
    print("📈 ОТЧЕТ ЛЕГКОГО ОБЛАЧНОГО СКРИНИНГА:")
    print(f"  📥 Скачано всего строк:    {len(stage_1_list)}")
    print(f"  ❌ Мертвые/Дубли отсеяны:  {len(stage_1_list) - len(final_pool)}")
    print(f"  🚀 Передано на ПК нод:     {len(final_pool)}")
    print("="*50 + "\n")
            
    if os.path.exists(CONFIG["CHUNKS_DIR"]):
        try: shutil.rmtree(CONFIG["CHUNKS_DIR"])
        except: pass
    os.makedirs(CONFIG["CHUNKS_DIR"], exist_ok=True)
    
    if not final_pool:
        with open(os.path.join(CONFIG["CHUNKS_DIR"], "chunk_empty.txt"), "w", encoding="utf-8") as f:
            f.write("")
    else:
        chunk_size = CONFIG["CHUNK_SIZE"]
        chunks = [final_pool[i:i + chunk_size] for i in range(0, len(final_pool), chunk_size)]
        for idx, chunk in enumerate(chunks, 1):
            chunk_file = os.path.join(CONFIG["CHUNKS_DIR"], f"chunk_{idx:03d}.txt")
            with open(chunk_file, "w", encoding="utf-8") as f:
                f.write("\n".join(chunk))

if __name__ == "__main__":
    asyncio.run(async_main())

