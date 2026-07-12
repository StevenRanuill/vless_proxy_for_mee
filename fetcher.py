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

def fetch_and_clean_sub(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8', errors='ignore')
            # Если подписка прилетела в Base64 (часто бывает у агрегаторов), декодируем её
            if not content.startswith(('vless://', 'vmess://', 'ss://', 'trojan://')):
                try:
                    content = base64.b64decode(content).decode('utf-8', errors='ignore')
                except:
                    pass
            return re.findall(CONFIG["PROXY_REGEX"], content)
    except:
        return []

def main():
    print("1. Скачивание готовых проверенных подписок...")
    raw_pool = set()
    for url in ELITE_SUBSCRIPTIONS:
        found = fetch_and_clean_sub(url)
        raw_pool.update(found)
        print(f"-> Из источника получено {len(found)} нод.")
        
    print(f"2. Уникальных серверов после склейки: {len(raw_pool)}. Нарезка пачек...")
    
    if os.path.exists(CONFIG["CHUNKS_DIR"]):
        import shutil
        shutil.rmtree(CONFIG["CHUNKS_DIR"])
    os.makedirs(CONFIG["CHUNKS_DIR"], exist_ok=True)
    
    nodes_list = list(raw_pool)
    chunk_size = CONFIG["CHUNK_SIZE"]
    chunk_num = 0
    
    for i in range(0, len(nodes_list), chunk_size):
        chunk_num = (i // chunk_size) + 1
        with open(os.path.join(CONFIG["CHUNKS_DIR"], f"chunk_{chunk_num}.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(nodes_list[i:i + chunk_size]))
            
    print(f"🎉 Подготовлено {chunk_num} пачек для вашего ПК.")

if __name__ == '__main__':
    main()
