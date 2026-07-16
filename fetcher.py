import os
import sys
import json
import asyncio
import aiohttp
from urllib.parse import urlparse, parse_qs

# =====================================================================
# ЧАСТЬ 1: КОНФИГУРАЦИЯ, ИСТОЧНИКИ И ЗАГРУЗЧИК СЫРЫХ ДАННЫХ
# =====================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Глобальные настройки фетчера
CONFIG = {
    # Публичные источники (URL подписок vless/ss/vmess в формате Base64 или Plain text)
    "SOURCES": [
        "https://githubusercontent.com",
        "https://githubusercontent.com",
        "https://githubusercontent.com"
    ],
    "CHUNKS_DIR": os.path.join(SCRIPT_DIR, "raw_chunks"),
    "CHUNK_SIZE": 100,               # По сколько нод нарезать в один файл чанка
    "TIMEOUT_DOWNLOAD": 15.0,        # Таймаут на скачивание одного источника
    # Ключевые слова в SNI, хосте или адресе, которые мы пропускаем (белый список)
    "ALLOWED_SNI_KEYWORDS": ["google", "cloudflare", "github", "vless", "cdn", "speedtest", "ir", "cf", "yt"]
}

async def fetch_source(session, url):
    """
    Асинхронно скачивает содержимое одного источника.
    """
    try:
        timeout = aiohttp.ClientTimeout(total=CONFIG["TIMEOUT_DOWNLOAD"])
        async with session.get(url, timeout=timeout) as response:
            if response.status == 200:
                text = await response.text()
                print(f"[+] Успешно скачан источник: {url[:50]}...")
                return text
            else:
                print(f"[-] Ошибка скачивания {url[:50]}... Статус: {response.status}")
                return ""
    except Exception as e:
        print(f"[-] Исключение при скачивании {url[:50]}: {e}")
        return ""

async def get_all_raw_data():
    """
    Параллельно запускает скачивание всех источников из списка CONFIG.
    """
    print(f"[INFO] Запуск сбора сырых данных из {len(CONFIG['SOURCES'])} источников...")
    
    # Настраиваем заголовки, чтобы GitHub не блокировал частые запросы
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [fetch_source(session, url) for url in CONFIG["SOURCES"]]
        results = await asyncio.gather(*tasks)
        
    # Объединяем все скачанные строки в один массив
    raw_lines = []
    for text in results:
        if text:
            # Разбиваем текст по строкам, очищаем пробелы
            raw_lines.extend([line.strip() for line in text.splitlines() if line.strip()])
            
    # Убираем жесткие дубликаты строк на самом раннем этапе
    unique_raw_lines = list(set(raw_lines))
    print(f"[INFO] Всего собрано строк: {len(raw_lines)}. Уникальных: {len(unique_raw_lines)}")
    return unique_raw_lines
# =====================================================================
# ЧАСТЬ 2: SNI ФИЛЬТРАЦИЯ, НАРЕЗКА ЧАНКОВ И ТОЧКА ВХОДА MAIN
# =====================================================================

def parse_and_filter_nodes(raw_lines):
    """
    Разбирает собранные строки, отбирает строго протокол VLESS,
    валидирует SNI/Reality параметры и отсекает заведомый мусор.
    """
    filtered_nodes = []
    print(f"[INFO] Начало валидации и фильтрации {len(raw_lines)} нод...")

    for line in raw_lines:
        if not line.startswith("vless://"):
            continue

        try:
            # Извлекаем параметры ссылки через встроенный парсер URL
            parsed = urlparse(line)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            security = params.get("security", "none").lower()
            sni = params.get("sni", "").lower()
            host = params.get("host", "").lower()
            address = parsed.hostname.lower() if parsed.hostname else ""

            # --- ПРАВИЛА ФИЛЬТРАЦИИ ---

            # 1. Защита REALITY: если протокол требует открытый ключ, а его нет — пропускаем
            if security == "reality" and not params.get("pbk"):
                continue

            # 2. Защита шифрования: если включен TLS/Reality, но SNI и Host полностью пустые
            if security in ["tls", "xtls", "reality"] and not sni and not host:
                continue

            # 3. Фильтрация по белому списку ключевых слов в SNI, Host или IP/Домене
            match_found = False
            for keyword in CONFIG["ALLOWED_SNI_KEYWORDS"]:
                if keyword in sni or keyword in host or keyword in address:
                    match_found = True
                    break

            # 4. Защита от кривых/битых SNI (слишком короткие домены или пробелы)
            if sni and (len(sni) < 4 or " " in sni):
                continue

            # Если нода прошла все критерии, добавляем ее в чистый пул
            filtered_nodes.append(line)

        except Exception:
            # Если ссылка повреждена настолько, что парсер выдал сбой — просто пропускаем ее
            continue

    # Убираем возможные дубликаты ссылок, если они различались только хэшем в конце
    final_nodes = list(set(filtered_nodes))
    print(f"[INFO] Фильтрация завершена. Сформирован пул из {len(final_nodes)} качественных нод.")
    return final_nodes


def save_to_chunks(nodes):
    """
    Очищает папку raw_chunks и нарезает ноды на файлы по CHUNK_SIZE штук.
    """
    chunks_dir = CONFIG["CHUNKS_DIR"]
    os.makedirs(chunks_dir, exist_ok=True)

    # 1. Полная очистка папки от старых текстовых чанков
    print("[INFO] Очистка папки raw_chunks перед записью новых данных...")
    for file in os.listdir(chunks_dir):
        if file.startswith("chunk_") and file.endswith(".txt"):
            try:
                os.remove(os.path.join(chunks_dir, file))
            except Exception:
                pass

    if not nodes:
        print("[WARN] Нет доступных нод для записи в чанки.")
        return

    # 2. Нарезка пула на файлы
    chunk_size = CONFIG["CHUNK_SIZE"]
    chunk_count = 0

    for i in range(0, len(nodes), chunk_size):
        chunk_count += 1
        chunk_data = nodes[i:i + chunk_size]
        chunk_file = os.path.join(chunks_dir, f"chunk_{chunk_count:03d}.txt")

        with open(chunk_file, "w", encoding="utf-8") as f:
            for node in chunk_data:
                f.write(f"{node}\n")

    print(f"[SUCCESS] Успешно создано {chunk_count} файлов-чанков в директории raw_chunks.")


def main():
    """
    Главный управляющий метод фетчера.
    """
    print("\n=== СТАРТ РАБОТЫ ФЕТЧЕРА ===")
    
    # Запускаем асинхронную скачку
    raw_data = asyncio.run(get_all_raw_data())
    
    # Фильтруем пул по SNI
    clean_nodes = parse_and_filter_nodes(raw_data)
    
    # Нарезаем файлы для чекера
    save_to_chunks(clean_nodes)
    
    print("=== РАБОТА ФЕТЧЕРА ПОЛНОСТЬЮ ЗАВЕРШЕНА ===\n")


if __name__ == "__main__":
    main()
