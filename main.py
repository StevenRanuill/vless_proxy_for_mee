import urllib.request
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_server(key):
    """Проверяет один ключ и возвращает его, если сервер доступен"""
    try:
        # Извлекаем часть после @ и убираем параметры после ?
        parts = key.split('@')
        if len(parts) < 2:
            return None
        
        server_part = parts[1].split('?')[0]
        # Если есть порт, разделяем на IP и порт
        if ':' in server_part:
            ip, port = server_part.split(':')
            # Пробуем быстро подключиться по TCP (таймаут 1.5 секунды)
            with socket.create_connection((ip, int(port)), timeout=1.5):
                return key
    except:
        pass
    return None

def parse_and_check_configs():
    with open('urls.json', 'r') as f:
        sources = json.load(f)
    
    unique_keys = set()
    alive_keys = []
    
    # 1. Сбор сырых ключей
    for url in sources:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8', errors='ignore')
                found = re.findall(r'(vless://[^\s]+|ss://[^\s]+|trojan://[^\s]+)', content)
                for key in found:
                    unique_keys.add(key.strip())
        except Exception as e:
            print(f"Ошибка чтения {url}: {e}")

    print(f"Всего собрано уникальных ключей: {len(unique_keys)}")
    print("Запуск быстрой многопоточной проверки...")

    # 2. Параллельная проверка в 100 потоков
    with ThreadPoolExecutor(max_workers=100) as executor:
        # Отправляем все ключи на проверку одновременно
        futures = {executor.submit(check_server, key): key for key in unique_keys}
        for futures_task in as_completed(futures):
            result = futures_task.result()
            if result:
                alive_keys.append(result)

    # 3. Сохранение результатов
    with open('my_sub.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(alive_keys))
        
    print(f"Проверка успешно завершена! Сохранено живых серверов: {len(alive_keys)} из {len(unique_keys)}")

if __name__ == '__main__':
    parse_and_check_configs()
