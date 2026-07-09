import urllib.request
import json
import re
import socket
from urllib.parse import urlparse

def check_server(ip, port):
    """Проверяет, открыт ли порт на сервере (таймаут 2 секунды)"""
    try:
        # Пытаемся установить быстрое TCP-соединение
        with socket.create_connection((ip, int(port)), timeout=2.0):
            return True
    except:
        return False

def parse_and_check_configs():
    with open('urls.json', 'r') as f:
        sources = json.load(f)
    
    unique_keys = set()
    alive_keys = []
    
    # 1. Сбор всех ключей из источников
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

    print(f"Всего собрано сырых уникальных ключей: {len(unique_keys)}")
    print("Начинаем проверку доступности серверов...")

    # 2. Валидация каждого ключа по TCP порту
    for key in unique_keys:
        try:
            # Извлекаем IP/домен и порт из структуры ключа (после символа @)
            parts = key.split('@')
            if len(parts) < 2:
                continue
            
            server_part = parts[1].split('?')[0] # Получаем "ip:port"
            if ':' in server_part:
                ip, port = server_part.split(':')
                # Запускаем проверку порта
                if check_server(ip, port):
                    alive_keys.append(key)
        except Exception as e:
            continue

    # 3. Сохранение только живых серверов
    with open('my_sub.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(alive_keys))
        
    print(f"Проверка завершена! Сохранено живых серверов: {len(alive_keys)} из {len(unique_keys)}")

if __name__ == '__main__':
    parse_and_check_configs()
