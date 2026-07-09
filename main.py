import urllib.request
import json
import re
import base64

def parse_configs():
    # Читаем список наших источников
    with open('urls.json', 'r') as f:
        sources = json.load(f)
    
    unique_keys = set()
    
    for url in sources:
        try:
            # Скачиваем содержимое по ссылке
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read()
                
                # Если база зашифрована в Base64, пробуем её расшифровать
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                except:
                    decoded = content.decode('utf-8', errors='ignore')
                
                # Ищем регулярным выражением все строки протоколов
                found = re.findall(r'(vless://[^\s]+|ss://[^\s]+|trojan://[^\s]+)', decoded)
                for key in found:
                    # Очищаем от мусора в конце строки, если он есть
                    clean_key = key.strip().split('\\')[0]
                    unique_keys.add(clean_key)
        except Exception as e:
            print(f"Ошибка при скачивании {url}: {e}")

    # Сохраняем очищенный результат в обычный текстовый список
    with open('my_sub.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(list(unique_keys)))
        
    print(f"Парсинг успешно завершен! Собрано уникальных ключей: {len(unique_keys)}")

if __name__ == '__main__':
    parse_configs()
