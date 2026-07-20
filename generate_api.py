import os
import sys
import shutil
import urllib.request
import zipfile
import subprocess

# Определяем пути относительно текущего скрипта
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "xray_api")
TEMP_ZIP = os.path.join(SCRIPT_DIR, "xray_core.zip")
TEMP_EXTRACT = os.path.join(SCRIPT_DIR, "Xray-core-main")


def download_and_extract_proto():

    
    print("2. Распаковка архива...")
    if os.path.exists(TEMP_EXTRACT):
        shutil.rmtree(TEMP_EXTRACT)
    with zipfile.ZipFile(TEMP_ZIP, 'r') as zip_ref:
        zip_ref.extractall(SCRIPT_DIR)


def compile_proto_files():
    print("3. Поиск и компиляция файлов Protobuf...")
    # Находим корневую папку с исходниками протобуф внутри распакованного архива
    proto_root = TEMP_EXTRACT
    
    # Собираем все .proto файлы
    proto_files = []
    for root, dirs, files in os.walk(proto_root):
        for file in files:
            if file.endswith(".proto"):
                # Нам нужен относительный путь от корня репозитория Xray
                rel_path = os.path.relpath(os.path.join(root, file), proto_root)
                proto_files.append(rel_path)

    if not proto_files:
        print("[Ошибка] Не найдено ни одного .proto файла!")
        return

    # Переключаемся в папку с прото-файлами для корректных относительных импортов
    os.chdir(proto_root)

    # Запускаем компилятор gRPC
    # Используем sys.executable, чтобы привязаться к текущему запущенному интерпретатору
    python_exe = sys.executable
    
    print(f"Компиляция {len(proto_files)} файлов...")
    for proto in proto_files:
        cmd = [
            python_exe, "-m", "grpc_tools.protoc",
            f"-I=.",
            f"--python_out={OUTPUT_DIR}",
            f"--grpc_python_out={OUTPUT_DIR}",
            proto
        ]
        # Создаем подпапки в целевой директории, чтобы компилятор не падал
        target_sub_dir = os.path.dirname(os.path.join(OUTPUT_DIR, proto))
        os.makedirs(target_sub_dir, exist_ok=True)
        
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

def fix_imports_and_init():
    print("4. Создание файлов инициализации __init__.py...")
    # Для того чтобы Python импортировал вложенные модули, везде должны быть __init__.py
    for root, dirs, files in os.walk(OUTPUT_DIR):
        init_file = os.path.join(root, "__init__.py")
        if not os.path.exists(init_file):
            with open(init_file, "w") as f:
                f.write("")

    print("5. Очистка временных файлов...")
    os.chdir(SCRIPT_DIR)
    if os.path.exists(TEMP_ZIP):
        os.remove(TEMP_ZIP)
    if os.path.exists(TEMP_EXTRACT):
        shutil.rmtree(TEMP_EXTRACT)
    print("[УСПЕХ] Папка xray_api успешно сгенерирована и готова к работе!")

if __name__ == "__main__":
    # Гарантируем, что целевая папка чистая
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    try:
        download_and_extract_proto()
        compile_proto_files()
        fix_imports_and_init()
    except Exception as e:
        print(f"[КРИТИЧЕСКАЯ ОШИБКА]: {e}")
