import psutil
import time
from datetime import datetime
import os
import json
from colorama import Fore, Style, init

# Initialisation de colorama pour la coloration dans le terminal
init(autoreset=True)

# Chargement de la configuration depuis config.json
def load_config():
    try:
        with open("config.json", "r") as f:
            config = json.load(f)
            return config.get("log", False)
    except FileNotFoundError:
        print(f"{Fore.RED}Error: config.json not found. Using default settings.")
        return False
    except json.JSONDecodeError:
        print(f"{Fore.RED}Error: Invalid JSON format in config.json. Using default settings.")
        return False

LOG_FILE = "logs.txt"
LOGGING_ENABLED = load_config()

os.system("title System Watchdog (idle)")
print(f'''{Fore.LIGHTBLUE_EX}
  ___         _              __      __    _      _       _           
 / __|_  _ __| |_ ___ _ __   \ \    / /_ _| |_ __| |_  __| |___  __ _ 
 \__ \ || (_-<  _/ -_) '  \   \ \/\/ / _` |  _/ _| ' \/ _` / _ \/ _` |
 |___/\_, /__/\__\___|_|_|_|   \_/\_/\__,_|\__\__|_||_\__,_\___/\__, |
      |__/                                                      |___/ 

======================================================================

{Fore.WHITE}// DEVELOPED BY {Fore.LIGHTYELLOW_EX}NOTLOANN
{Fore.WHITE}// CURRENT VERSION: {Fore.LIGHTYELLOW_EX}2.0

{Fore.WHITE}// LOGS: {Fore.LIGHTYELLOW_EX}{'TRUE' if LOGGING_ENABLED else 'FALSE'}
''')

print(f"{Style.DIM}Press any key to start.\nPress CTRL+C to stop.\n\n")
os.system("pause > nul")

os.system("title System Watchdog (active)")

seen_files_by_name = {}
seen_conns_by_name = {}

WINDOWS_SYSTEM_PATHS = ['C:\\Windows', 'C:\\Program Files', 'C:\\Users']

def is_windows_process(path):
    if path is None:
        return False
    path = path.lower()
    return path.startswith("c:\\windows")

def get_process_info(proc):
    try:
        name = proc.name()
        pid = proc.pid
        exe = proc.exe()
        return name, pid, exe
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None, None, None

def log_to_file(message):
    """
    Enregistre les messages dans un fichier de log avec l'encodage UTF-8.
    """
    if LOGGING_ENABLED:
        with open(LOG_FILE, "a", encoding="utf-8") as log_file:
            log_file.write(f"{message}\n")

def monitor_processes():
    print(f"{Fore.GREEN}🔍 Checking...\n")

    while True:
        for proc in psutil.process_iter(['pid']):
            try:
                name, pid, exe = get_process_info(proc)
                if name is None:
                    continue

                # Récupérer la date en gris/blanc
                date_str = f"{Fore.WHITE}[{datetime.now().strftime('%H:%M:%S')}]"

                # Vérification des accès aux fichiers
                try:
                    for f in proc.open_files():
                        message = f"{date_str} {Fore.YELLOW}📁 {name} has opened {f.path}"
                        print(message)
                        log_to_file(message)  # Log le message si l'option est activée
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Vérification des connexions réseau
                try:
                    for conn in proc.connections(kind='inet'):
                        if conn.status != psutil.CONN_NONE and conn.raddr:
                            ip, port = conn.raddr
                            message = f"{date_str} {Fore.CYAN}🌐 {name} connected to {ip}:{port}"
                            print(message)
                            log_to_file(message)  # Log le message si l'option est activée
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Vérification des accès aux périphériques (caméra, microphone)
                try:
                    for f in proc.open_files():
                        if 'camera' in f.path.lower() or 'mic' in f.path.lower():
                            message = f"{date_str} {Fore.RED}🎥 {name} has accessed a camera or mic: {f.path}"
                            print(message)
                            log_to_file(message)  # Log le message si l'option est activée
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(1)

if __name__ == "__main__":
    try:
        monitor_processes()
    except KeyboardInterrupt:
        os.system("title System Watchdog (stopped)")
        print(f"\n\n{Fore.LIGHTRED_EX}🛑 Stopped check.{Style.RESET_ALL}")
        print(f"\nCommands: {Style.DIM}restart/exit")
        choice = input(f"{Fore.LIGHTYELLOW_EX}==> ")
        if choice == "restart":
            os.system("cls")
            os.system("python main.py")
        if choice == "exit":
            print(f"\n{Fore.LIGHTCYAN_EX}See ya!")
            time.sleep(1)
            exit()
