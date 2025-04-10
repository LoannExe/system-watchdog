import psutil
import time
from datetime import datetime
import os

os.system("title System Watchdog")
print('''

  ___         _              __      __    _      _       _           
 / __|_  _ __| |_ ___ _ __   \ \    / /_ _| |_ __| |_  __| |___  __ _ 
 \__ \ || (_-<  _/ -_) '  \   \ \/\/ / _` |  _/ _| ' \/ _` / _ \/ _` |
 |___/\_, /__/\__\___|_|_|_|   \_/\_/\__,_|\__\__|_||_\__,_\___/\__, |
      |__/                                                      |___/ 

''')
print("Filters:\n\n🟦 FW = From Windows\n🟨 NFW = Not From Windows\n🚨 Suspicious file interaction/connections will be listed in logs.txt\n\nThis script is most likely used to detect rats.")
print("Press any key to start.\n\n")
os.system("pause > nul")

LOG_FILE = "logs.txt"

seen_files_by_name = {}
seen_conns_by_name = {}


SUSPECT_IPS = ['192.168.1.100', '10.0.0.2'] 

WINDOWS_SYSTEM_PATHS = ['C:\\Windows', 'C:\\Program Files', 'C:\\Users']

def is_windows_process(path):
    if path is None:
        return False
    path = path.lower()
    return path.startswith("c:\\windows")

def is_suspect_ip(ip):
    """
    Vérifie si l'IP appartient à une liste d'IP suspectes.
    """
    return ip in SUSPECT_IPS

def is_suspect_file(path):
    """
    Vérifie si le fichier est dans un répertoire sensible non-Windows.
    """
    path = path.lower()
    for wp in WINDOWS_SYSTEM_PATHS:
        if wp.lower() in path:
            return False  
    return True

def get_process_info(proc):
    try:
        name = proc.name()
        pid = proc.pid
        exe = proc.exe()
        system_flag = "🟦 FW" if is_windows_process(exe) else "🟨 NFW"
        return name, pid, exe, system_flag
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None, None, None, None

def log_to_file(message):
    """
    Enregistre les messages dans un fichier de log avec l'encodage UTF-8.
    """
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(f"{message}\n")

def monitor_processes():
    print("🔍 Checking...\n")

    while True:
        for proc in psutil.process_iter(['pid']):
            try:
                name, pid, exe, system_flag = get_process_info(proc)
                if name is None:
                    continue


                if name not in seen_files_by_name:
                    seen_files_by_name[name] = set()
                if name not in seen_conns_by_name:
                    seen_conns_by_name[name] = set()


                try:
                    for f in proc.open_files():
                        if f.path not in seen_files_by_name[name]:
                            seen_files_by_name[name].add(f.path)
                            if is_suspect_file(f.path):
                                message = f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 Suspect file access: {f.path} by {name} [{system_flag}]"
                                print(message)
                                log_to_file(message)
                            else:
                                message = f"[{datetime.now().strftime('%H:%M:%S')}] 📁 {name} has opened {f.path} [{system_flag}]"
                                print(message)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass


                try:
                    for conn in proc.connections(kind='inet'):
                        if conn.status != psutil.CONN_NONE and conn.raddr:
                            ip, port = conn.raddr
                            conn_key = f"{ip}:{port}"
                            if conn_key not in seen_conns_by_name[name]:
                                seen_conns_by_name[name].add(conn_key)
                                if is_suspect_ip(ip):
                                    message = f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 Suspect connection: {name} connected to suspicious IP {ip}:{port} [{system_flag}]"
                                    print(message)
                                    log_to_file(message)
                                else:
                                    message = f"[{datetime.now().strftime('%H:%M:%S')}] 🌐 {name} connected to {ip}:{port} [{system_flag}]"
                                    print(message)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(1)

if __name__ == "__main__":
    try:
        monitor_processes()
    except KeyboardInterrupt:
        print("\n🛑 Stopped check.")
