"""
Log Watcher - Surveillance automatique des logs avec alertes
"""
import os
import time
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

LOG_DIR = Path('logs')
LOG_FILE = LOG_DIR / 'server.log'
ERROR_PATTERNS = [
    'ERROR',
    'Exception',
    'Traceback',
    'NameError',
    'LDAPException',
    '500 Error',
    'Unhandled'
]

class LogWatcher(FileSystemEventHandler):
    def __init__(self):
        self.last_position = 0
        self.error_count = 0
        self.last_alert = 0
        self.alert_cooldown = 60  # Secondes entre les alertes
        
    def on_modified(self, event):
        if event.src_path == str(LOG_FILE):
            self.check_for_errors()
    
    def check_for_errors(self):
        try:
            with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                
                for line in new_lines:
                    if any(pattern in line for pattern in ERROR_PATTERNS):
                        self.error_count += 1
                        self.handle_error(line)
        except Exception as e:
            print(f"[LOG WATCHER] Error reading log: {e}")
    
    def handle_error(self, line):
        now = time.time()
        if now - self.last_alert > self.alert_cooldown:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"\n{'='*60}")
            print(f"🚨 ALERTE ERREUR - {timestamp}")
            print(f"{'='*60}")
            print(f"Erreur détectée: {line.strip()[:200]}")
            print(f"Total erreurs depuis démarrage: {self.error_count}")
            print(f"{'='*60}\n")
            self.last_alert = now


def start_log_watcher():
    """Démarrer la surveillance des logs."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    event_handler = LogWatcher()
    observer = Observer()
    observer.schedule(event_handler, str(LOG_DIR), recursive=False)
    observer.start()
    
    print(f"👁️  Log Watcher démarré - Surveillance de {LOG_FILE}")
    print(f"📊 En attente d'erreurs...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print(f"\n🛑 Log Watcher arrêté. Total erreurs: {event_handler.error_count}")
    observer.join()


if __name__ == '__main__':
    start_log_watcher()
