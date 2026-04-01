#!/usr/bin/env python3
"""
Auto-reload watcher pour AD Web Interface.
Surveille les changements de fichiers et redémarre le serveur automatiquement.
"""

import os
import sys
import time
import subprocess
import threading
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Extensions à surveiller
WATCHED_EXTENSIONS = {'.py', '.html', '.css', '.js', '.json', '.env'}

# Répertoires à surveiller
WATCHED_DIRS = [
    'templates',
    'static/css',
    'static/js',
    'routes',
]

# Fichiers à ignorer
IGNORED_FILES = {
    '__pycache__',
    '.pyc',
    '.log',
    '.tmp',
    'server.log',
    'debug.log',
}


class ChangeHandler(FileSystemEventHandler):
    """Gère les événements de changement de fichiers."""
    
    def __init__(self, restart_callback):
        self.restart_callback = restart_callback
        self.last_restart = 0
        self.debounce_seconds = 2  # Évite les redémarrages trop fréquents
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        # Vérifier l'extension
        path = Path(event.src_path)
        if path.suffix not in WATCHED_EXTENSIONS:
            return
        
        # Vérifier les fichiers ignorés
        if any(ignored in str(path) for ignored in IGNORED_FILES):
            return
        
        # Débounce
        current_time = time.time()
        if current_time - self.last_restart < self.debounce_seconds:
            return
        
        print(f"\n🔄 Changement détecté: {path.name}")
        self.last_restart = current_time
        self.restart_callback()


class AutoReloader:
    """Gère le rechargement automatique du serveur."""
    
    def __init__(self, script='run.py', host='0.0.0.0', port=5000):
        self.script = script
        self.host = host
        self.port = port
        self.process = None
        self.running = True
    
    def start_server(self):
        """Démarre le serveur."""
        print(f"\n🚀 Démarrage du serveur sur http://{self.host}:{self.port}")
        self.process = subprocess.Popen(
            [sys.executable, self.script],
            env={**os.environ, 'AD_SILENT': 'false'}
        )
    
    def stop_server(self):
        """Arrête le serveur."""
        if self.process:
            print("\n⏹️  Arrêt du serveur...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
    
    def restart_server(self):
        """Redémarre le serveur."""
        self.stop_server()
        time.sleep(1)
        self.start_server()
    
    def run(self):
        """Démarre le watcher et le serveur."""
        # Démarrer le serveur
        self.start_server()
        
        # Configurer le watcher
        event_handler = ChangeHandler(self.restart_server)
        observer = Observer()
        
        # Ajouter les répertoires à surveiller
        for watched_dir in WATCHED_DIRS:
            path = Path(watched_dir)
            if path.exists():
                observer.schedule(event_handler, str(path), recursive=True)
                print(f"👁️  Surveillance: {watched_dir}/")
        
        # Ajouter le répertoire racine pour les fichiers .py
        observer.schedule(event_handler, '.', recursive=False)
        
        observer.start()
        print("\n✅ Watcher démarré. Appuyez sur Ctrl+C pour arrêter.\n")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n⏹️  Arrêt du watcher...")
            self.running = False
            observer.stop()
            observer.join()
            self.stop_server()
            print("✅ Arrêté.")


if __name__ == '__main__':
    print("=" * 60)
    print("  AD Web Interface - Auto Reload Watcher")
    print("=" * 60)
    
    # Vérifier watchdog
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        print("\n❌ watchdog non installé. Installation...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'watchdog', '-q'])
        print("✅ watchdog installé.")
    
    # Démarrer
    reloader = AutoReloader()
    reloader.run()
