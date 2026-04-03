"""
Auto-Reload Server - Redémarre automatiquement le serveur lors des modifications
Surveille les fichiers Python, HTML, CSS, JS
Version améliorée avec logging détaillé
"""
import os
import sys
import time
import subprocess
import hashlib
from pathlib import Path
from datetime import datetime

# Configuration
VERBOSE = True  # Afficher les logs détaillés
CHECK_INTERVAL = 1  # Vérifier toutes les secondes
RESTART_DELAY = 2  # Attendre 2 secondes avant de redémarrer

# Fichiers à surveiller
WATCH_PATTERNS = [
    '*.py',      # Python
    '*.html',    # Templates
    '*.css',     # CSS
    '*.js',      # JavaScript
    '.env',      # Configuration
]

# Répertoires à surveiller
WATCH_DIRS = [
    'routes',
    'templates',
    'static/css',
    'static/js',
    '.',  # Racine (pour app.py, config.py, etc.)
]

# Fichiers exclus
EXCLUDE_PATTERNS = [
    '*.pyc',
    '__pycache__',
    '.git',
    'logs',
    'data',
    'test_*.py',
    '*.log',
    '.qwen',
    '.claude',
]


def log(message, level='INFO'):
    """Afficher un message de log."""
    timestamp = datetime.now().strftime('%H:%M:%S')
    prefix = {
        'INFO': 'ℹ️',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'SUCCESS': '✅',
        'DEBUG': '🔍'
    }.get(level, '•')
    
    if VERBOSE or level in ['ERROR', 'WARNING', 'SUCCESS']:
        print(f"{timestamp} {prefix} {message}")


class FileWatcher:
    def __init__(self):
        self.file_hashes = {}
        self.server_process = None
        self.running = True
        self.last_restart = 0
        self.restart_count = 0
        
    def get_file_hash(self, filepath):
        """Calculer le hash d'un fichier."""
        try:
            with open(filepath, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            if VERBOSE:
                log(f"Erreur lecture {filepath}: {e}", 'DEBUG')
            return None
    
    def should_watch(self, filepath):
        """Vérifier si le fichier doit être surveillé."""
        path = Path(filepath)
        filename = path.name
        
        # Exclure certains patterns
        for pattern in EXCLUDE_PATTERNS:
            if filename.match(pattern) or str(path).replace('\\', '/').find(pattern.replace('*', '')) >= 0:
                return False
        
        # Exclure les fichiers temporaires
        if filename.startswith('~') or filename.endswith('.tmp'):
            return False
        
        # Inclure seulement les patterns souhaités
        for pattern in WATCH_PATTERNS:
            if filename.match(pattern):
                return True
        
        return False
    
    def scan_files(self):
        """Scanner tous les fichiers à surveiller."""
        files = {}
        
        # Répertoires
        for dir_name in WATCH_DIRS:
            if not os.path.exists(dir_name):
                continue
                
            try:
                for root, dirs, filenames in os.walk(dir_name):
                    # Exclure certains répertoires
                    dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', '.qwen', '.claude', 'logs', 'data']]
                    
                    for filename in filenames:
                        filepath = os.path.join(root, filename)
                        if self.should_watch(filepath):
                            file_hash = self.get_file_hash(filepath)
                            if file_hash:
                                files[filepath] = file_hash
            except Exception as e:
                log(f"Erreur scan {dir_name}: {e}", 'WARNING')
        
        return files
    
    def start_server(self):
        """Démarrer le serveur Flask."""
        log(f"\n{'='*60}")
        log(f" 🚀 Démarrage du serveur Flask...", 'INFO')
        log(f"{'='*60}\n")
        
        try:
            self.server_process = subprocess.Popen(
                [sys.executable, 'run.py'],
                env={**os.environ, 'FLASK_DEBUG': '1'},
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
            )
            
            log(f" ✅ Serveur démarré (PID: {self.server_process.pid})", 'SUCCESS')
            log(f" 📡 Écoute sur http://localhost:5000")
            log(f" 👁️  Surveillance des modifications...\n")
            
            self.restart_count += 1
            self.last_restart = time.time()
            
        except Exception as e:
            log(f" ❌ Erreur démarrage serveur: {e}", 'ERROR')
            self.server_process = None
    
    def stop_server(self):
        """Arrêter le serveur."""
        if self.server_process:
            log(f"\n 🛑 Arrêt du serveur (PID: {self.server_process.pid})...", 'INFO')
            
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
            except Exception as e:
                log(f" ⚠️  Force kill: {e}", 'WARNING')
                try:
                    self.server_process.kill()
                except:
                    pass
            
            self.server_process = None
            log(f" ✅ Serveur arrêté", 'SUCCESS')
    
    def restart_server(self, changed_files):
        """Redémarrer le serveur."""
        # Éviter les redémarrages trop fréquents
        if time.time() - self.last_restart < 5:
            log(f" ⏳ Skip restart (trop récent)", 'DEBUG')
            return
        
        log(f"\n{'='*60}", 'INFO')
        log(f" 📝 Modification détectée !", 'WARNING')
        log(f"{'='*60}")
        
        for f in changed_files[:5]:  # Afficher max 5 fichiers
            log(f"   ✏️  {f}", 'DEBUG')
        
        if len(changed_files) > 5:
            log(f"   ... et {len(changed_files) - 5} autres", 'DEBUG')
        
        self.stop_server()
        
        # Attendre que le port se libère
        log(f" ⏳ Attente {RESTART_DELAY}s...", 'INFO')
        time.sleep(RESTART_DELAY)
        
        self.start_server()
    
    def check_changes(self):
        """Vérifier les changements de fichiers."""
        current_files = self.scan_files()
        
        changed = False
        changed_files = []
        
        # Nouveaux fichiers
        new_files = set(current_files.keys()) - set(self.file_hashes.keys())
        if new_files and VERBOSE:
            for f in new_files:
                log(f"   ➕ Nouveau: {os.path.basename(f)}", 'DEBUG')
            changed = True
            changed_files.extend(new_files)
        
        # Fichiers supprimés
        deleted_files = set(self.file_hashes.keys()) - set(current_files.keys())
        if deleted_files and VERBOSE:
            for f in deleted_files:
                log(f"   ➖ Supprimé: {os.path.basename(f)}", 'DEBUG')
            changed = True
            changed_files.extend(deleted_files)
        
        # Fichiers modifiés
        for filepath, hash_value in current_files.items():
            if filepath in self.file_hashes:
                if self.file_hashes[filepath] != hash_value:
                    if VERBOSE:
                        log(f"   ✏️  Modifié: {os.path.basename(filepath)}", 'DEBUG')
                    changed = True
                    changed_files.append(filepath)
        
        return changed, changed_files
    
    def run(self):
        """Lancer la surveillance."""
        log(f"\n{'='*60}")
        log(f" 👁️  AUTO-RELOAD - Surveillance des fichiers", 'INFO')
        log(f"{'='*60}")
        log(f"\n📁 Répertoires surveillés: {', '.join(WATCH_DIRS)}")
        log(f"📄 Types de fichiers: {', '.join(WATCH_PATTERNS)}")
        log(f"⏱️  Intervalle: {CHECK_INTERVAL}s")
        log(f"⚠️  Appuie sur Ctrl+C pour arrêter\n")
        
        # Scan initial
        log(f"🔍 Scan initial...", 'INFO')
        self.file_hashes = self.scan_files()
        log(f"📊 {len(self.file_hashes)} fichiers surveillés\n", 'SUCCESS')
        
        # Démarrer le serveur
        self.start_server()
        
        # Boucle de surveillance
        try:
            while self.running:
                time.sleep(CHECK_INTERVAL)
                
                try:
                    changed, changed_files = self.check_changes()
                    
                    if changed:
                        self.file_hashes = self.scan_files()
                        self.restart_server(changed_files)
                    
                    # Vérifier si le serveur tourne toujours
                    if self.server_process and self.server_process.poll() is not None:
                        log(f" ⚠️  Serveur arrêté inopinément", 'WARNING')
                        self.server_process = None
                        time.sleep(2)
                        self.start_server()
                        
                except Exception as e:
                    log(f" ❌ Erreur surveillance: {e}", 'ERROR')
                    time.sleep(2)
                    
        except KeyboardInterrupt:
            log(f"\n\n{'='*60}")
            log(f" 👋 Arrêt de la surveillance...", 'INFO')
            log(f"{'='*60}\n")
            self.stop_server()
            self.running = False
            log(f"📊 Statistiques: {self.restart_count} redémarrages", 'INFO')


if __name__ == '__main__':
    # Vérifier que run.py existe
    if not os.path.exists('run.py'):
        log(f"❌ Erreur: run.py introuvable", 'ERROR')
        log(f"   Assurez-vous d'être dans le répertoire du projet", 'ERROR')
        input("Appuyez sur Entrée pour quitter...")
        sys.exit(1)
    
    # Lancer la surveillance
    watcher = FileWatcher()
    watcher.run()
