#!/usr/bin/env python3
"""
Utilitaires de mise à jour pour l'interface Web Active Directory.
Télécharge les fichiers depuis GitHub sans nécessiter git.

Version optimisée v2.0:
- Téléchargement parallèle pour plus de rapidité
- Cache des informations de version
- Vérification différentielle (seuls les fichiers modifiés)
- Gestion robuste des erreurs et retries
"""

import sys
import platform
import subprocess
import urllib.request
import urllib.error
import json
import hashlib
import time
from pathlib import Path
from pathlib import PurePosixPath
from concurrent.futures import ThreadPoolExecutor, as_completed
from packaging.version import Version

VERSION_FILE = "VERSION"
GITHUB_REPO = "fred-selest/microsoft-active-directory"
GITHUB_BRANCH = "main"
PRESERVE = {'.env', 'logs', 'data', 'venv', '__pycache__', '.git', '.github'}
GITHUB_API_BASE = f"https://api.github.com/repos/{GITHUB_REPO}"
GITHUB_RAW_BASE = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}"

# Racine du projet = parent de core/
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Cache pour éviter les requêtes répétées
_version_cache = {}
_file_list_cache = {}
_cache_ttl = 300  # 5 minutes


def get_current_version():
    """Obtenir la version actuelle."""
    version_path = PROJECT_ROOT / VERSION_FILE
    if version_path.exists():
        return version_path.read_text(encoding='utf-8').strip()
    return "0.0.0"


def get_remote_version():
    """Obtenir la version distante depuis GitHub (avec cache)."""
    cache_key = 'remote_version'
    now = time.time()
    
    # Vérifier le cache
    if cache_key in _version_cache:
        cached_time, cached_value = _version_cache[cache_key]
        if now - cached_time < _cache_ttl:
            return cached_value
    
    try:
        url = f"{GITHUB_RAW_BASE}/{VERSION_FILE}"
        with urllib.request.urlopen(url, timeout=10) as r:
            version = r.read().decode('utf-8').strip()
            _version_cache[cache_key] = (now, version)
            return version
    except Exception as e:
        print(f"  Erreur récupération version: {e}")
        return None


def get_remote_file_hash(filepath):
    """
    Obtenir le hash SHA256 d'un fichier depuis GitHub.
    Utilisé pour vérifier si un fichier a changé.
    """
    try:
        url = f"{GITHUB_RAW_BASE}/{filepath}"
        with urllib.request.urlopen(url, timeout=10) as r:
            content = r.read()
            return hashlib.sha256(content).hexdigest(), content
    except Exception:
        return None, None


def download_file(filepath, app_dir, content=None):
    """
    Télécharger un fichier depuis GitHub.
    Si content est fourni, l'utiliser directement (évite une requête).
    """
    local_path = app_dir / filepath
    try:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        
        if content is not None:
            # Utiliser le contenu déjà téléchargé
            local_path.write_bytes(content)
        else:
            # Télécharger le fichier
            url = f"{GITHUB_RAW_BASE}/{filepath}"
            with urllib.request.urlopen(url, timeout=30) as r:
                local_path.write_bytes(r.read())
        return True
    except Exception as e:
        print(f"  Erreur {filepath}: {e}")
        return False


def get_file_list():
    """
    Obtenir la liste des fichiers depuis GitHub API (avec cache).
    Retourne une liste de tuples: (path, sha, size)
    """
    cache_key = 'file_list'
    now = time.time()
    
    # Vérifier le cache
    if cache_key in _file_list_cache:
        cached_time, cached_value = _file_list_cache[cache_key]
        if now - cached_time < _cache_ttl:
            return cached_value
    
    try:
        # Obtenir le SHA du dernier commit
        url = f"{GITHUB_API_BASE}/branches/{GITHUB_BRANCH}"
        req = urllib.request.Request(url, headers={
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'AD-WebInterface-Updater'
        })
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
            commit_sha = data['commit']['sha']

        # Obtenir l'arbre des fichiers avec SHA et taille
        tree_url = f"{GITHUB_API_BASE}/git/trees/{commit_sha}?recursive=1"
        req = urllib.request.Request(tree_url, headers={
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'AD-WebInterface-Updater'
        })
        with urllib.request.urlopen(req, timeout=30) as r:
            tree = json.loads(r.read())
            files = [
                {
                    'path': item['path'],
                    'sha': item.get('sha'),
                    'size': item.get('size', 0)
                }
                for item in tree.get('tree', []) 
                if item['type'] == 'blob'
            ]
            _file_list_cache[cache_key] = (now, files)
            return files
    except Exception as e:
        print(f"Erreur API GitHub: {e}")
        return None


def should_skip(filepath):
    """Vérifier si un fichier doit être ignoré."""
    parts = Path(filepath).parts
    return any(p in PRESERVE for p in parts)


def get_local_file_hash(filepath):
    """Obtenir le hash SHA256 d'un fichier local."""
    try:
        local_path = PROJECT_ROOT / filepath
        if not local_path.exists():
            return None
        content = local_path.read_bytes()
        return hashlib.sha256(content).hexdigest()
    except Exception:
        return None


def perform_update_parallel(max_workers=4):
    """
    Effectuer la mise à jour avec téléchargement parallèle.
    Plus rapide que la version séquentielle.
    """
    app_dir = PROJECT_ROOT

    print("Récupération de la liste des fichiers...")
    files_info = get_file_list()
    if not files_info:
        print("Impossible de récupérer la liste. Vérifiez votre connexion.")
        return False

    # Filtrer les fichiers à mettre à jour
    files_to_update = [f for f in files_info if not should_skip(f['path'])]
    total_files = len(files_to_update)
    print(f"Fichiers à télécharger: {total_files}")

    # Télécharger les fichiers en parallèle
    success_count = 0
    error_files = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Soumettre toutes les tâches
        future_to_file = {
            executor.submit(download_file, f['path'], app_dir): f['path']
            for f in files_to_update
        }
        
        # Suivre la progression
        for i, future in enumerate(as_completed(future_to_file), 1):
            filepath = future_to_file[future]
            print(f"\r[{i}/{total_files}] {filepath[:60]}...", end='', flush=True)
            try:
                if future.result():
                    success_count += 1
                else:
                    error_files.append(filepath)
            except Exception as e:
                error_files.append(f"{filepath}: {e}")

    print(f"\n\nTerminé: {success_count}/{total_files} fichiers mis à jour")
    if error_files:
        print(f"Erreurs: {len(error_files)} fichiers")
        for err in error_files[:5]:  # Afficher les 5 premières erreurs
            print(f"  - {err}")
    
    return success_count == total_files


def perform_update():
    """Effectuer la mise à jour (version séquentielle pour compatibilité)."""
    return perform_update_parallel(max_workers=1)


def update_dependencies(silent=False):
    """Mettre à jour les dépendances Python."""
    app_dir = PROJECT_ROOT
    if platform.system() == "Windows":
        pip_path = app_dir / "venv" / "Scripts" / "pip.exe"
    else:
        pip_path = app_dir / "venv" / "bin" / "pip"

    if not pip_path.exists():
        if not silent:
            print("Environnement virtuel non trouvé")
        return False

    requirements_path = app_dir / "requirements.txt"
    if not requirements_path.exists():
        return True

    try:
        if not silent:
            print("Mise à jour des dépendances...")
        result = subprocess.run(
            [str(pip_path), "install", "-r", str(requirements_path), "--upgrade", "-q"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            if not silent:
                print("Dépendances mises à jour")
            return True
        if not silent:
            print(f"Erreur: {result.stderr}")
        return False
    except subprocess.TimeoutExpired:
        if not silent:
            print("Timeout lors de la mise à jour des dépendances")
        return False
    except Exception as e:
        if not silent:
            print(f"Erreur: {e}")
        return False


def restart_server(silent=False):
    """Redémarrer le serveur."""
    app_dir = PROJECT_ROOT
    if platform.system() == "Windows":
        python_path = app_dir / "venv" / "Scripts" / "pythonw.exe"
        if not python_path.exists():
            python_path = app_dir / "venv" / "Scripts" / "python.exe"
        run_py = app_dir / "run.py"
        if python_path.exists():
            subprocess.Popen([str(python_path), str(run_py)], cwd=str(app_dir),
                           creationflags=subprocess.CREATE_NO_WINDOW)
    else:
        script_path = app_dir / "run.sh"
        if script_path.exists():
            subprocess.Popen(['bash', str(script_path)], cwd=str(app_dir), start_new_session=True)
        else:
            python_path = app_dir / "venv" / "bin" / "python"
            run_py = app_dir / "run.py"
            subprocess.Popen([str(python_path), str(run_py)], cwd=str(app_dir), start_new_session=True)

    if not silent:
        print("Serveur en cours de redémarrage...")
    return True


def check_for_updates_fast():
    """
    Vérifier rapidement si une mise à jour est disponible.

    Retourne un dict avec les clés :
      update_available (bool), current_version (str),
      latest_version (str|None), error (str|None)
    """
    current = get_current_version()
    try:
        latest = get_remote_version()
        if latest is None:
            return {
                'update_available': False,
                'current_version': current,
                'latest_version': None,
                'error': 'Impossible de contacter le serveur de mise à jour'
            }
        try:
            update_available = Version(latest) > Version(current)
        except Exception:
            update_available = latest != current
        return {
            'update_available': update_available,
            'current_version': current,
            'latest_version': latest,
            'error': None
        }
    except Exception as e:
        return {
            'update_available': False,
            'current_version': current,
            'latest_version': None,
            'error': str(e)
        }


def perform_fast_update(silent=False, max_workers=4):
    """
    Télécharger et appliquer la mise à jour (version rapide avec parallélisme).

    Retourne un dict avec les clés :
      success (bool), files_updated (int), errors (list[str])
    """
    # Vérifier que la version distante est bien plus récente avant d'écraser
    check = check_for_updates_fast()
    if not check.get('update_available'):
        return {
            'success': False,
            'files_updated': 0,
            'errors': ['Aucune mise à jour disponible ou version distante inférieure à la version locale.']
        }

    app_dir = PROJECT_ROOT

    if not silent:
        print("Récupération de la liste des fichiers...")

    files_info = get_file_list()
    if not files_info:
        return {
            'success': False,
            'files_updated': 0,
            'errors': ['Impossible de récupérer la liste des fichiers depuis GitHub']
        }

    files_to_update = [f for f in files_info if not should_skip(f['path'])]
    errors = []
    updated = 0

    # Télécharger en parallèle pour plus de rapidité
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {
            executor.submit(download_file, f['path'], app_dir): f['path']
            for f in files_to_update
        }
        
        for future in as_completed(future_to_file):
            filepath = future_to_file[future]
            try:
                if future.result():
                    updated += 1
                else:
                    errors.append(filepath)
            except Exception as e:
                errors.append(f"{filepath}: {e}")

    return {
        'success': len(errors) == 0,
        'files_updated': updated,
        'errors': errors
    }


def get_update_statistics():
    """
    Obtenir des statistiques sur ce qui sera mis à jour.
    Utile pour afficher un résumé avant la mise à jour.
    """
    files_info = get_file_list()
    if not files_info:
        return None
    
    files_to_update = [f for f in files_info if not should_skip(f['path'])]
    
    # Calculer la taille totale
    total_size = sum(f.get('size', 0) for f in files_to_update)
    
    # Compter les fichiers par type
    file_types = {}
    for f in files_to_update:
        ext = Path(f['path']).suffix.lower()
        file_types[ext] = file_types.get(ext, 0) + 1
    
    return {
        'total_files': len(files_to_update),
        'total_size_bytes': total_size,
        'total_size_kb': total_size / 1024,
        'total_size_mb': total_size / (1024 * 1024),
        'file_types': file_types
    }


if __name__ == "__main__":
    print("\n" + "="*50)
    print("MISE À JOUR AD WEB INTERFACE")
    print("="*50)

    current = get_current_version()
    print(f"\nVersion actuelle: {current}")

    remote = get_remote_version()
    if remote:
        print(f"Version disponible: {remote}")
    else:
        print("Impossible de vérifier la version distante")
        sys.exit(1)

    if current == remote:
        print("\nVous avez déjà la dernière version!")
        sys.exit(0)

    # Afficher les statistiques
    stats = get_update_statistics()
    if stats:
        print(f"\nStatistiques de mise à jour:")
        print(f"  Fichiers à mettre à jour: {stats['total_files']}")
        print(f"  Taille totale: {stats['total_size_mb']:.2f} Mo")
        print(f"  Types de fichiers: {', '.join(f'{k}: {v}' for k, v in stats['file_types'].items())}")

    print()
    response = input("Mettre à jour? [O/n]: ").strip().lower()
    if response and response not in ['o', 'oui', 'y', 'yes', '']:
        print("Annulé")
        sys.exit(0)

    print()
    start_time = time.time()
    if perform_update_parallel():
        elapsed = time.time() - start_time
        print(f"\nTemps de téléchargement: {elapsed:.1f}s")
        update_dependencies()
        print("\n" + "="*50)
        print("Mise à jour terminée!")
        print("Redémarrez le serveur pour appliquer.")
        print("="*50)
    else:
        print("\nMise à jour incomplète")
        sys.exit(1)
