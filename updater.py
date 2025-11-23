#!/usr/bin/env python3
"""
Utilitaires de mise a jour pour l'interface Web Active Directory.
Telecharge les fichiers depuis GitHub sans necesiter git.
"""

import sys
import platform
import subprocess
import urllib.request
import json
from pathlib import Path

VERSION_FILE = "VERSION"
GITHUB_REPO = "fred-selest/microsoft-active-directory"
GITHUB_BRANCH = "main"
PRESERVE = {'.env', 'logs', 'data', 'venv', '__pycache__', '.git'}


def get_current_version():
    """Obtenir la version actuelle."""
    version_path = Path(__file__).parent / VERSION_FILE
    if version_path.exists():
        return version_path.read_text(encoding='utf-8').strip()
    return "0.0.0"


def get_remote_version():
    """Obtenir la version distante depuis GitHub."""
    try:
        url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{VERSION_FILE}"
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.read().decode('utf-8').strip()
    except:
        return None


def download_file(filepath, app_dir):
    """Telecharger un fichier depuis GitHub."""
    url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{filepath}"
    local_path = app_dir / filepath
    try:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=30) as r:
            local_path.write_bytes(r.read())
        return True
    except Exception as e:
        print(f"  Erreur {filepath}: {e}")
        return False


def get_file_list():
    """Obtenir la liste des fichiers depuis GitHub API."""
    try:
        # Obtenir le SHA du dernier commit
        url = f"https://api.github.com/repos/{GITHUB_REPO}/branches/{GITHUB_BRANCH}"
        req = urllib.request.Request(url, headers={'Accept': 'application/vnd.github.v3+json'})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
            commit_sha = data['commit']['sha']

        # Obtenir l'arbre des fichiers
        tree_url = f"https://api.github.com/repos/{GITHUB_REPO}/git/trees/{commit_sha}?recursive=1"
        req = urllib.request.Request(tree_url, headers={'Accept': 'application/vnd.github.v3+json'})
        with urllib.request.urlopen(req, timeout=30) as r:
            tree = json.loads(r.read())
            return [item['path'] for item in tree.get('tree', []) if item['type'] == 'blob']
    except Exception as e:
        print(f"Erreur API GitHub: {e}")
        return None


def should_skip(filepath):
    """Verifier si un fichier doit etre ignore."""
    parts = Path(filepath).parts
    return any(p in PRESERVE for p in parts)


def perform_update():
    """Effectuer la mise a jour."""
    app_dir = Path(__file__).parent

    print("Recuperation de la liste des fichiers...")
    files = get_file_list()
    if not files:
        print("Impossible de recuperer la liste. Verifiez votre connexion.")
        return False

    files_to_update = [f for f in files if not should_skip(f)]
    print(f"Fichiers a telecharger: {len(files_to_update)}")

    success = 0
    for i, filepath in enumerate(files_to_update, 1):
        print(f"\r[{i}/{len(files_to_update)}] {filepath[:50]}...", end='', flush=True)
        if download_file(filepath, app_dir):
            success += 1

    print(f"\n\nTermine: {success}/{len(files_to_update)} fichiers mis a jour")
    return success == len(files_to_update)


def update_dependencies(silent=False):
    """Mettre a jour les dependances Python."""
    app_dir = Path(__file__).parent
    if platform.system() == "Windows":
        pip_path = app_dir / "venv" / "Scripts" / "pip.exe"
    else:
        pip_path = app_dir / "venv" / "bin" / "pip"

    if not pip_path.exists():
        if not silent:
            print("Environnement virtuel non trouve")
        return False

    requirements_path = app_dir / "requirements.txt"
    if not requirements_path.exists():
        return True

    try:
        if not silent:
            print("Mise a jour des dependances...")
        result = subprocess.run(
            [str(pip_path), "install", "-r", str(requirements_path), "--upgrade", "-q"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            if not silent:
                print("Dependances mises a jour")
            return True
        if not silent:
            print(f"Erreur: {result.stderr}")
        return False
    except Exception as e:
        if not silent:
            print(f"Erreur: {e}")
        return False


def restart_server(silent=False):
    """Redemarrer le serveur."""
    app_dir = Path(__file__).parent
    if platform.system() == "Windows":
        silent_script = app_dir / "run-silent.vbs"
        if silent_script.exists():
            subprocess.Popen(['wscript.exe', str(silent_script)], cwd=str(app_dir),
                           creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            python_path = app_dir / "venv" / "Scripts" / "pythonw.exe"
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
        print("Serveur en cours de redemarrage...")
    return True


if __name__ == "__main__":
    print("\n" + "="*50)
    print("MISE A JOUR AD WEB INTERFACE")
    print("="*50)

    current = get_current_version()
    print(f"\nVersion actuelle: {current}")

    remote = get_remote_version()
    if remote:
        print(f"Version disponible: {remote}")
    else:
        print("Impossible de verifier la version distante")
        sys.exit(1)

    if current == remote:
        print("\nVous avez deja la derniere version!")
        sys.exit(0)

    print()
    response = input("Mettre a jour? [O/n]: ").strip().lower()
    if response and response not in ['o', 'oui', 'y', 'yes', '']:
        print("Annule")
        sys.exit(0)

    print()
    if perform_update():
        update_dependencies()
        print("\n" + "="*50)
        print("Mise a jour terminee!")
        print("Redemarrez le serveur pour appliquer.")
        print("="*50)
    else:
        print("\nMise a jour incomplete")
        sys.exit(1)
