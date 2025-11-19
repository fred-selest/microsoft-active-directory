#!/usr/bin/env python3
"""
Systeme de mise a jour automatique pour l'interface Web Active Directory.
Telecharge et installe les nouvelles versions depuis GitHub.
"""

import os
import sys
import json
import shutil
import tempfile
import zipfile
import platform
import subprocess
from pathlib import Path

# Configuration du depot GitHub
GITHUB_REPO = "fred-selest/microsoft-active-directory"
GITHUB_BRANCH = "main"
VERSION_FILE = "VERSION"


def get_current_version():
    """Obtenir la version actuelle installee."""
    version_path = Path(__file__).parent / VERSION_FILE

    if version_path.exists():
        with open(version_path, 'r', encoding='utf-8') as f:
            return f.read().strip()
    return "0.0.0"


def get_latest_version(silent=False):
    """Obtenir la derniere version disponible sur GitHub."""
    try:
        if platform.system() == "Windows":
            # Utiliser PowerShell sur Windows
            cmd = [
                "powershell", "-Command",
                f"(Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{VERSION_FILE}' -UseBasicParsing).Content"
            ]
        else:
            # Utiliser curl sur Linux/macOS
            cmd = [
                "curl", "-s",
                f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{VERSION_FILE}"
            ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except Exception as e:
        if not silent:
            print(f"Erreur lors de la verification de version: {e}")
        return None


def compare_versions(current, latest):
    """Comparer deux numeros de version."""
    def parse_version(v):
        return tuple(map(int, v.split('.')))

    try:
        return parse_version(latest) > parse_version(current)
    except:
        return False


def check_for_updates():
    """Verifier si une mise a jour est disponible."""
    current = get_current_version()
    latest = get_latest_version()

    if latest is None:
        return {
            'update_available': False,
            'current_version': current,
            'latest_version': None,
            'error': 'Impossible de verifier les mises a jour'
        }

    update_available = compare_versions(current, latest)

    return {
        'update_available': update_available,
        'current_version': current,
        'latest_version': latest,
        'error': None
    }


def download_update(silent=False):
    """Telecharger la derniere version depuis GitHub."""
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, "update.zip")

    try:
        url = f"https://github.com/{GITHUB_REPO}/archive/refs/heads/{GITHUB_BRANCH}.zip"

        if platform.system() == "Windows":
            cmd = [
                "powershell", "-Command",
                f"Invoke-WebRequest -Uri '{url}' -OutFile '{zip_path}'"
            ]
        else:
            cmd = ["curl", "-s", "-L", "-o", zip_path, url]

        if not silent:
            print(f"Telechargement de la mise a jour...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode != 0:
            raise Exception(f"Erreur de telechargement: {result.stderr}")

        if not os.path.exists(zip_path):
            raise Exception("Le fichier telecharge n'existe pas")

        return zip_path, temp_dir

    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise e


def apply_update(zip_path, temp_dir, silent=False):
    """Appliquer la mise a jour telechargee."""
    app_dir = Path(__file__).parent

    try:
        # Extraire l'archive
        if not silent:
            print("Extraction de la mise a jour...")
        extract_dir = os.path.join(temp_dir, "extracted")

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)

        # Trouver le dossier extrait
        extracted_folders = os.listdir(extract_dir)
        if not extracted_folders:
            raise Exception("Archive vide")

        source_dir = os.path.join(extract_dir, extracted_folders[0])

        # Fichiers a ne pas ecraser
        preserve_files = ['.env', 'logs', 'data', 'venv']

        # Copier les nouveaux fichiers
        if not silent:
            print("Installation des nouveaux fichiers...")
        for item in os.listdir(source_dir):
            if item in preserve_files:
                continue

            src_path = os.path.join(source_dir, item)
            dst_path = os.path.join(app_dir, item)

            if os.path.isdir(src_path):
                if os.path.exists(dst_path):
                    shutil.rmtree(dst_path)
                shutil.copytree(src_path, dst_path)
            else:
                shutil.copy2(src_path, dst_path)

        if not silent:
            print("Mise a jour terminee avec succes!")
        return True

    except Exception as e:
        if not silent:
            print(f"Erreur lors de l'application de la mise a jour: {e}")
        return False
    finally:
        # Nettoyer les fichiers temporaires
        shutil.rmtree(temp_dir, ignore_errors=True)


def update_dependencies(silent=False):
    """Mettre a jour les dependances Python."""
    app_dir = Path(__file__).parent

    if platform.system() == "Windows":
        pip_path = app_dir / "venv" / "Scripts" / "pip.exe"
    else:
        pip_path = app_dir / "venv" / "bin" / "pip"

    if not pip_path.exists():
        if not silent:
            print("Environnement virtuel non trouve, dependances non mises a jour")
        return False

    requirements_path = app_dir / "requirements.txt"

    if not requirements_path.exists():
        return True

    try:
        if not silent:
            print("Mise a jour des dependances...")
        result = subprocess.run(
            [str(pip_path), "install", "-r", str(requirements_path), "--upgrade", "-q"],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            if not silent:
                print("Dependances mises a jour")
            return True
        else:
            if not silent:
                print(f"Erreur: {result.stderr}")
            return False

    except Exception as e:
        if not silent:
            print(f"Erreur lors de la mise a jour des dependances: {e}")
        return False


def restart_server(silent=False):
    """Redemarrer le serveur automatiquement."""
    app_dir = Path(__file__).parent

    if platform.system() == "Windows":
        # Sur Windows, utiliser run.bat
        script_path = app_dir / "run.bat"
        if script_path.exists():
            subprocess.Popen(
                ['cmd', '/c', 'start', '', str(script_path)],
                cwd=str(app_dir),
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        else:
            # Fallback: lancer directement python
            python_path = app_dir / "venv" / "Scripts" / "python.exe"
            run_py = app_dir / "run.py"
            subprocess.Popen(
                [str(python_path), str(run_py)],
                cwd=str(app_dir),
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
    else:
        # Sur Linux/macOS, utiliser run.sh
        script_path = app_dir / "run.sh"
        if script_path.exists():
            subprocess.Popen(
                ['bash', str(script_path)],
                cwd=str(app_dir),
                start_new_session=True
            )
        else:
            # Fallback: lancer directement python
            python_path = app_dir / "venv" / "bin" / "python"
            run_py = app_dir / "run.py"
            subprocess.Popen(
                [str(python_path), str(run_py)],
                cwd=str(app_dir),
                start_new_session=True
            )

    if not silent:
        print("Serveur en cours de redemarrage...")
    return True


def perform_update():
    """Executer la mise a jour complete."""
    print("\n" + "="*50)
    print("MISE A JOUR DE L'INTERFACE WEB AD")
    print("="*50 + "\n")

    # Verifier les mises a jour
    info = check_for_updates()

    if info['error']:
        print(f"Erreur: {info['error']}")
        return False

    if not info['update_available']:
        print(f"Vous avez deja la derniere version ({info['current_version']})")
        return True

    print(f"Version actuelle: {info['current_version']}")
    print(f"Nouvelle version: {info['latest_version']}")
    print()

    # Confirmation
    response = input("Voulez-vous mettre a jour? [O/n]: ").strip().lower()
    if response and response not in ['o', 'oui', 'y', 'yes']:
        print("Mise a jour annulee")
        return False

    # Telecharger
    try:
        zip_path, temp_dir = download_update()
    except Exception as e:
        print(f"Erreur de telechargement: {e}")
        return False

    # Appliquer
    if not apply_update(zip_path, temp_dir):
        return False

    # Mettre a jour les dependances
    update_dependencies()

    print("\n" + "="*50)
    print("Mise a jour terminee!")
    print("Redemarrez le serveur pour appliquer les changements.")
    print("="*50 + "\n")

    return True


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        # Mode verification uniquement
        info = check_for_updates()
        print(json.dumps(info, indent=2))
    else:
        # Mode mise a jour
        success = perform_update()
        sys.exit(0 if success else 1)
