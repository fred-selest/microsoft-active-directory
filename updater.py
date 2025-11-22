#!/usr/bin/env python3
"""
Utilitaires de mise a jour pour l'interface Web Active Directory.
Le systeme de mise a jour principal est dans updater_fast.py (mise a jour incrementale).
Ce module fournit les fonctions utilitaires: version, redemarrage, dependances.
"""

import os
import sys
import json
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
    """Redemarrer le serveur automatiquement (en mode silencieux sur Windows)."""
    app_dir = Path(__file__).parent

    if platform.system() == "Windows":
        # Sur Windows, utiliser run-silent.vbs pour eviter la fenetre de console
        silent_script = app_dir / "run-silent.vbs"
        if silent_script.exists():
            subprocess.Popen(
                ['wscript.exe', str(silent_script)],
                cwd=str(app_dir),
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        else:
            # Fallback: lancer pythonw (sans console)
            pythonw_path = app_dir / "venv" / "Scripts" / "pythonw.exe"
            run_py = app_dir / "run.py"
            if pythonw_path.exists():
                subprocess.Popen(
                    [str(pythonw_path), str(run_py)],
                    cwd=str(app_dir),
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                # Dernier recours: python.exe sans nouvelle console
                python_path = app_dir / "venv" / "Scripts" / "python.exe"
                subprocess.Popen(
                    [str(python_path), str(run_py)],
                    cwd=str(app_dir),
                    creationflags=subprocess.CREATE_NO_WINDOW
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


if __name__ == "__main__":
    # Utiliser le systeme de mise a jour rapide
    from updater_fast import check_for_updates_fast, perform_fast_update

    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        # Mode verification uniquement
        info = check_for_updates_fast()
        print(json.dumps(info, indent=2))
    else:
        # Mode mise a jour incrementale rapide
        print("\n" + "="*50)
        print("MISE A JOUR INCREMENTALE RAPIDE")
        print("="*50 + "\n")

        info = check_for_updates_fast()

        if info.get('error'):
            print(f"Erreur: {info['error']}")
            sys.exit(1)

        if not info['update_available']:
            print(f"Vous avez deja la derniere version ({info['current_version']})")
            sys.exit(0)

        print(f"Version actuelle: {info['current_version']}")
        print(f"Nouvelle version: {info['latest_version']}")
        print(f"Fichiers a mettre a jour: {info['files_to_update']}")
        print(f"Taille a telecharger: {info['download_size_kb']:.1f} Ko")
        print()

        # Confirmation
        response = input("Voulez-vous mettre a jour? [O/n]: ").strip().lower()
        if response and response not in ['o', 'oui', 'y', 'yes']:
            print("Mise a jour annulee")
            sys.exit(0)

        # Mise a jour
        result = perform_fast_update(silent=False)

        if result['success']:
            update_dependencies(silent=False)
            print("\n" + "="*50)
            print("Mise a jour terminee!")
            print("Redemarrez le serveur pour appliquer les changements.")
            print("="*50 + "\n")
            sys.exit(0)
        else:
            print(f"\nErreur: {result.get('errors', [])}")
            sys.exit(1)
