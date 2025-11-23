#!/usr/bin/env python3
"""
Utilitaires de mise a jour pour l'interface Web Active Directory.
"""

import sys
import platform
import subprocess
from pathlib import Path

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
    print(f"\nVersion actuelle: {get_current_version()}")
    print("\nPour mettre a jour, utilisez git:")
    print("  git pull origin main")
    print("\nPuis mettez a jour les dependances:")
    print("  python updater.py --deps")

    if len(sys.argv) > 1 and sys.argv[1] == "--deps":
        update_dependencies(silent=False)
