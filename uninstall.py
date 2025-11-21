#!/usr/bin/env python3
"""
Désinstallateur pour AD Web Interface.
Supprime proprement l'application et ses données.
"""

import os
import sys
import shutil
import platform
from pathlib import Path


def get_app_dir():
    """Obtenir le répertoire de l'application."""
    return Path(__file__).parent.resolve()


def get_data_dirs():
    """Obtenir les répertoires de données selon le système."""
    if platform.system() == "Windows":
        return {
            'logs': Path(os.environ.get('PROGRAMDATA', 'C:/ProgramData')) / 'ADWebInterface' / 'logs',
            'data': Path(os.environ.get('PROGRAMDATA', 'C:/ProgramData')) / 'ADWebInterface' / 'data',
            'backup': Path(os.environ.get('PROGRAMDATA', 'C:/ProgramData')) / 'ADWebInterface' / 'backups',
        }
    else:
        return {
            'logs': Path('/var/log/ad-web-interface'),
            'data': Path('/var/lib/ad-web-interface'),
            'backup': Path('/var/lib/ad-web-interface/backups'),
        }


def stop_server():
    """Arrêter le serveur s'il est en cours d'exécution."""
    print("Arrêt du serveur...")

    if platform.system() == "Windows":
        # Windows: tuer les processus Python qui utilisent app.py
        try:
            import subprocess
            subprocess.run(
                ['taskkill', '/F', '/IM', 'python.exe', '/FI', 'WINDOWTITLE eq AD*'],
                capture_output=True
            )
        except:
            pass
    else:
        # Linux/macOS: chercher et tuer le processus
        try:
            import subprocess
            result = subprocess.run(
                ['pgrep', '-f', 'app.py'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                pids = result.stdout.strip().split('\n')
                for pid in pids:
                    if pid:
                        subprocess.run(['kill', pid], capture_output=True)
        except:
            pass


def remove_venv(app_dir: Path):
    """Supprimer l'environnement virtuel."""
    venv_dir = app_dir / 'venv'
    if venv_dir.exists():
        print(f"Suppression de l'environnement virtuel: {venv_dir}")
        try:
            shutil.rmtree(venv_dir)
            return True
        except Exception as e:
            print(f"  Erreur: {e}")
            return False
    return True


def remove_cache(app_dir: Path):
    """Supprimer les fichiers cache."""
    cache_dirs = [
        app_dir / '__pycache__',
        app_dir / '.pytest_cache',
        app_dir / 'data' / 'update_cache.json',
    ]

    for cache in cache_dirs:
        if cache.exists():
            print(f"Suppression du cache: {cache}")
            try:
                if cache.is_dir():
                    shutil.rmtree(cache)
                else:
                    cache.unlink()
            except Exception as e:
                print(f"  Erreur: {e}")


def remove_data(keep_config: bool = False):
    """Supprimer les données de l'application."""
    data_dirs = get_data_dirs()

    for name, path in data_dirs.items():
        if path.exists():
            print(f"Suppression des données ({name}): {path}")
            try:
                shutil.rmtree(path)
            except Exception as e:
                print(f"  Erreur: {e}")


def remove_app(app_dir: Path, keep_config: bool = False):
    """Supprimer les fichiers de l'application."""
    # Fichiers à conserver si keep_config
    preserve = ['.env'] if keep_config else []

    # Sauvegarder les fichiers à préserver
    preserved_files = {}
    for filename in preserve:
        filepath = app_dir / filename
        if filepath.exists():
            with open(filepath, 'rb') as f:
                preserved_files[filename] = f.read()

    print(f"Suppression de l'application: {app_dir}")

    # Supprimer tous les fichiers sauf le script de désinstallation en cours
    current_script = Path(__file__).resolve()

    for item in app_dir.iterdir():
        if item.resolve() == current_script:
            continue
        try:
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
        except Exception as e:
            print(f"  Erreur suppression {item}: {e}")

    # Restaurer les fichiers préservés
    for filename, content in preserved_files.items():
        filepath = app_dir / filename
        with open(filepath, 'wb') as f:
            f.write(content)
        print(f"  Conservé: {filename}")


def remove_shortcuts():
    """Supprimer les raccourcis (Windows)."""
    if platform.system() != "Windows":
        return

    try:
        import winreg
        # Supprimer du menu démarrer si présent
        start_menu = Path(os.environ['APPDATA']) / 'Microsoft' / 'Start Menu' / 'Programs'
        shortcut = start_menu / 'AD Web Interface.lnk'
        if shortcut.exists():
            print(f"Suppression du raccourci: {shortcut}")
            shortcut.unlink()
    except:
        pass


def remove_service():
    """Supprimer le service système si installé."""
    if platform.system() == "Windows":
        try:
            import subprocess
            # Arrêter et supprimer le service Windows
            subprocess.run(['sc', 'stop', 'ADWebInterface'], capture_output=True)
            subprocess.run(['sc', 'delete', 'ADWebInterface'], capture_output=True)
            print("Service Windows supprimé")
        except:
            pass
    else:
        # Linux: supprimer le service systemd
        service_file = Path('/etc/systemd/system/ad-web-interface.service')
        if service_file.exists():
            try:
                import subprocess
                subprocess.run(['systemctl', 'stop', 'ad-web-interface'], capture_output=True)
                subprocess.run(['systemctl', 'disable', 'ad-web-interface'], capture_output=True)
                service_file.unlink()
                subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
                print("Service systemd supprimé")
            except Exception as e:
                print(f"Erreur suppression service: {e}")


def export_config(app_dir: Path):
    """Exporter la configuration avant désinstallation."""
    export_dir = Path.home() / 'ad-web-interface-backup'
    export_dir.mkdir(exist_ok=True)

    files_to_export = ['.env', 'data/api_keys.json']

    for filename in files_to_export:
        src = app_dir / filename
        if src.exists():
            dst = export_dir / filename.replace('/', '_')
            shutil.copy2(src, dst)
            print(f"  Exporté: {filename} -> {dst}")

    print(f"\nConfiguration sauvegardée dans: {export_dir}")
    return export_dir


def uninstall(complete: bool = False, keep_config: bool = False, export: bool = False):
    """
    Désinstaller l'application.

    Args:
        complete: Supprimer aussi les données utilisateur
        keep_config: Conserver le fichier .env
        export: Exporter la configuration avant suppression
    """
    app_dir = get_app_dir()

    print("\n" + "="*60)
    print("DÉSINSTALLATION DE AD WEB INTERFACE")
    print("="*60)
    print(f"\nRépertoire: {app_dir}")
    print(f"Mode: {'Complet' if complete else 'Standard'}")
    print(f"Conserver config: {'Oui' if keep_config else 'Non'}")
    print()

    # Exporter si demandé
    if export:
        print("Export de la configuration...")
        export_config(app_dir)
        print()

    # Arrêter le serveur
    stop_server()

    # Supprimer le service
    print("\nSuppression du service...")
    remove_service()

    # Supprimer les raccourcis
    print("\nSuppression des raccourcis...")
    remove_shortcuts()

    # Supprimer le cache
    print("\nSuppression du cache...")
    remove_cache(app_dir)

    # Supprimer l'environnement virtuel
    print("\nSuppression de l'environnement virtuel...")
    remove_venv(app_dir)

    # Supprimer les données si complet
    if complete:
        print("\nSuppression des données...")
        remove_data(keep_config)

    # Supprimer l'application
    print("\nSuppression des fichiers de l'application...")
    remove_app(app_dir, keep_config)

    print("\n" + "="*60)
    print("DÉSINSTALLATION TERMINÉE")
    print("="*60)

    if not complete:
        print("\nNote: Les données utilisateur ont été conservées.")
        print("Pour une suppression complète, relancez avec --complete")

    # Auto-suppression du script
    print("\nCe script sera supprimé automatiquement...")

    # Sur Windows, on ne peut pas supprimer un script en cours d'exécution
    # On crée un script batch pour le faire
    if platform.system() == "Windows":
        cleanup_bat = app_dir / 'cleanup.bat'
        with open(cleanup_bat, 'w') as f:
            f.write('@echo off\n')
            f.write('timeout /t 2 /nobreak > nul\n')
            f.write(f'del /q "{Path(__file__).resolve()}"\n')
            f.write(f'del /q "{cleanup_bat}"\n')
            f.write(f'rmdir /q "{app_dir}" 2>nul\n')

        import subprocess
        subprocess.Popen(
            ['cmd', '/c', str(cleanup_bat)],
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    else:
        # Sur Linux/macOS, on peut utiliser un processus détaché
        import subprocess
        subprocess.Popen(
            ['sh', '-c', f'sleep 2; rm -f "{Path(__file__).resolve()}"; rmdir "{app_dir}" 2>/dev/null'],
            start_new_session=True
        )


def main():
    """Point d'entrée principal."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Désinstallateur AD Web Interface',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Exemples:
  python uninstall.py                    # Désinstallation standard
  python uninstall.py --complete         # Supprime aussi les données
  python uninstall.py --export           # Exporte la config avant
  python uninstall.py --keep-config      # Conserve le fichier .env
  python uninstall.py --complete --export # Export + suppression totale
'''
    )

    parser.add_argument(
        '--complete', '-c',
        action='store_true',
        help='Suppression complète incluant les données utilisateur'
    )

    parser.add_argument(
        '--keep-config', '-k',
        action='store_true',
        help='Conserver le fichier de configuration .env'
    )

    parser.add_argument(
        '--export', '-e',
        action='store_true',
        help='Exporter la configuration avant suppression'
    )

    parser.add_argument(
        '--yes', '-y',
        action='store_true',
        help='Ne pas demander de confirmation'
    )

    args = parser.parse_args()

    # Confirmation
    if not args.yes:
        print("\n" + "!"*60)
        print("ATTENTION: Cette action va désinstaller AD Web Interface")
        if args.complete:
            print("Mode COMPLET: Toutes les données seront supprimées!")
        print("!"*60 + "\n")

        response = input("Êtes-vous sûr de vouloir continuer? [o/N]: ").strip().lower()
        if response not in ['o', 'oui', 'y', 'yes']:
            print("Désinstallation annulée.")
            sys.exit(0)

    # Exécuter la désinstallation
    uninstall(
        complete=args.complete,
        keep_config=args.keep_config,
        export=args.export
    )


if __name__ == "__main__":
    main()
