#!/usr/bin/env python3
"""
Lanceur multi-plateforme pour l'interface Web AD.
Détecte automatiquement le système d'exploitation et utilise le serveur approprié.
"""

import os
import sys
import platform
import secrets
import logging


def ensure_env_file():
    """Créer un fichier .env minimal avec des valeurs par défaut sûres si absent."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    env_file = os.path.join(script_dir, '.env')

    if not os.path.exists(env_file):
        secret_key = secrets.token_hex(32)
        content = (
            "# Configuration générée automatiquement au premier démarrage\n"
            "# Modifiez ce fichier pour configurer votre serveur Active Directory\n"
            "#\n"
            "# Pour la production, définissez FLASK_ENV=production et FLASK_DEBUG=false\n"
            "# et activez FORCE_HTTPS=true avec un reverse proxy HTTPS.\n"
            "\n"
            f"SECRET_KEY={secret_key}\n"
            "FLASK_DEBUG=false\n"
            "FLASK_ENV=production\n"
            "\n"
            "AD_WEB_HOST=0.0.0.0\n"
            "AD_WEB_PORT=5000\n"
            "\n"
            "# Laissez vide pour configurer via l'interface web\n"
            "AD_SERVER=\n"
            "AD_PORT=389\n"
            "AD_USE_SSL=false\n"
            "AD_BASE_DN=\n"
            "\n"
            "# Désactivé pour un accès local en HTTP\n"
            "FORCE_HTTPS=false\n"
            "SESSION_COOKIE_SECURE=false\n"
            "\n"
            "RBAC_ENABLED=true\n"
            "DEFAULT_ROLE=reader\n"
            "SESSION_TIMEOUT=30\n"
            "ITEMS_PER_PAGE=25\n"
        )
        try:
            with open(env_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print("=" * 50)
            print("[INFO] Fichier .env créé automatiquement.")
            print("[INFO] Modifiez .env pour configurer votre serveur AD.")
            print(f"[INFO] Chemin: {env_file}")
            print("=" * 50)
        except IOError as e:
            print(f"[ATTENTION] Impossible de créer .env: {e}")


def main():
    # S'assurer que nous sommes dans le bon répertoire
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # Créer .env automatiquement s'il n'existe pas
    ensure_env_file()

    # Charger les variables d'environnement depuis .env si le fichier existe
    env_file = os.path.join(script_dir, '.env')
    if os.path.exists(env_file):
        try:
            from dotenv import load_dotenv
            # Spécifier l'encodage UTF-8 pour éviter les erreurs sur Windows
            load_dotenv(env_file, encoding='utf-8')
            print(f"Configuration chargée depuis {env_file}")
        except ImportError:
            print("Note: python-dotenv non installé, fichier .env non chargé")
        except UnicodeDecodeError:
            # Si le fichier a un mauvais encodage, essayer avec l'encodage système
            print("Avertissement: Fichier .env avec encodage incorrect, tentative de lecture...")
            try:
                load_dotenv(env_file, encoding='latin-1')
                print(f"Configuration chargée depuis {env_file} (encodage latin-1)")
            except Exception as e:
                print(f"Erreur lors du chargement de .env: {e}")

    # Configurer le logging vers fichier (fonctionne aussi avec pythonw.exe sans console)
    log_dir = os.path.join(script_dir, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'server.log')
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        root_logger.setLevel(logging.INFO)
        fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setFormatter(fmt)
        root_logger.addHandler(fh)
        if sys.stdout is not None:
            sh = logging.StreamHandler(sys.stdout)
            sh.setFormatter(fmt)
            root_logger.addHandler(sh)
    logging.info("=== Démarrage serveur AD Web Interface ===")

    # Importer et démarrer l'application
    from app import run_server
    run_server()


if __name__ == '__main__':
    main()
