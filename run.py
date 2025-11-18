#!/usr/bin/env python3
"""
Lanceur multi-plateforme pour l'interface Web AD.
Détecte automatiquement le système d'exploitation et utilise le serveur approprié.
"""

import os
import sys
import platform

def main():
    # S'assurer que nous sommes dans le bon répertoire
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # Charger les variables d'environnement depuis .env si le fichier existe
    env_file = os.path.join(script_dir, '.env')
    if os.path.exists(env_file):
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file)
            print(f"Configuration chargée depuis {env_file}")
        except ImportError:
            print("Note: python-dotenv non installé, fichier .env non chargé")

    # Importer et démarrer l'application
    from app import run_server
    run_server()


if __name__ == '__main__':
    main()
