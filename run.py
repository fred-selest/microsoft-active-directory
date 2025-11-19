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

    # Importer et démarrer l'application
    from app import run_server
    run_server()


if __name__ == '__main__':
    main()
