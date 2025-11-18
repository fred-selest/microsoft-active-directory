#!/usr/bin/env python3
"""
Assistant d'installation pour l'interface Web Active Directory.
Guide l'administrateur à travers la configuration du serveur.
"""

import os
import sys
import secrets
import subprocess
import platform

def print_header():
    """Afficher l'en-tête de l'assistant."""
    print("\n" + "=" * 60)
    print("  ASSISTANT D'INSTALLATION")
    print("  Interface Web Active Directory")
    print("=" * 60)
    print()

def print_section(title):
    """Afficher un titre de section."""
    print(f"\n--- {title} ---\n")

def ask_question(question, default=None, required=False):
    """Poser une question à l'utilisateur."""
    if default:
        prompt = f"{question} [{default}]: "
    else:
        prompt = f"{question}: "

    while True:
        answer = input(prompt).strip()

        if not answer and default:
            return default
        elif not answer and required:
            print("Cette valeur est requise.")
            continue
        elif not answer:
            return ""
        else:
            return answer

def ask_yes_no(question, default=True):
    """Poser une question oui/non."""
    default_str = "O/n" if default else "o/N"
    prompt = f"{question} [{default_str}]: "

    answer = input(prompt).strip().lower()

    if not answer:
        return default
    return answer in ['o', 'oui', 'y', 'yes']

def ask_port(question, default):
    """Demander un numéro de port."""
    while True:
        answer = ask_question(question, str(default))
        try:
            port = int(answer)
            if 1 <= port <= 65535:
                return port
            else:
                print("Le port doit être entre 1 et 65535.")
        except ValueError:
            print("Veuillez entrer un nombre valide.")

def generate_secret_key():
    """Générer une clé secrète sécurisée."""
    return secrets.token_hex(32)

def create_virtual_env():
    """Créer l'environnement virtuel."""
    print_section("Création de l'environnement virtuel")

    if os.path.exists("venv"):
        if ask_yes_no("Un environnement virtuel existe déjà. Le recréer?", False):
            import shutil
            shutil.rmtree("venv")
        else:
            print("Utilisation de l'environnement virtuel existant.")
            return True

    print("Création de l'environnement virtuel...")
    try:
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
        print("Environnement virtuel créé avec succès.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de la création de l'environnement virtuel: {e}")
        return False

def install_dependencies():
    """Installer les dépendances."""
    print_section("Installation des dépendances")

    # Déterminer le chemin de pip dans le venv
    if platform.system() == "Windows":
        pip_path = os.path.join("venv", "Scripts", "pip")
    else:
        pip_path = os.path.join("venv", "bin", "pip")

    print("Installation des dépendances Python...")
    try:
        subprocess.run([pip_path, "install", "-r", "requirements.txt"], check=True)
        print("Dépendances installées avec succès.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'installation des dépendances: {e}")
        return False

def create_env_file(config):
    """Créer le fichier .env avec la configuration."""
    print_section("Création du fichier de configuration")

    env_content = f"""# Configuration du serveur
# Généré par l'assistant d'installation
AD_WEB_HOST={config['host']}
AD_WEB_PORT={config['port']}

# Configuration Flask
SECRET_KEY={config['secret_key']}
FLASK_ENV={config['flask_env']}
FLASK_DEBUG={str(config['debug']).lower()}

# Configuration Active Directory
AD_SERVER={config['ad_server']}
AD_PORT={config['ad_port']}
AD_USE_SSL={str(config['ad_use_ssl']).lower()}
AD_BASE_DN={config['ad_base_dn']}
"""

    try:
        with open(".env", "w") as f:
            f.write(env_content)
        print("Fichier .env créé avec succès.")
        return True
    except IOError as e:
        print(f"Erreur lors de la création du fichier .env: {e}")
        return False

def get_local_ip():
    """Obtenir l'adresse IP locale."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "VOTRE_IP"

def main():
    """Fonction principale de l'assistant d'installation."""
    print_header()

    print("Cet assistant va vous guider dans la configuration du serveur.")
    print("Appuyez sur Entrée pour accepter les valeurs par défaut.\n")

    config = {}

    # Configuration du serveur web
    print_section("Configuration du serveur web")

    config['host'] = '0.0.0.0'  # Toujours 0.0.0.0 pour l'accès réseau
    config['port'] = ask_port("Port du serveur web", 5000)

    # Environnement
    is_production = ask_yes_no("Est-ce une installation de production?", False)
    config['flask_env'] = 'production' if is_production else 'development'
    config['debug'] = not is_production

    # Clé secrète
    config['secret_key'] = generate_secret_key()
    print(f"\nClé secrète générée automatiquement.")

    # Configuration Active Directory
    print_section("Configuration Active Directory (optionnel)")

    configure_ad = ask_yes_no("Configurer le serveur AD maintenant?", False)

    if configure_ad:
        config['ad_server'] = ask_question("Adresse du serveur AD", "")
        config['ad_port'] = ask_port("Port LDAP", 389)
        config['ad_use_ssl'] = ask_yes_no("Utiliser SSL/TLS (LDAPS)?", False)
        config['ad_base_dn'] = ask_question("Base DN (ex: DC=exemple,DC=com)", "")
    else:
        config['ad_server'] = ""
        config['ad_port'] = 389
        config['ad_use_ssl'] = False
        config['ad_base_dn'] = ""
        print("Vous pourrez configurer Active Directory plus tard via l'interface web.")

    # Résumé
    print_section("Résumé de la configuration")
    print(f"  Port du serveur     : {config['port']}")
    print(f"  Environnement       : {config['flask_env']}")
    if config['ad_server']:
        print(f"  Serveur AD          : {config['ad_server']}:{config['ad_port']}")
        print(f"  SSL/TLS             : {'Oui' if config['ad_use_ssl'] else 'Non'}")
        if config['ad_base_dn']:
            print(f"  Base DN             : {config['ad_base_dn']}")
    else:
        print("  Serveur AD          : Non configuré")

    print()
    if not ask_yes_no("Procéder à l'installation?", True):
        print("\nInstallation annulée.")
        return

    # Création de l'environnement virtuel
    if not create_virtual_env():
        print("\nÉchec de la création de l'environnement virtuel.")
        return

    # Installation des dépendances
    if not install_dependencies():
        print("\nÉchec de l'installation des dépendances.")
        return

    # Création du fichier .env
    if not create_env_file(config):
        print("\nÉchec de la création du fichier de configuration.")
        return

    # Instructions finales
    local_ip = get_local_ip()

    print_section("Installation terminée!")
    print("Pour démarrer le serveur :\n")

    if platform.system() == "Windows":
        print("  run.bat")
        print("  ou")
        print("  venv\\Scripts\\activate && python run.py")
    else:
        print("  ./run.sh")
        print("  ou")
        print("  source venv/bin/activate && python run.py")

    print(f"\n\nURL d'accès pour les utilisateurs :")
    print(f"  http://{local_ip}:{config['port']}")
    print()

    if is_production:
        print("Note: Pour la production, configurez un reverse proxy (nginx)")
        print("      avec HTTPS pour sécuriser les connexions.")

    print("\n" + "=" * 60 + "\n")

if __name__ == "__main__":
    main()
