#!/usr/bin/env python3
"""
Assistant d'installation pour l'interface Web Active Directory.
Guide l'administrateur à travers la configuration du serveur.
Installe automatiquement toutes les dépendances au bon endroit.
"""

import os
import sys
import secrets
import subprocess
import platform
import shutil

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

def print_success(message):
    """Afficher un message de succès."""
    print(f"  [OK] {message}")

def print_error(message):
    """Afficher un message d'erreur."""
    print(f"  [ERREUR] {message}")

def print_info(message):
    """Afficher un message d'information."""
    print(f"  [INFO] {message}")

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

def run_command(command, description=None, check=True, capture_output=False):
    """Exécuter une commande et gérer les erreurs."""
    if description:
        print(f"  {description}...")

    try:
        if capture_output:
            result = subprocess.run(command, check=check, capture_output=True, text=True)
            return result
        else:
            subprocess.run(command, check=check)
        return True
    except subprocess.CalledProcessError as e:
        return False
    except FileNotFoundError:
        return False

def check_python_version():
    """Vérifier la version de Python."""
    print_section("Vérification de Python")

    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"

    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print_error(f"Python {version_str} détecté. Python 3.8+ est requis.")
        return False

    print_success(f"Python {version_str} détecté")
    return True

def check_system_dependencies():
    """Vérifier et installer les dépendances système."""
    print_section("Vérification des dépendances système")

    system = platform.system()

    if system == "Linux":
        # Vérifier si python3-venv est installé
        try:
            subprocess.run([sys.executable, "-m", "venv", "--help"],
                         capture_output=True, check=True)
            print_success("Module venv disponible")
        except subprocess.CalledProcessError:
            print_error("Le module venv n'est pas installé")
            print_info("Installation requise: sudo apt install python3-venv")

            if ask_yes_no("Voulez-vous l'installer maintenant? (nécessite sudo)", True):
                result = run_command(
                    ["sudo", "apt", "install", "-y", "python3-venv", "python3-pip"],
                    "Installation de python3-venv"
                )
                if not result:
                    print_error("Échec de l'installation. Veuillez l'installer manuellement.")
                    return False
                print_success("python3-venv installé")
            else:
                return False

        # Vérifier pip
        try:
            subprocess.run([sys.executable, "-m", "pip", "--version"],
                         capture_output=True, check=True)
            print_success("pip disponible")
        except subprocess.CalledProcessError:
            print_info("Installation de pip...")
            if not run_command(["sudo", "apt", "install", "-y", "python3-pip"]):
                print_error("Échec de l'installation de pip")
                return False

    elif system == "Windows":
        # Sur Windows, venv est inclus avec Python
        print_success("Système Windows détecté")
        print_success("venv et pip inclus avec Python")

    elif system == "Darwin":  # macOS
        print_success("Système macOS détecté")
        # venv est généralement inclus avec Python sur macOS

    return True

def get_venv_paths():
    """Obtenir les chemins des exécutables dans le venv."""
    if platform.system() == "Windows":
        return {
            'python': os.path.join("venv", "Scripts", "python.exe"),
            'pip': os.path.join("venv", "Scripts", "pip.exe"),
            'activate': os.path.join("venv", "Scripts", "activate.bat")
        }
    else:
        return {
            'python': os.path.join("venv", "bin", "python"),
            'pip': os.path.join("venv", "bin", "pip"),
            'activate': os.path.join("venv", "bin", "activate")
        }

def create_virtual_env():
    """Créer l'environnement virtuel."""
    print_section("Création de l'environnement virtuel")

    if os.path.exists("venv"):
        if ask_yes_no("Un environnement virtuel existe déjà. Le recréer?", False):
            print_info("Suppression de l'ancien environnement virtuel...")
            shutil.rmtree("venv")
        else:
            print_info("Utilisation de l'environnement virtuel existant.")
            return True

    print_info("Création de l'environnement virtuel...")

    try:
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
        print_success("Environnement virtuel créé dans ./venv/")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Échec de la création: {e}")
        return False

def upgrade_pip():
    """Mettre à jour pip dans le venv."""
    paths = get_venv_paths()

    print_info("Mise à jour de pip...")
    try:
        subprocess.run(
            [paths['python'], "-m", "pip", "install", "--upgrade", "pip"],
            check=True,
            capture_output=True
        )
        print_success("pip mis à jour")
        return True
    except subprocess.CalledProcessError:
        print_info("Impossible de mettre à jour pip (non critique)")
        return True

def install_dependencies():
    """Installer les dépendances dans le venv."""
    print_section("Installation des dépendances Python")

    paths = get_venv_paths()

    # Vérifier que le venv existe
    if not os.path.exists(paths['pip']):
        print_error(f"pip non trouvé dans {paths['pip']}")
        return False

    # Mettre à jour pip d'abord
    upgrade_pip()

    # Installer les dépendances depuis requirements.txt
    print_info("Installation des packages depuis requirements.txt...")

    try:
        result = subprocess.run(
            [paths['pip'], "install", "-r", "requirements.txt"],
            check=True,
            capture_output=True,
            text=True
        )
        print_success("Toutes les dépendances installées")
    except subprocess.CalledProcessError as e:
        print_error(f"Échec de l'installation: {e.stderr}")
        return False

    # Vérifier l'installation des packages critiques
    print_info("Vérification des packages installés...")

    packages_to_check = ['flask', 'ldap3', 'python-dotenv']
    all_ok = True

    for package in packages_to_check:
        try:
            subprocess.run(
                [paths['pip'], "show", package],
                check=True,
                capture_output=True
            )
            print_success(f"{package} installé")
        except subprocess.CalledProcessError:
            print_error(f"{package} non trouvé")
            all_ok = False

    return all_ok

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
        with open(".env", "w", encoding="utf-8") as f:
            f.write(env_content)
        print_success("Fichier .env créé")
        return True
    except IOError as e:
        print_error(f"Échec de la création du fichier .env: {e}")
        return False

def create_data_directories():
    """Créer les répertoires de données."""
    print_section("Création des répertoires")

    dirs_to_create = ['logs', 'data']

    for dir_name in dirs_to_create:
        dir_path = os.path.join(os.getcwd(), dir_name)
        try:
            os.makedirs(dir_path, exist_ok=True)
            print_success(f"Répertoire {dir_name}/ créé")
        except OSError as e:
            print_info(f"Impossible de créer {dir_name}/: {e}")

    return True

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

def test_installation():
    """Tester que l'installation fonctionne."""
    print_section("Test de l'installation")

    paths = get_venv_paths()

    # Tester l'import de Flask
    print_info("Test d'import de Flask...")
    try:
        result = subprocess.run(
            [paths['python'], "-c", "from flask import Flask; print('OK')"],
            check=True,
            capture_output=True,
            text=True
        )
        print_success("Flask fonctionne correctement")
    except subprocess.CalledProcessError:
        print_error("Échec du test Flask")
        return False

    # Tester l'import de ldap3
    print_info("Test d'import de ldap3...")
    try:
        result = subprocess.run(
            [paths['python'], "-c", "from ldap3 import Server; print('OK')"],
            check=True,
            capture_output=True,
            text=True
        )
        print_success("ldap3 fonctionne correctement")
    except subprocess.CalledProcessError:
        print_error("Échec du test ldap3")
        return False

    return True

def main():
    """Fonction principale de l'assistant d'installation."""
    print_header()

    print("Cet assistant va installer et configurer le serveur.")
    print("Appuyez sur Entrée pour accepter les valeurs par défaut.\n")

    # Vérifications préliminaires
    if not check_python_version():
        return

    if not check_system_dependencies():
        return

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
    print_info("Clé secrète générée automatiquement")

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
        print_info("Vous pourrez configurer Active Directory via l'interface web.")

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

    # Installation
    steps = [
        ("Environnement virtuel", create_virtual_env),
        ("Dépendances Python", install_dependencies),
        ("Fichier de configuration", lambda: create_env_file(config)),
        ("Répertoires de données", create_data_directories),
        ("Test de l'installation", test_installation),
    ]

    for step_name, step_func in steps:
        if not step_func():
            print_error(f"Échec à l'étape: {step_name}")
            print("\nL'installation a échoué. Consultez les erreurs ci-dessus.")
            return

    # Instructions finales
    local_ip = get_local_ip()
    paths = get_venv_paths()

    print_section("Installation terminée avec succès!")

    print("\nStructure installée:")
    print("  ./venv/           - Environnement virtuel Python")
    print("  ./.env            - Configuration du serveur")
    print("  ./logs/           - Fichiers de logs")
    print("  ./data/           - Données de l'application")

    print("\n\nPour démarrer le serveur:\n")

    if platform.system() == "Windows":
        print("  run.bat")
        print("\n  ou manuellement:")
        print(f"  {paths['activate']}")
        print("  python run.py")
    else:
        print("  ./run.sh")
        print("\n  ou manuellement:")
        print(f"  source {paths['activate']}")
        print("  python run.py")

    print(f"\n\nURL d'accès pour les utilisateurs:")
    print(f"  http://{local_ip}:{config['port']}")
    print()

    if is_production:
        print("Note: Pour la production, configurez un reverse proxy (nginx)")
        print("      avec HTTPS pour sécuriser les connexions.")

    print("\n" + "=" * 60 + "\n")

if __name__ == "__main__":
    main()
