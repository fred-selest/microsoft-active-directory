#!/bin/bash
# Script d'installation pour Linux/macOS
# Télécharge le projet depuis GitHub, installe Python si nécessaire, et configure le serveur

echo "======================================================"
echo "  Installation - Interface Web Active Directory"
echo "======================================================"
echo

# Variables
GITHUB_REPO="fred-selest/microsoft-active-directory"
BRANCH="claude/cross-platform-web-interface-017bbfitWFZ7Ndcg51ZZUzC2"
PROJECT_DIR="microsoft-active-directory"

# Fonction pour demander confirmation
ask_yes_no() {
    local prompt="$1"
    local default="$2"
    local answer

    if [ "$default" = "y" ]; then
        prompt="$prompt [O/n]: "
    else
        prompt="$prompt [o/N]: "
    fi

    read -p "$prompt" answer
    answer=${answer:-$default}

    case "$answer" in
        [OoYy]* ) return 0 ;;
        * ) return 1 ;;
    esac
}

# Vérifier si nous sommes déjà dans le dossier du projet
if [ -f "install.py" ]; then
    echo "Fichiers du projet détectés."
else
    # Télécharger le projet depuis GitHub
    echo "Téléchargement du projet depuis GitHub..."
    echo

    # Vérifier si Git est installé
    if command -v git &> /dev/null; then
        echo "Git détecté. Clonage du repository..."
        if git clone -b "$BRANCH" "https://github.com/$GITHUB_REPO.git"; then
            cd "$PROJECT_DIR"
        else
            echo "Erreur lors du clonage. Tentative de téléchargement ZIP..."
            DOWNLOAD_ZIP=true
        fi
    else
        DOWNLOAD_ZIP=true
    fi

    # Télécharger le ZIP si nécessaire
    if [ "$DOWNLOAD_ZIP" = true ]; then
        echo "Téléchargement du projet en ZIP..."

        # Créer un répertoire temporaire
        TEMP_DIR=$(mktemp -d)
        ZIP_URL="https://github.com/$GITHUB_REPO/archive/refs/heads/$BRANCH.zip"

        # Télécharger avec curl ou wget
        if command -v curl &> /dev/null; then
            curl -L -o "$TEMP_DIR/project.zip" "$ZIP_URL"
        elif command -v wget &> /dev/null; then
            wget -O "$TEMP_DIR/project.zip" "$ZIP_URL"
        else
            echo "Erreur: curl ou wget requis pour télécharger le projet."
            echo "Installez curl: sudo apt install curl"
            exit 1
        fi

        if [ ! -f "$TEMP_DIR/project.zip" ]; then
            echo "Erreur: Impossible de télécharger le projet."
            echo "Vérifiez votre connexion internet."
            rm -rf "$TEMP_DIR"
            exit 1
        fi

        echo "Extraction des fichiers..."

        # Extraire le ZIP
        unzip -q "$TEMP_DIR/project.zip" -d "$TEMP_DIR/extracted"

        # Trouver le dossier extrait
        EXTRACTED_DIR=$(ls -d "$TEMP_DIR/extracted"/*/ | head -1)

        # Vérifier si le dossier existe déjà
        if [ -d "$PROJECT_DIR" ]; then
            if ask_yes_no "Le dossier $PROJECT_DIR existe déjà. Le remplacer?" "n"; then
                rm -rf "$PROJECT_DIR"
            else
                echo "Installation annulée."
                rm -rf "$TEMP_DIR"
                exit 0
            fi
        fi

        # Déplacer le dossier extrait
        mv "$EXTRACTED_DIR" "$PROJECT_DIR"

        echo "Fichiers extraits dans $PROJECT_DIR"
        cd "$PROJECT_DIR"

        # Nettoyer
        rm -rf "$TEMP_DIR"
    fi
fi

# Détecter le gestionnaire de paquets
detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        echo "apt"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v yum &> /dev/null; then
        echo "yum"
    elif command -v pacman &> /dev/null; then
        echo "pacman"
    elif command -v brew &> /dev/null; then
        echo "brew"
    else
        echo "unknown"
    fi
}

# Installer Python selon le système
install_python() {
    local pkg_manager=$(detect_package_manager)

    echo "Gestionnaire de paquets détecté: $pkg_manager"
    echo

    case "$pkg_manager" in
        apt)
            echo "Installation de Python 3 avec apt..."
            sudo apt update
            sudo apt install -y python3 python3-pip python3-venv
            ;;
        dnf)
            echo "Installation de Python 3 avec dnf..."
            sudo dnf install -y python3 python3-pip python3-virtualenv
            ;;
        yum)
            echo "Installation de Python 3 avec yum..."
            sudo yum install -y python3 python3-pip python3-virtualenv
            ;;
        pacman)
            echo "Installation de Python 3 avec pacman..."
            sudo pacman -S --noconfirm python python-pip python-virtualenv
            ;;
        brew)
            echo "Installation de Python 3 avec Homebrew..."
            brew install python3
            ;;
        *)
            echo "Erreur: Gestionnaire de paquets non reconnu."
            echo "Veuillez installer Python 3 manuellement."
            return 1
            ;;
    esac

    return $?
}

# Vérifier si Python 3 est installé
if ! command -v python3 &> /dev/null; then
    echo "Python 3 n'est pas installé sur ce système."
    echo

    if ask_yes_no "Voulez-vous installer Python 3 automatiquement?" "y"; then
        echo
        install_python

        if [ $? -ne 0 ]; then
            echo
            echo "Échec de l'installation de Python."
            echo "Veuillez l'installer manuellement et relancer ce script."
            exit 1
        fi

        echo
        echo "Python 3 installé avec succès!"
        echo
    else
        echo
        echo "Installation annulée."
        echo
        echo "Pour installer Python 3 manuellement:"
        echo "  Ubuntu/Debian : sudo apt install python3 python3-pip python3-venv"
        echo "  CentOS/RHEL   : sudo yum install python3 python3-pip"
        echo "  Fedora        : sudo dnf install python3 python3-pip"
        echo "  Arch Linux    : sudo pacman -S python python-pip"
        echo "  macOS         : brew install python3"
        exit 1
    fi
fi

# Vérifier la version de Python
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')
echo "Python $PYTHON_VERSION détecté"
echo

# Vérifier pip
if ! python3 -m pip --version &> /dev/null; then
    echo "pip n'est pas installé."

    if ask_yes_no "Voulez-vous installer pip?" "y"; then
        pkg_manager=$(detect_package_manager)
        case "$pkg_manager" in
            apt)
                sudo apt install -y python3-pip
                ;;
            dnf)
                sudo dnf install -y python3-pip
                ;;
            yum)
                sudo yum install -y python3-pip
                ;;
            pacman)
                sudo pacman -S --noconfirm python-pip
                ;;
            brew)
                # pip est inclus avec Python sur Homebrew
                ;;
            *)
                echo "Veuillez installer pip manuellement."
                exit 1
                ;;
        esac
    else
        exit 1
    fi
fi

# Vérifier venv
if ! python3 -m venv --help &> /dev/null; then
    echo "Le module venv n'est pas disponible."

    if ask_yes_no "Voulez-vous l'installer?" "y"; then
        pkg_manager=$(detect_package_manager)
        case "$pkg_manager" in
            apt)
                sudo apt install -y python3-venv
                ;;
            dnf)
                sudo dnf install -y python3-virtualenv
                ;;
            yum)
                sudo yum install -y python3-virtualenv
                ;;
            *)
                echo "Veuillez installer python3-venv manuellement."
                exit 1
                ;;
        esac
    else
        exit 1
    fi
fi

# Lancer l'assistant d'installation
python3 install.py
