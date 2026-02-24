#!/bin/bash
# Script de demarrage Linux/macOS pour l'interface Web AD

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "======================================"
echo "  Interface Web Active Directory"
echo "======================================"
echo

# --- Fonction : installer Python selon le gestionnaire de paquets ---
install_python() {
    echo "Tentative d'installation automatique de Python 3..."
    echo

    if command -v apt-get &>/dev/null; then
        echo "Gestionnaire detecte: apt"
        sudo apt-get update -qq && sudo apt-get install -y python3 python3-pip python3-venv

    elif command -v dnf &>/dev/null; then
        echo "Gestionnaire detecte: dnf"
        sudo dnf install -y python3 python3-pip

    elif command -v yum &>/dev/null; then
        echo "Gestionnaire detecte: yum"
        sudo yum install -y python3 python3-pip

    elif command -v pacman &>/dev/null; then
        echo "Gestionnaire detecte: pacman"
        sudo pacman -S --noconfirm python python-pip

    elif command -v brew &>/dev/null; then
        echo "Gestionnaire detecte: Homebrew"
        brew install python3

    else
        echo "[ERREUR] Aucun gestionnaire de paquets reconnu."
        echo "Installez Python manuellement:"
        echo "  Ubuntu/Debian : sudo apt install python3 python3-pip python3-venv"
        echo "  Fedora/RHEL   : sudo dnf install python3 python3-pip"
        echo "  Arch Linux    : sudo pacman -S python python-pip"
        echo "  macOS         : brew install python3"
        return 1
    fi

    if ! command -v python3 &>/dev/null; then
        echo "[ERREUR] Python 3 toujours absent apres installation."
        return 1
    fi

    echo "[OK] Python 3 installe avec succes."
    return 0
}

# --- Verifier si Python 3 est disponible ---
if ! command -v python3 &>/dev/null; then
    echo "[INFO] Python 3 n'est pas installe."
    echo

    read -r -p "Installer Python 3 automatiquement ? [O/n]: " ANSWER
    ANSWER=${ANSWER:-O}

    case "$ANSWER" in
        [OoYy]*)
            install_python || exit 1
            ;;
        *)
            echo "Installation annulee."
            echo "Installez Python 3 puis relancez run.sh."
            exit 1
            ;;
    esac
    echo
fi

# --- Verifier que python3-venv est disponible ---
if ! python3 -m venv --help &>/dev/null; then
    echo "[INFO] Le module venv est absent. Installation..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y python3-venv
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y python3-pip
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm python-virtualenv
    else
        echo "[ERREUR] Impossible d'installer python3-venv automatiquement."
        echo "Essayez: sudo apt install python3-venv"
        exit 1
    fi
fi

# --- Creer le venv s'il est absent ---
if [ ! -d "venv" ]; then
    echo "Creation de l'environnement virtuel..."
    python3 -m venv venv || { echo "[ERREUR] Echec creation venv."; exit 1; }
    echo "[OK] Environnement virtuel cree."
    echo
fi

# --- Activer le venv ---
source venv/bin/activate

# --- Installer les dependances si Flask est absent ---
if ! python3 -c "import flask" 2>/dev/null; then
    echo "Installation des dependances Python..."
    pip install -r requirements.txt --quiet || { echo "[ERREUR] Echec installation des dependances."; exit 1; }
    echo "[OK] Dependances installees."
    echo
fi

# --- Demarrer l'application (cree .env automatiquement si absent) ---
python3 run.py
