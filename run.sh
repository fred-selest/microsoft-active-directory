#!/bin/bash
# Script de demarrage Linux/macOS pour l'interface Web AD

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "======================================"
echo "  Interface Web Active Directory"
echo "======================================"
echo

# Verifier si Python 3 est disponible
if ! command -v python3 &> /dev/null; then
    echo "Erreur: Python 3 n'est pas installe."
    echo
    echo "Installez-le avec:"
    echo "  Ubuntu/Debian : sudo apt install python3 python3-pip python3-venv"
    echo "  Fedora/RHEL   : sudo dnf install python3 python3-pip"
    echo "  Arch Linux    : sudo pacman -S python"
    echo "  macOS         : brew install python3"
    exit 1
fi

# Creer l'environnement virtuel s'il est absent
if [ ! -d "venv" ]; then
    echo "Creation de l'environnement virtuel..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo
        echo "Erreur lors de la creation du venv."
        echo "Sur Ubuntu/Debian: sudo apt install python3-venv"
        exit 1
    fi
    echo "Environnement virtuel cree."
    echo
fi

# Activer le venv
source venv/bin/activate

# Installer les dependances si Flask est absent
if ! python3 -c "import flask" 2>/dev/null; then
    echo "Installation des dependances Python..."
    pip install -r requirements.txt --quiet
    if [ $? -ne 0 ]; then
        echo "Erreur lors de l'installation des dependances."
        exit 1
    fi
    echo "Dependances installees."
    echo
fi

# Demarrer l'application (cree .env automatiquement si absent)
python3 run.py
