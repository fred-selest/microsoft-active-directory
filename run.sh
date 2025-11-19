#!/bin/bash
# Script de demarrage Linux/macOS pour l'interface Web AD

echo "Demarrage de l'interface Web AD sur Linux/macOS..."
echo

# Obtenir le repertoire du script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Verifier si Python est disponible
if ! command -v python3 &> /dev/null; then
    echo "Erreur: Python 3 n'est pas installe"
    echo "Veuillez installer Python 3: sudo apt install python3 python3-pip"
    exit 1
fi

# Verifier si l'environnement virtuel existe
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "Environnement virtuel active"
else
    echo "Note: Aucun environnement virtuel trouve. Utilisation du Python systeme."
    echo "Pour creer un venv: python3 -m venv venv"
fi

# Installer les dependances si necessaire
if ! python3 -c "import flask" 2>/dev/null; then
    echo "Installation des dependances..."
    pip3 install -r requirements.txt
fi

# Demarrer l'application
python3 run.py
