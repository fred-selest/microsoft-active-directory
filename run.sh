#!/bin/bash
# Script de démarrage Linux/macOS pour l'interface Web AD

echo "Démarrage de l'interface Web AD sur Linux/macOS..."
echo

# Obtenir le répertoire du script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Vérifier si Python est disponible
if ! command -v python3 &> /dev/null; then
    echo "Erreur: Python 3 n'est pas installé"
    echo "Veuillez installer Python 3: sudo apt install python3 python3-pip"
    exit 1
fi

# Vérifier si l'environnement virtuel existe
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "Environnement virtuel activé"
else
    echo "Note: Aucun environnement virtuel trouvé. Utilisation du Python système."
    echo "Pour créer un venv: python3 -m venv venv"
fi

# Installer les dépendances si nécessaire
if ! python3 -c "import flask" 2>/dev/null; then
    echo "Installation des dépendances..."
    pip3 install -r requirements.txt
fi

# Démarrer l'application
python3 run.py
