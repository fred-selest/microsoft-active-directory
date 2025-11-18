#!/bin/bash
# Script d'installation pour Linux/macOS
# Lance l'assistant d'installation interactif

echo "======================================================"
echo "  Installation - Interface Web Active Directory"
echo "======================================================"
echo

# Obtenir le répertoire du script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Vérifier si Python 3 est installé
if ! command -v python3 &> /dev/null; then
    echo "Erreur: Python 3 n'est pas installé."
    echo ""
    echo "Pour installer Python 3 :"
    echo "  Ubuntu/Debian : sudo apt install python3 python3-pip python3-venv"
    echo "  CentOS/RHEL   : sudo yum install python3 python3-pip"
    echo "  macOS         : brew install python3"
    echo ""
    exit 1
fi

# Vérifier la version de Python
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Python $PYTHON_VERSION détecté"
echo

# Lancer l'assistant d'installation
python3 install.py
