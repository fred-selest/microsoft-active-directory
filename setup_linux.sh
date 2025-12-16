#!/bin/bash
# Installation Simple - Linux/Ubuntu
set -e

echo "========================================"
echo "Installation AD Web Interface - Linux"
echo "========================================"
echo

# Verifier Python
if ! command -v python3 &> /dev/null; then
    echo "[ERREUR] Python3 non installe"
    echo
    echo "Installation:"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip python3-venv"
    echo "  Fedora:        sudo dnf install python3 python3-pip"
    echo "  Arch:          sudo pacman -S python python-pip"
    exit 1
fi

echo "[OK] Python detecte"
python3 --version
echo

# Verifier pip
if ! python3 -m pip --version &> /dev/null; then
    echo "[ERREUR] pip non installe"
    echo "Installation: sudo apt install python3-pip"
    exit 1
fi

# Verifier venv
if ! python3 -m venv --help &> /dev/null; then
    echo "[ERREUR] venv non disponible"
    echo "Installation: sudo apt install python3-venv"
    exit 1
fi

echo "[OK] pip et venv disponibles"
echo

# Creer venv
if [ -d "venv" ]; then
    echo "[INFO] Environnement virtuel existe"
else
    echo "Creation environnement virtuel..."
    python3 -m venv venv
    echo "[OK] Environnement virtuel cree"
fi
echo

# Activer et installer
echo "Installation dependances..."
source venv/bin/activate
python3 -m pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt
echo "[OK] Dependances installees"
echo

# Creer dossiers
mkdir -p logs data static/images
echo "[OK] Dossiers crees"
echo

# Creer .env
if [ ! -f ".env" ]; then
    echo "Generation de SECRET_KEY securisee..."
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    cat > .env << EOF
SECRET_KEY=$SECRET
FLASK_ENV=production
HOST=0.0.0.0
PORT=5000
EOF
    echo "[OK] Fichier .env cree avec SECRET_KEY aleatoire"
else
    echo "[INFO] Fichier .env existe deja"
fi
echo

# Rendre run.sh executable
chmod +x run.sh 2>/dev/null || true

echo "========================================"
echo "Installation terminee!"
echo "========================================"
echo
echo "Pour demarrer:"
echo "  ./run.sh"
echo
echo "Ou manuellement:"
echo "  source venv/bin/activate"
echo "  python3 run.py"
echo
echo "Acces: http://localhost:5000"
echo
