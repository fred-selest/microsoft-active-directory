# Installation sur Ubuntu/Linux

## Installation rapide

```bash
# 1. Installer les dépendances système
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git

# 2. Cloner le projet
cd ~
git clone https://github.com/fred-selest/microsoft-active-directory.git
cd microsoft-active-directory

# 3. Lancer l'installation interactive
python3 install.py
```

## Installation manuelle

Si l'assistant install.py ne fonctionne pas :

```bash
# 1. Créer environnement virtuel
python3 -m venv venv

# 2. Activer l'environnement
source venv/bin/activate

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Créer le fichier .env
cat > .env << EOF
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
FLASK_ENV=production
HOST=0.0.0.0
PORT=5000
EOF

# 5. Créer les dossiers
mkdir -p logs data static/images

# 6. Lancer le serveur
python3 run.py
```

## Lancement rapide

Après installation :

```bash
./run.sh
```

Ou :

```bash
source venv/bin/activate
python3 run.py
```

## Accès

Ouvrez votre navigateur :
- Local: http://localhost:5000
- Réseau: http://VOTRE_IP:5000

## Problèmes courants

### "ModuleNotFoundError: No module named 'flask'"
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### "python3-venv n'est pas disponible"
```bash
sudo apt install python3-venv
```

### Port 5000 déjà utilisé
Modifiez PORT dans .env ou lancez avec :
```bash
PORT=8080 python3 run.py
```
