# Interface Web Active Directory

Interface web pour Microsoft Active Directory. Les utilisateurs accèdent simplement via leur navigateur web.

## Pour les utilisateurs (clients)

**Aucune installation requise !** Ouvrez simplement votre navigateur et accédez à :

```
http://ADRESSE_DU_SERVEUR:5000
```

Exemples :
- Réseau local : `http://192.168.1.100:5000`
- Nom d'hôte : `http://serveur-ad.entreprise.local:5000`
- Avec domaine : `https://ad.monentreprise.com`

L'interface fonctionne sur **tous les systèmes** (Windows, Linux, macOS, tablettes, smartphones).

---

## Installation rapide

### 🪟 Windows

1. Téléchargez le projet : https://github.com/fred-selest/microsoft-active-directory/archive/refs/heads/main.zip
2. Décompressez
3. Double-cliquez sur `setup_windows.bat`
4. Lancez avec `run.bat` (ou `run_legacy.bat` si Python 3.12+)

### 🐧 Linux / Ubuntu

```bash
# Cloner le projet
git clone https://github.com/fred-selest/microsoft-active-directory.git
cd microsoft-active-directory

# Installer
chmod +x setup_linux.sh
./setup_linux.sh

# Lancer
./run.sh
```

**Ou installation manuelle rapide :**

```bash
cd microsoft-active-directory
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Créer .env avec SECRET_KEY sécurisée
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
echo "FLASK_ENV=production" >> .env
echo "HOST=0.0.0.0" >> .env
echo "PORT=5000" >> .env

# Lancer
python3 run.py
```

---

## Accès

Une fois lancé, ouvrez votre navigateur :
- **Local :** http://localhost:5000
- **Réseau :** http://VOTRE_IP:5000

Trouvez votre IP :
- **Linux :** `hostname -I` ou `ip addr`
- **Windows :** `ipconfig`

---

## Configuration

Le fichier `.env` contient la configuration :

```ini
SECRET_KEY=votre-cle-secrete-aleatoire-64-caracteres
FLASK_ENV=production
HOST=0.0.0.0
PORT=5000
```

**⚠️ IMPORTANT :** Changez `SECRET_KEY` en production !

Générez une clé sécurisée :
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## Problèmes courants

### Erreur MD4 (Python 3.12+)

**Windows :** Utilisez `run_legacy.bat`

**Linux :** Consultez `README_MD4.md`

### Port 5000 déjà utilisé

Modifiez `PORT=8080` dans `.env`

### python3-venv introuvable (Ubuntu)

```bash
sudo apt install python3-venv
```

---

## Déploiement production

### Avec Gunicorn (Linux)

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 'app:app'
```

### Avec reverse proxy NGINX + HTTPS

```nginx
server {
    listen 443 ssl;
    server_name ad.monentreprise.com;

    ssl_certificate /chemin/vers/cert.pem;
    ssl_certificate_key /chemin/vers/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Fonctionnalités

- ✅ Connexion LDAP/LDAPS à Active Directory
- ✅ Gestion utilisateurs, groupes, ordinateurs
- ✅ Recherche avancée
- ✅ Interface responsive (desktop, tablette, mobile)
- ✅ Multi-plateforme (Windows, Linux)
- ✅ Support Python 3.12+ (avec run_legacy.bat)

---

## Sécurité

- 🔒 Utilisez HTTPS en production (reverse proxy)
- 🔒 Changez `SECRET_KEY` (64 caractères minimum)
- 🔒 Utilisez LDAPS (port 636) pour Active Directory
- 🔒 Activez le pare-feu et limitez l'accès réseau

---

## Documentation

- `INSTALLATION.md` - Guide d'installation détaillé
- `INSTALL_UBUNTU.md` - Installation Linux spécifique
- `README_MD4.md` - Correction erreur MD4 Python 3.12+

---

## Structure du projet

```
microsoft-active-directory/
├── app.py                  # Application Flask principale
├── run.py                  # Point d'entrée
├── config.py               # Configuration
├── requirements.txt        # Dépendances Python
├── routes/                 # Routes Flask (blueprints)
├── templates/              # Pages HTML (Jinja2)
├── static/                 # CSS, JavaScript, images
├── setup_windows.bat       # Installation Windows
├── setup_linux.sh          # Installation Linux
├── run.bat / run.sh        # Scripts de lancement
└── run_legacy.bat          # Lancement avec MD4 (Python 3.12+)
```

---

## Licence

MIT
