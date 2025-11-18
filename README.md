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

## Pour les administrateurs (installation du serveur)

### Prérequis

- Un serveur (Windows ou Linux)
- Python 3.8+
- Accès réseau au serveur Active Directory

### Installation rapide

```bash
# 1. Cloner le projet
git clone <url-du-repo>
cd microsoft-active-directory

# 2. Créer un environnement virtuel
python -m venv venv

# 3. Activer l'environnement
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 4. Installer les dépendances
pip install -r requirements.txt

# 5. Configurer (optionnel)
cp .env.example .env
# Éditer .env selon vos besoins

# 6. Démarrer le serveur
python run.py
```

### Démarrage automatique

**Linux/macOS :**
```bash
./run.sh
```

**Windows :**
```cmd
run.bat
```

### Configuration du serveur

Créez un fichier `.env` à partir de l'exemple :

```bash
cp .env.example .env
```

| Variable | Description | Défaut |
|----------|-------------|--------|
| `AD_WEB_HOST` | Adresse d'écoute (`0.0.0.0` = tous) | `0.0.0.0` |
| `AD_WEB_PORT` | Port d'écoute | `5000` |
| `SECRET_KEY` | Clé secrète (à changer !) | (défaut) |

### Trouver l'adresse du serveur

**Linux :**
```bash
ip addr
# ou
hostname -I
```

**Windows :**
```cmd
ipconfig
```

Communiquez cette adresse à vos utilisateurs : `http://VOTRE_IP:5000`

### Déploiement en production

#### Linux (avec Gunicorn)

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

#### Windows (avec Waitress)

```bash
pip install waitress
set FLASK_ENV=production
python run.py
```

#### Avec un nom de domaine (recommandé)

Configurez un reverse proxy (nginx ou Apache) pour :
- Utiliser HTTPS (certificat SSL)
- Utiliser un nom de domaine convivial
- Exemple : `https://ad.monentreprise.com`

**Exemple nginx :**
```nginx
server {
    listen 443 ssl;
    server_name ad.monentreprise.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Fonctionnalités

- **Connexion LDAP/LDAPS** à Active Directory
- **Recherche** d'utilisateurs, groupes et ordinateurs
- **Interface responsive** (desktop, tablette, mobile)
- **Multi-plateforme** (serveur Windows ou Linux)

## Sécurité

- Définissez un `SECRET_KEY` sécurisé en production
- Utilisez HTTPS avec un reverse proxy
- Utilisez LDAPS (port 636) pour les connexions AD sécurisées

## Structure du projet

```
microsoft-active-directory/
├── app.py              # Application principale
├── config.py           # Configuration
├── run.py / run.sh / run.bat  # Scripts de démarrage
├── requirements.txt    # Dépendances
├── templates/          # Pages HTML
└── static/             # CSS et JavaScript
```

## Licence

MIT
