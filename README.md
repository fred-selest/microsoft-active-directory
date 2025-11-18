# Microsoft Active Directory Web Interface

Interface web cross-platform pour Microsoft Active Directory. Fonctionne sur **Windows** et **Linux** sans modification.

## Caractéristiques

- **Cross-platform** : Fonctionne sur Windows et Linux
- **Accès réseau** : Liaison sur `0.0.0.0` pour permettre l'accès depuis n'importe quel appareil
- **LDAP/LDAPS** : Support des connexions sécurisées SSL/TLS
- **Interface responsive** : Accessible depuis desktop et mobile

## Installation

### Prérequis

- Python 3.8+
- pip

### Installation des dépendances

```bash
# Créer un environnement virtuel (recommandé)
python -m venv venv

# Activer l'environnement virtuel
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt
```

## Démarrage

### Linux/macOS

```bash
chmod +x run.sh
./run.sh
```

Ou directement :
```bash
python run.py
```

### Windows

Double-cliquez sur `run.bat` ou exécutez :
```cmd
python run.py
```

## Configuration

Copiez `.env.example` vers `.env` et modifiez les valeurs :

```bash
cp .env.example .env
```

### Variables d'environnement

| Variable | Description | Défaut |
|----------|-------------|--------|
| `AD_WEB_HOST` | Adresse IP d'écoute | `0.0.0.0` |
| `AD_WEB_PORT` | Port d'écoute | `5000` |
| `SECRET_KEY` | Clé secrète Flask | (à définir) |
| `FLASK_ENV` | Environnement | `development` |
| `AD_SERVER` | Serveur AD par défaut | (vide) |
| `AD_PORT` | Port LDAP | `389` |
| `AD_USE_SSL` | Utiliser SSL | `false` |

## Accès à l'interface

Une fois démarrée, l'interface est accessible à :

- **Local** : http://localhost:5000
- **Réseau** : http://VOTRE_IP:5000

Pour trouver votre IP :
- Linux : `ip addr` ou `hostname -I`
- Windows : `ipconfig`

## Production

### Linux (avec Gunicorn)

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Windows (avec Waitress)

```bash
pip install waitress
set FLASK_ENV=production
python run.py
```

## Structure du projet

```
microsoft-active-directory/
├── app.py              # Application Flask principale
├── config.py           # Configuration cross-platform
├── run.py              # Script de démarrage Python
├── run.sh              # Script de démarrage Linux
├── run.bat             # Script de démarrage Windows
├── requirements.txt    # Dépendances Python
├── .env.example        # Exemple de configuration
├── templates/          # Templates HTML
│   ├── base.html
│   ├── index.html
│   ├── connect.html
│   └── dashboard.html
└── static/
    ├── css/
    │   └── style.css
    └── js/
        └── main.js
```

## API Endpoints

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/` | GET | Page d'accueil |
| `/connect` | GET/POST | Connexion AD |
| `/dashboard` | GET | Dashboard |
| `/api/search` | POST | Recherche LDAP |
| `/api/system-info` | GET | Info système |
| `/health` | GET | Health check |

## Sécurité

- En production, définissez un `SECRET_KEY` sécurisé
- Utilisez HTTPS avec un reverse proxy (nginx, Apache)
- Considérez l'utilisation de LDAPS (port 636) pour les connexions AD

## License

MIT
