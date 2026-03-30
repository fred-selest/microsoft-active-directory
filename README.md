# Interface Web Active Directory

Interface web pour Microsoft Active Directory. Gérez vos utilisateurs, groupes et ordinateurs directement depuis votre navigateur — aucune installation requise côté client.

> **Version actuelle : 1.17.5** — [Voir les releases](https://github.com/fred-selest/microsoft-active-directory/releases)

---

## Pour les utilisateurs

**Aucune installation requise.** Ouvrez votre navigateur et accédez à :

```
http://ADRESSE_DU_SERVEUR:5000
```

Exemples :
- Réseau local : `http://192.168.1.100:5000`
- Nom d'hôte : `http://serveur-ad.entreprise.local:5000`
- Avec HTTPS : `https://ad.monentreprise.com`

Fonctionne sur tous les systèmes et navigateurs (Windows, Linux, macOS, tablettes, smartphones).

---

## Installation sur Windows Server (recommandé)

> Consultez le guide complet : **[GUIDE_INSTALLATION_WINDOWS.md](GUIDE_INSTALLATION_WINDOWS.md)**

### En 3 étapes

**1. Télécharger**

Téléchargez la dernière release Windows depuis :
```
https://github.com/fred-selest/microsoft-active-directory/releases/latest
```
Décompressez dans un dossier sans accent ni espace, par exemple `C:\AD-Web\`.

**2. Installer le service**

Clic droit sur `install_service.bat` → **Exécuter en tant qu'administrateur**

Le script gère automatiquement :
- Installation de Python si absent
- Création du venv et des dépendances
- Génération du fichier `.env` avec `SECRET_KEY` aléatoire
- Installation du service Windows (démarrage automatique, redémarrage sur crash)
- Ouverture du port 5000 dans le pare-feu Windows

**3. Accéder**

L'adresse réseau est affichée à la fin de l'installation. Communiquez-la à vos utilisateurs.

### Gestion du service

```bat
net start ADWebInterface    # Démarrer
net stop ADWebInterface     # Arrêter
sc query ADWebInterface     # Statut
uninstall_service.bat       # Désinstaller (en admin)
```

---

## Installation sur Linux

```bash
git clone https://github.com/fred-selest/microsoft-active-directory.git
cd microsoft-active-directory

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Générer la configuration
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
echo "FLASK_ENV=production" >> .env

python3 run.py
```

Production avec Gunicorn :
```bash
gunicorn -w 4 -b 0.0.0.0:5000 'app:app'
```

---

## Configuration

Le fichier `.env` est généré automatiquement au premier démarrage. Principales options :

```ini
SECRET_KEY=votre-cle-secrete          # Généré automatiquement
FLASK_ENV=production
AD_WEB_HOST=0.0.0.0
AD_WEB_PORT=5000

# Active Directory (optionnel — configurable via l'interface)
AD_SERVER=dc01.entreprise.local
AD_PORT=389
AD_USE_SSL=false
AD_BASE_DN=DC=entreprise,DC=local

# Contrôle d'accès (RBAC)
RBAC_ENABLED=true
DEFAULT_ROLE=reader
RBAC_ADMIN_GROUPS=Domain Admins,Administrateurs du domaine
```

Voir `.env.example` pour toutes les options documentées.

---

## Fonctionnalités

- Connexion LDAP / LDAPS à Active Directory
- Gestion des utilisateurs (créer, modifier, désactiver, déplacer, supprimer)
- Gestion des groupes et des membres
- Gestion des ordinateurs et des OUs
- Recherche globale
- Export CSV
- Contrôle d'accès basé sur les rôles AD (admin / operator / reader)
- Audit log de toutes les actions
- Alertes : comptes expirants, mots de passe expirants, comptes inactifs
- Interface responsive (desktop, tablette, mobile)
- Mises à jour depuis l'interface web (détection automatique)
- Support Python 3.12+ (NTLM/MD4 géré automatiquement)

---

## Sécurité

- Mots de passe chiffrés en session (AES-128 Fernet)
- Protection injection LDAP
- Tokens CSRF sur tous les formulaires
- Rate limiting sur la connexion
- `SECRET_KEY` unique par déploiement, générée automatiquement
- Salt PBKDF2 unique par installation (`data/crypto_salt.bin`)
- RBAC activé par défaut (rôle `reader` minimum)
- Support LDAPS (port 636) recommandé en production
- Compatible reverse proxy HTTPS (nginx, IIS)

---

## Mises à jour

L'interface affiche automatiquement une notification quand une mise à jour est disponible.
Cliquer sur le bouton déclenche le téléchargement, la mise à jour des dépendances et le redémarrage du service. Les fichiers `.env` et `data/` sont toujours préservés.

---

## Déploiement production avec HTTPS (nginx)

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

## Problèmes courants

| Problème | Solution |
|----------|----------|
| Port 5000 déjà utilisé | `AD_WEB_PORT=8080` dans `.env` |
| Erreur MD4 / NTLM (Python 3.12+) | Géré automatiquement par `install_service.bat` ; sinon utiliser `run_legacy.bat` |
| Interface inaccessible depuis le réseau | Vérifier la règle pare-feu (créée automatiquement par `install_service.bat`) |
| `python3-venv` introuvable (Ubuntu) | `sudo apt install python3-venv` |

---

## Structure du projet

```
microsoft-active-directory/
├── app.py                        # Application Flask principale
├── run.py                        # Point d'entrée
├── config.py                     # Configuration
├── requirements.txt              # Dépendances Python
├── routes/                       # Blueprints Flask
├── templates/                    # Pages HTML (Jinja2)
├── static/                       # CSS, JavaScript, icônes
├── install_service.bat           # Installation service Windows (recommandé)
├── uninstall_service.bat         # Désinstallation service Windows
├── run_server.bat                # Démarrage manuel Windows
├── run_legacy.bat                # Démarrage avec support MD4
├── run_client.bat                # Raccourci navigateur client
├── run.sh                        # Démarrage Linux
├── openssl_legacy.cnf            # Support NTLM/MD4 Python 3.12+
├── GUIDE_INSTALLATION_WINDOWS.md # Guide installation Windows Server
└── .env.example                  # Modèle de configuration
```

---

## Licence

MIT
