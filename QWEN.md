# Interface Web Microsoft Active Directory

> **Version actuelle :** 1.17.4 — [Voir les releases](https://github.com/fred-selest/microsoft-active-directory/releases)

Application web pour gérer Microsoft Active Directory depuis un navigateur. Aucune installation client requise.

---
# Rôle
Tu es mon Lead Developer intégré dans VS Code. Tu as accès au contexte de mon workspace.

# Objectif
Améliorer le code actuel, éliminer les bugs et optimiser les performances par itérations successives jusqu'à stabilité complète.

# Contexte
Je travaille sur ce projet dans VS Code. Utilise tes capacités de lecture de fichiers pour analyser le code pertinent.

# Processus de Travail (Boucle)
1. **Analyse du Contexte** : Scan les fichiers ouverts ou référencés. Identifie les bugs, la dette technique et les risques.
2. **Proposition de Code** : Génère les corrections directement sous forme de blocs de code applicables ou de "diffs".
3. **Stratégie de Test** : Propose les commandes exactes à lancer dans le terminal VS Code pour tester la correction (ex: `npm test`, `python pytest`, etc.).
4. **Validation** : Attends que je lance les tests et te donne le retour (succès ou logs d'erreur).
5. **Itération** : Si erreur, analyse les logs, corrige le code, et recommence à l'étape 1.

# Contraintes
- Ne suppose pas que le code fonctionne sans test.
- Si tu modifies un fichier, indique clairement le chemin du fichier.
- Priorise la sécurité et la lisibilité.
- Si tu détectes un bug critique, signale-le en gras avant de proposer la fix.

# Démarrage
Commence par me demander quels sont les fichiers principaux ou la fonctionnalité sur laquelle je veux travailler aujourd'hui, puis lance l'analyse.

## 📋 Table des matières

1. [Démarrage rapide](#-démarrage-rapide)
2. [Installation](#-installation)
3. [Configuration](#-configuration)
4. [Fonctionnalités](#-fonctionnalités)
5. [Sécurité](#-sécurité)
6. [Architecture](#-architecture)
7. [Développement](#-développement)
8. [Dépannage](#-dépannage)
9. [Historique](#-historique)

---

## 🚀 Démarrage rapide

### Windows (Service automatique)

```bat
# 1. Télécharger et extraire dans C:\AD-Web\
# 2. Clic droit sur install_service.bat → Exécuter en tant qu'administrateur
# 3. Accéder à http://NOM_SERVEUR:5000
```

### Linux

```bash
git clone https://github.com/fred-selest/microsoft-active-directory.git
cd microsoft-active-directory
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
python3 run.py
```

---

## 📦 Installation

### Windows Server (Recommandé)

**Prérequis :**
- Windows Server 2016/2019/2022 ou Windows 10/11
- Droits administrateur local
- Accès réseau vers AD (ports 389/636)
- Internet (installation uniquement, pour Python et NSSM)

**Procédure :**

| Étape | Action |
|-------|--------|
| 1 | Télécharger depuis [GitHub Releases](https://github.com/fred-selest/microsoft-active-directory/releases/latest) |
| 2 | Extraire dans `C:\AD-Web\microsoft-active-directory\` (sans accents ni espaces) |
| 3 | `install_service.bat` → Exécuter en tant qu'administrateur |

**Le script automatise :**
- Installation de Python si absent (via winget ou python.org)
- Création du venv et dépendances
- Génération `.env` avec SECRET_KEY unique
- Configuration support NTLM/MD4 (Python 3.12+)
- Installation service Windows (auto-start, redémarrage sur crash)
- Ouverture port 5000 dans le pare-feu Windows

### Gestion du service

```bat
net start ADWebInterface      # Démarrer
net stop ADWebInterface       # Arrêter
sc query ADWebInterface       # Statut
uninstall_service.bat         # Désinstaller (admin)
```

Le service est visible dans `services.msc` sous le nom **Interface Web Active Directory**.

### Linux (Production)

```bash
# Installation
git clone https://github.com/fred-selest/microsoft-active-directory.git
cd microsoft-active-directory

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Configuration
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
echo "FLASK_ENV=production" >> .env

# Production avec Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 'app:app'
```

### HTTPS avec nginx

```nginx
server {
    listen 443 ssl http2;
    server_name ad.monentreprise.com;

    ssl_certificate /chemin/vers/cert.pem;
    ssl_certificate_key /chemin/vers/key.pem;

    # Headers de sécurité
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

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

## ⚙️ Configuration

### Fichier .env

```ini
# =============================================================================
# CONFIGURATION FLASK (OBLIGATOIRE)
# =============================================================================

# CRITIQUE: Générer avec python -c 'import secrets; print(secrets.token_hex(32))'
# Ne jamais laisser la valeur par défaut en production
SECRET_KEY=votre-cle-secrete

# Mode debug (false en production)
FLASK_DEBUG=false
FLASK_ENV=production

# =============================================================================
# CONFIGURATION SERVEUR
# =============================================================================

AD_WEB_HOST=0.0.0.0
AD_WEB_PORT=5000

# Mode silencieux (pas de console, pour pythonw.exe)
AD_SILENT=true

# =============================================================================
# CONFIGURATION SESSION ET HTTPS
# =============================================================================

# Cookies HTTPS uniquement (true en production avec HTTPS)
SESSION_COOKIE_SECURE=true
SESSION_TIMEOUT=30

# Redirection HTTP → HTTPS (nécessite reverse proxy)
FORCE_HTTPS=true

# Proxys de confiance (reverse proxy)
TRUSTED_PROXIES=127.0.0.1,::1

# =============================================================================
# CONFIGURATION ACTIVE DIRECTORY (optionnel - configurable via UI)
# =============================================================================

AD_SERVER=dc01.entreprise.local
AD_PORT=389
AD_USE_SSL=false
AD_BASE_DN=DC=entreprise,DC=local

# =============================================================================
# CONFIGURATION RBAC (Role-Based Access Control)
# =============================================================================

RBAC_ENABLED=true
DEFAULT_ROLE=reader

# Groupes AD pour attribution automatique des rôles
# Le premier groupe correspondant détermine le rôle
RBAC_ADMIN_GROUPS=Domain Admins,Administrateurs du domaine
RBAC_OPERATOR_GROUPS=IT Support,Helpdesk
RBAC_READER_GROUPS=Domain Users

# =============================================================================
# CHEMINS (optionnel - détection automatique par défaut)
# =============================================================================

AD_LOG_DIR=logs
AD_DATA_DIR=data

# =============================================================================
# AUTRES OPTIONS
# =============================================================================

ITEMS_PER_PAGE=25
```

### Rôles RBAC

| Rôle | Permissions | Groupes par défaut |
|------|-------------|-------------------|
| `admin` | read, write, delete, admin | Domain Admins, Administrateurs du domaine |
| `operator` | read, write | IT Support, Helpdesk |
| `reader` | read | Domain Users (défaut) |

### Permissions par rôle

| Action | admin | operator | reader |
|--------|-------|----------|--------|
| Consulter utilisateurs/groupes/ordinateurs | ✅ | ✅ | ✅ |
| Créer/modifier utilisateurs | ✅ | ✅ | ❌ |
| Créer/modifier groupes | ✅ | ✅ | ❌ |
| Supprimer objets | ✅ | ❌ | ❌ |
| Gestion RBAC | ✅ | ❌ | ❌ |
| Audit logs | ✅ | ❌ | ❌ |

---

## ✨ Fonctionnalités

### Gestion Active Directory

| Fonctionnalité | Description |
|----------------|-------------|
| **Connexion LDAP/LDAPS** | Support des ports 389 (LDAP) et 636 (LDAPS) |
| **Utilisateurs** | Créer, modifier, désactiver, déplacer, supprimer |
| **Groupes** | Gestion des membres, groupes imbriqués |
| **Ordinateurs** | Liste, détails, LAPS |
| **OUs** | Créer, modifier, supprimer, déplacer |
| **Recherche globale** | Recherche multi-critères (nom, email, login) |
| **Export CSV/Excel** | Export des utilisateurs et groupes |

### Administration

| Fonctionnalité | Description |
|----------------|-------------|
| **RBAC** | Contrôle d'accès basé sur groupes AD |
| **Audit** | Journal complet de toutes les actions |
| **Alertes** | Comptes expirants, mots de passe expirants, comptes inactifs |
| **Sauvegarde** | Backup automatique avant modifications |
| **Historique** | Suivi des changements |
| **Mises à jour** | Détection et application automatiques |

### Interface utilisateur

| Fonctionnalité | Description |
|----------------|-------------|
| **Responsive** | Desktop, tablette, mobile |
| **Mode sombre** | Bascule clair/sombre |
| **Multi-langue** | Français, Anglais |
| **PWA** | Installation comme application native |
| **Favoris** | Pages favorites personnalisables |
| **Templates** | Modèles de création utilisateurs |

---

## 🔒 Sécurité

### Fonctionnalités implémentées

| Fonctionnalité | Description | Statut |
|----------------|-------------|--------|
| **Chiffrement sessions** | Fernet (AES-128 CBC) avec PBKDF2 (100k itérations) | ✅ |
| **Salt unique** | Salt PBKDF2 par déploiement (`data/crypto_salt.bin`) | ✅ |
| **Protection LDAP** | Échappement caractères spéciaux LDAP | ✅ |
| **Protection CSRF** | Tokens sur tous les formulaires | ✅ |
| **Rate limiting** | 5 tentatives / 5 minutes sur login | ✅ |
| **Headers sécurité** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options | ✅ |
| **RBAC** | Activé par défaut avec rôle reader minimum | ✅ |
| **Cookies sécurisés** | SESSION_COOKIE_SECURE=true par défaut | ✅ |
| **Protection path traversal** | Validation des chemins de fichiers | ✅ |
| **Validation DN** | Sanitisation des Distinguished Names | ✅ |

### Checklist de déploiement sécurisé

- [ ] SECRET_KEY forte générée (32 octets hex)
- [ ] HTTPS activé avec certificat valide
- [ ] `SESSION_COOKIE_SECURE=true`
- [ ] `FLASK_DEBUG=false` en production
- [ ] `RBAC_ENABLED=true`
- [ ] `DEFAULT_ROLE=reader`
- [ ] LDAPS activé (port 636) recommandé
- [ ] Pare-feu configuré (accès restreint)
- [ ] Logs protégés avec permissions restrictives
- [ ] Sauvegardes régulières configurées

### Audit de sécurité (v1.10.0+)

**28 vulnérabilités identifiées et corrigées :**

**Critiques :**
- ✅ Chiffrement des mots de passe en session
- ✅ Protection injection LDAP
- ✅ SECRET_KEY obligatoire en production
- ✅ Retrait ExecutionPolicy Bypass PowerShell

**Priorité haute :**
- ✅ Cookies de session sécurisés
- ✅ Headers de sécurité supplémentaires
- ✅ RBAC activé par défaut
- ✅ Versions des dépendances fixées
- ✅ .gitignore renforcé
- ✅ Protection path traversal

---

## 🏗️ Architecture

### Structure du projet

```
microsoft-active-directory/
├── app.py                        # Application Flask principale
├── run.py                        # Point d'entrée (auto-génération .env)
├── config.py                     # Configuration multi-plateforme
├── requirements.txt              # Dépendances Python
├── routes/                       # Blueprints Flask
│   ├── core.py                   # Connexion AD, RBAC, permissions
│   ├── users.py                  # Gestion utilisateurs
│   ├── groups.py                 # Gestion groupes
│   ├── computers.py              # Gestion ordinateurs
│   ├── tools.py                  # Outils utilitaires
│   └── admin.py                  # Administration
├── templates/                    # Templates HTML (Jinja2)
├── static/                       # CSS, JavaScript, icônes
├── security.py                   # Sécurité (LDAP, CSRF, rate limiting)
├── session_crypto.py             # Chiffrement Fernet/AES-128
├── audit.py                      # Journal d'audit
├── alerts.py                     # Système d'alertes
├── backup.py                     # Sauvegarde objets AD
├── path_security.py              # Protection path traversal
├── translations.py               # Multi-langue (fr/en)
├── settings_manager.py           # Paramètres utilisateurs
├── updater.py / updater_fast.py  # Mises à jour automatiques
├── install_service.bat           # Installation service Windows
├── uninstall_service.bat         # Désinstallation service
├── run_server.bat                # Démarrage manuel Windows
├── run_legacy.bat                # Démarrage avec support MD4
├── run_client.bat                # Ouverture navigateur client
├── openssl_legacy.cnf            # Config NTLM/MD4 Python 3.12+
└── .env.example                  # Modèle de configuration
```

### Flux d'architecture

```
┌─────────────────────────────────┐
│      Serveur Windows            │
│  ┌──────────────────────────┐   │
│  │  Service ADWebInterface  │   │
│  │  (Flask + Waitress)      │   │
│  │  Port 5000               │   │
│  └────────────┬─────────────┘   │
│               │ LDAP/LDAPS      │
│  ┌────────────▼─────────────┐   │
│  │  Contrôleur de domaine   │   │
│  │  Active Directory        │   │
│  └──────────────────────────┘   │
└───────────────┬─────────────────┘
                │ HTTP
     ┌──────────┴──────────┐
     │   Navigateurs web   │
     └─────────────────────┘
```

### Stack technique

| Composant | Version | Usage |
|-----------|---------|-------|
| Flask | 3.0.0 | Framework web |
| Werkzeug | 3.0.1 | Utilitaires WSGI |
| ldap3 | 2.9.1 | Connexion Active Directory |
| cryptography | 41.0.7 | Chiffrement sessions |
| python-dotenv | 1.0.0 | Gestion configuration |
| gunicorn | 21.2.0 | Serveur WSGI (Linux) |
| waitress | 2.1.2 | Serveur WSGI (Windows) |
| reportlab | 4.0.7 | Génération PDF |
| openpyxl | 3.1.2 | Export Excel |

### Répertoires de données

| Répertoire | Contenu |
|------------|---------|
| `data/` | Données persistantes |
| `data/backups/` | Sauvegardes objets AD |
| `data/history/` | Historique des changements |
| `data/crypto_salt.bin` | Salt de chiffrement unique |
| `logs/` | Journaux d'application |
| `logs/audit.log` | Journal d'audit |
| `logs/server.log` | Logs Flask/Waitress |
| `logs/service.log` | Logs service Windows |

---

## 💻 Développement

### Mode développement

```bash
export FLASK_ENV=development
export FLASK_DEBUG=true
python run.py
```

### Conventions de code

- **Python :** 3.8+ compatible
- **Docstrings :** En français
- **Noms de fonctions :** Anglais
- **Commentaires :** Français
- **Type hints :** Utilisés avec modération

### Gestion des erreurs

```python
# ✅ Bon : Logger les erreurs
try:
    # ...
except Exception as e:
    logger.warning(f"Erreur: {e}", exc_info=True)

# ❌ Mauvais : Ignorer silencieusement
try:
    # ...
except:
    pass
```

### Journalisation

| Fichier | Contenu | Niveau |
|---------|---------|--------|
| `logs/audit.log` | Journal d'audit (toutes actions) | INFO |
| `logs/service.log` | Logs du service Windows | INFO |
| `logs/service_error.log` | Erreurs du service | ERROR |
| `logs/server.log` | Logs Flask/Waitress | INFO |

### API Endpoints

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/health` | GET | Health check Docker/K8s |
| `/api/check-update` | GET | Vérifier mises à jour |
| `/api/perform-update` | POST | Effectuer mise à jour |

### Tests de sécurité

```bash
# Scan de dépendances
pip install safety
safety check

# Analyse statique
pip install bandit
bandit -r . -x venv/

# Test d'injection LDAP
# Tester avec *)(objectClass=* dans les champs de recherche
```

### Tests automatisés

Un script de test complet est inclus (`tests.py`) :

```bash
# Exécuter tous les tests
python tests.py

# Résultat attendu : 14/14 tests passés
```

**Tests inclus :**

| Test | Description |
|------|-------------|
| Configuration | Validation SECRET_KEY, RBAC, rôle par défaut |
| Échappement LDAP | Protection contre injection LDAP |
| Token CSRF | Génération et validation tokens |
| Chiffrement sessions | AES-128 Fernet avec PBKDF2 |
| Traductions | Support fr/en |
| Module audit | 20 actions définies |
| Routes core | Rôles admin/operator/reader |
| Application Flask | 45 routes enregistrées |
| Endpoint /api/health | Health check |
| Endpoint /api/check-update | Vérification mises à jour |
| Page d'accueil | Accessibilité |
| Répertoires | logs/, data/ existants |
| Fichier .env | Configuration valide |
| Dépendances | 6 modules critiques |

**Rapport de test :** `logs/test_report.json`

---

## 🔧 Dépannage

### Problèmes courants

| Problème | Cause | Solution |
|----------|-------|----------|
| Port 5000 déjà utilisé | Conflit de port | `AD_WEB_PORT=8080` dans `.env` |
| Erreur MD4/NTLM (Python 3.12+) | Hash MD4 désactivé | Utiliser `run_legacy.bat` ou vérifier `openssl_legacy.cnf` |
| Service ne démarre pas | Erreur de configuration | Consulter `logs\service_error.log` et Observateur d'événements |
| Connexion impossible depuis réseau | Pare-feu bloquant | Vérifier règle : `netsh advfirewall firewall show rule name="AD Web Interface"` |
| Identifiants incorrects (LDAP 49) | Mauvais format username | Utiliser `DOMAINE\utilisateur` ou `utilisateur@domaine.local` |
| `python3-venv` introuvable (Ubuntu) | Package manquant | `sudo apt install python3-venv` |
| Interface lente au démarrage | Serveur développement Flask | Forcer `FLASK_ENV=production` pour utiliser Waitress |
| NSSM introuvable | Téléchargement échoué | Télécharger manuellement depuis https://nssm.cc/download |

### Commandes de diagnostic

```bat
# Vérifier le service
sc query ADWebInterface

# Voir les logs
type logs\service_error.log

# Tester la connexion locale
curl http://localhost:5000

# Vérifier le pare-feu
netsh advfirewall firewall show rule name="AD Web Interface"

# Tester connexion AD
telnet dc01.entreprise.local 389

# Vérifier Python
python --version
```

### Logs d'erreur courants

| Erreur | Signification | Correction |
|--------|---------------|------------|
| `SECRET_KEY non définie` | Clé manquante dans .env | Générer avec `python -c 'import secrets; print(secrets.token_hex(32))'` |
| `WinError 1` | IPv6 non supporté ou adresse incorrecte | Vérifier adresse serveur AD et ports 389/636 |
| `invalidCredentials` / `Error 49` | Mot de passe incorrect | Vérifier identifiants AD |
| `MD4` / `unsupported hash` | NTLM non supporté Python 3.12+ | Utiliser `run_legacy.bat` |
| `FileNotFoundError` | Répertoire logs manquant | Vérifier permissions d'écriture |

### Procédure de réinitialisation

```bat
# 1. Arrêter le service
net stop ADWebInterface

# 2. Sauvegarder la configuration
copy .env .env.backup
copy data\* data_backup\

# 3. Supprimer les fichiers temporaires
del /Q logs\*.log
del /Q data\alerts.json

# 4. Redémarrer
net start ADWebInterface
```

---

## 📜 Historique

### Versions récentes

#### [1.17.4] - 2026-03-30
- **Corrigé :** Démarrage lent (60+ s → ~3 s) avec Waitress
- **Corrigé :** Logs vides avec `logging.FileHandler`
- **Corrigé :** `.env` auto-généré avec valeurs correctes

#### [1.17.3] - 2026-03-30
- **Corrigé :** Timeouts de démarrage augmentés (30s → 60s)
- **Nettoyage :** Suppression fichiers orphelins (api.py, smtp_service.py, etc.)

#### [1.17.2] - 2026-03-30
- **Corrigé :** Installation NSSM (winget, Chocolatey, miroirs GitHub)
- **Amélioré :** NSSM inclus dans le package Windows via GitHub Actions

#### [1.17.1] - 2026-03-29
- **Corrigé :** Workflow release GitHub Actions (job unique)

#### [1.17.0] - 2026-03-29
- **Amélioré :** Détection mots de passe expirants
- **Amélioré :** Comptes inactifs (jamais connectés)
- **Sécurité :** Salt PBKDF2 unique par déploiement
- **Ajouté :** `GUIDE_INSTALLATION_WINDOWS.md`
- **Supprimé :** Fichiers Docker (non utilisés)

#### [1.16.4] - 2025-11-22
- **Corrigé :** Recherche utilisateur AD (extraction nom sans domaine)

#### [1.16.3] - 2025-11-22
- **Ajouté :** Debug groupes AD (affichage groupes et rôle)

#### [1.16.0] - 2025-11-22
- **Ajouté :** Menus conditionnels selon permissions
- **Ajouté :** Fonction `has_permission` dans templates

#### [1.15.0] - 2025-11-22
- **Ajouté :** Attribution des rôles basée sur groupes AD

#### [1.14.0] - 2025-11-22
- **Ajouté :** Option "changement mot de passe obligatoire"

#### [1.11.0] - 2025-11-21
- **Sécurité :** Chiffrement AES-128 des mots de passe en session
- **Sécurité :** Protection injection LDAP
- **Sécurité :** SECRET_KEY obligatoire en production

---

## 📄 Licence

MIT

---

## 🔗 Liens utiles

- [Dépôt GitHub](https://github.com/fred-selest/microsoft-active-directory)
- [Releases](https://github.com/fred-selest/microsoft-active-directory/releases)
- [Guide d'installation Windows](GUIDE_INSTALLATION_WINDOWS.md)
- [Rapport de sécurité](SECURITY.md)
- [Changelog complet](CHANGELOG.md)
