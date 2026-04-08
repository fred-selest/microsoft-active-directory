# QWEN.md — Guide d'architecture pour assistants IA

> Ce fichier décrit l'architecture interne du projet **AD Web Interface** à l'intention des assistants IA (Claude, Qwen, GPT…) afin d'accélérer la compréhension du code et d'éviter les erreurs courantes.

**Version actuelle :** 1.36.0 (Avril 2026)

---

## 1. Vue d'ensemble

**AD Web Interface** est une application Flask permettant de gérer un Active Directory Microsoft depuis un navigateur web. Elle tourne en tant que **service Windows** via WinSW (`nssm/ADWebInterface.exe`), servie par **Waitress** (WSGI).

- **Point d'entrée :** `app.py` → importe `_openssl_init.py` EN PREMIER (fix NTLM/MD4 sur Python 3.12+)
- **Serveur WSGI :** Waitress (`waitress.serve`) sur `0.0.0.0:5000` par défaut
- **Configuration :** `config.py` → lit `.env` ou variables d'environnement
- **Version :** fichier `VERSION` à la racine (ex. `1.36.0`)

---

## 2. Structure des répertoires

```
C:\AD-WebInterface\
├── app.py                    # Application Flask, enregistrement des blueprints
├── config.py                 # Classe Config, chargement .env
├── run.py                    # Alias → run_server() de app.py
├── VERSION                   # Version courante (plain text)
├── _openssl_init.py          # DOIT être importé en premier — corrige MD4/NTLM
├── requirements.txt
│
├── core/                     # Modules utilitaires (package Python)
│   ├── __init__.py
│   ├── security.py           # CSRF, escape LDAP, headers HTTP, session cookie
│   ├── session_crypto.py     # Chiffrement Fernet des données de session
│   ├── audit.py              # Journal des actions (CSV + mémoire)
│   ├── audit_history.py      # Lecture de l'historique d'audit
│   ├── granular_permissions.py  # 40 permissions par groupe AD
│   ├── context_processor.py  # inject_globals() — version, dark_mode, connected
│   ├── updater.py            # Lecture VERSION + vérification GitHub releases
│   ├── settings_manager.py   # Lecture/écriture settings.json
│   ├── features.py           # Flags de fonctionnalités
│   ├── ldap_errors.py        # Traduction codes erreur LDAP en messages FR
│   ├── password_generator.py # Génération côté serveur (non exposé en route)
│   ├── translations.py       # i18n minimal FR/EN
│   ├── ad_detect.py          # Auto-détection du domaine AD
│   ├── alerts.py             # Alertes AD (comptes expirés, etc.)
│   ├── auto_alerts.py        # Déclenchement automatique des alertes
│   ├── backup.py             # Sauvegarde/restauration config
│   ├── dashboard_widgets.py  # Données pour les widgets du tableau de bord
│   ├── debug_utils.py        # Logger + helper init_debug()
│   ├── diagnostic.py         # Diagnostic LDAP et réseau (19 tests, v1.36)
│   ├── email_notifications.py# Envoi emails SMTP
│   ├── path_security.py      # Validation chemins fichiers (traversal)
│   ├── security_audit.py     # Audit de sécurité AD (8 problèmes)
│   ├── scripts_manager.py    # NOUVEAU v1.36: Gestion scripts PowerShell
│   └── log_analyzer.py       # NOUVEAU v1.36: Analyse auto des logs
│   └── data/                 # Données runtime (gitignored)
│       └── crypto_salt.bin   # Sel Fernet (généré au 1er démarrage)
│
├── routes/                   # Blueprints Flask
│   ├── __init__.py
│   ├── core.py               # Helpers partagés : get_ad_connection(), is_connected(),
│   │                         #   require_connection, require_permission
│   ├── main.py               # Blueprint "main" — accueil, connexion, déconnexion
│   ├── api.py                # Blueprint "api" — endpoints JSON + scripts (v1.36)
│   ├── admin_tools.py        # Blueprint "admin_tools" — permissions, settings,
│   │                         #   scripts (v1.36), log-analysis (v1.36)
│   │
│   ├── users/                # Blueprint "users"
│   │   ├── __init__.py       # Déclare users_bp (url_prefix='/users')
│   │   ├── list_users.py     # GET /users/
│   │   ├── create.py         # GET/POST /users/create
│   │   ├── update.py         # GET/POST /users/<dn>/edit
│   │   ├── delete.py         # POST /users/<dn>/delete
│   │   ├── password.py       # POST /users/<dn>/password
│   │   ├── move.py           # POST /users/<dn>/move
│   │   ├── helpers.py        # Fonctions partagées (get_user_details, etc.)
│   │   └── validators.py     # UserCreateRequest, UserUpdateRequest (dataclasses)
│   │
│   ├── groups/               # Blueprint "groups" (url_prefix='/groups')
│   │   └── __init__.py
│   │
│   ├── computers/            # Blueprint "computers" (url_prefix='/computers')
│   │   └── __init__.py
│   │
│   ├── ous/                  # Blueprint "ous" (url_prefix='/ous')
│   │   └── __init__.py
│   │
│   ├── tools/                # Blueprint "tools" (url_prefix='/tools')
│   │   ├── __init__.py
│   │   ├── accounts.py       # Comptes bloqués, expirés
│   │   ├── backups.py        # Sauvegardes
│   │   ├── bitlocker.py      # Clés BitLocker
│   │   ├── laps.py           # LAPS passwords
│   │   ├── misc.py           # Outils divers
│   │   └── password.py       # Audit mots de passe
│   │
│   ├── admin/                # Blueprint "admin" (url_prefix='/admin')
│   │   └── __init__.py
│   │
│   └── debug/                # Blueprint "debug" (url_prefix='/debug')
│       └── __init__.py
│
├── templates/                # Templates Jinja2 (73 fichiers)
│   ├── base.html             # Layout principal (navbar, dark mode, flash messages)
│   ├── index.html            # Landing page (hero + feature cards + system info)
│   ├── connect.html          # Formulaire de connexion AD
│   ├── dashboard.html
│   ├── list_users.html
│   ├── create_user.html      # Création utilisateur (générateur MDP, badge LDAPS)
│   ├── edit_user.html        # Édition utilisateur
│   ├── list_groups.html
│   ├── list_computers.html
│   ├── list_ous.html         # v1.36: stats, filtres, badges cliquables
│   ├── permissions.html      # Gestion permissions granulaires
│   ├── settings.html
│   ├── admin.html            # v1.36: lien vers log-analysis
│   ├── error.html
│   ├── diagnostic.html       # v1.36: 19 tests, infos système, export
│   ├── expiring_accounts.html # v1.36: dates FR, exclusion comptes système
│   ├── password_audit.html   # Audit mots de passe
│   ├── password_audit_history.html # v1.36: tri, dates FR
│   ├── log_analysis.html     # NOUVEAU v1.36: Analyse des logs
│   └── scripts.html          # NOUVEAU v1.36: Gestion scripts PowerShell
│   └── ...
│
├── static/
│   ├── css/
│   │   └── styles.css        # Design system complet (CSS custom properties)
│   ├── js/
│   └── img/
│
├── data/                     # Données persistantes (gitignored)
│   ├── settings.json
│   ├── permissions.json
│   └── audit_log.csv
│
├── logs/                     # Logs applicatifs (gitignored)
│
├── nssm/                     # Service Windows (WinSW)
│   ├── ADWebInterface.exe    # WinSW renommé
│   └── ADWebInterface.xml    # Config WinSW (executable, workdir, logs)
│
├── scripts/
│   ├── install_standalone.ps1   # Installation complète (venv + service WinSW)
│   ├── configure_service.ps1
│   ├── sign_winsw_admin.ps1     # Signature Authenticode self-signed (admin)
│   └── fix_*.ps1                # Correctifs LDAP signing, NTLM, SMBv1…
│
└── venv/                     # Environnement virtuel Python (gitignored)
```

---

## 3. Blueprints Flask

| Blueprint | Préfixe URL | Fichier principal |
|-----------|-------------|-------------------|
| `main_bp` | `/` | `routes/main.py` |
| `users_bp` | `/users` | `routes/users/__init__.py` |
| `groups_bp` | `/groups` | `routes/groups/__init__.py` |
| `computers_bp` | `/computers` | `routes/computers/__init__.py` |
| `ous_bp` | `/ous` | `routes/ous/__init__.py` |
| `tools_bp` | `/tools` | `routes/tools/__init__.py` |
| `admin_bp` | `/admin` | `routes/admin/__init__.py` |
| `debug_bp` | `/debug` | `routes/debug/__init__.py` |
| `api_bp` | `/api` | `routes/api.py` |
| `admin_tools_bp` | `/` | `routes/admin_tools.py` |

---

## 4. Connexion Active Directory

### Session Flask — clés importantes

| Clé | Type | Description |
|-----|------|-------------|
| `ad_server` | str | Hostname ou IP du DC |
| `ad_port` | int | Port LDAP (389 ou 636) |
| `ad_base_dn` | str | DN de base (ex. `DC=corp,DC=local`) |
| `ad_username` | str | sAMAccountName de l'utilisateur connecté |
| `ad_use_ssl` | bool | True si connexion LDAPS (port 636) |
| `ad_starttls` | bool | True si STARTTLS activé sur port 389 |
| `ad_user_dn` | str | DN complet de l'utilisateur connecté |
| `ad_permissions` | list | Permissions accordées à cet utilisateur |

### Méthode de connexion (`routes/core.py`)

L'ordre de tentative est :
1. **NTLM** sur port 389 (non chiffré)
2. **STARTTLS** sur port 389 (chiffrement opportuniste)
3. **LDAPS** sur port 636 (SSL/TLS)

```python
# Après bind() réussi, stocker dans la session :
session['ad_use_ssl'] = use_ssl       # True seulement si port 636
session['ad_starttls'] = starttls     # True seulement si STARTTLS
```

### Définition du mot de passe (unicodePwd)

**Requiert impérativement un canal chiffré** (LDAPS ou STARTTLS).

```python
can_set_password = session.get('ad_use_ssl', False) or session.get('ad_starttls', False)
```

L'attribut `unicodePwd` doit être modifié avec `MODIFY_REPLACE` (pas `MODIFY_ADD`) :

```python
unicode_pwd = f'"{password}"'.encode('utf-16-le')
conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})
```

---

## 5. Design System CSS (`static/css/styles.css`)

Le fichier est organisé en **17 sections numérotées** avec commentaires `/* ── Section N ──... */`.

### Variables CSS principales (`:root`)

```css
--primary:        #0078d4   /* Bleu Microsoft */
--primary-dark:   #005a9e
--white:          #ffffff
--bg-primary:     #f5f5f5
--bg-secondary:   #ffffff
--text-primary:   #1b1b1b
--text-secondary: #555555
--border-color:   #e0e0e0
--border-radius:  6px
--shadow-sm / --shadow-md / --shadow-lg
--spacing-sm / --spacing-md / --spacing-lg / --spacing-xl
--transition-fast / --transition-normal
```

### Variables dark mode

Définies dans la section 17 :
```css
:root {
    --dark-bg-primary:    var(--bg-primary);      /* alias light par défaut */
    --dark-bg-secondary:  var(--bg-secondary);
    --dark-border:        var(--border-color);
}
body.dark-mode {
    --dark-bg-primary:    #0f0f1a;
    --dark-bg-secondary:  #1a1a2e;
    --dark-border:        #3a3a5a;
    --dark-text-primary:  #f0f0f5;
    --dark-text-secondary:#c0c0d0;
}
```

### Classes utilitaires importantes

- `.badge`, `.badge-success`, `.badge-warning`, `.badge-danger`, `.badge-info`
- `.alert`, `.alert-success`, `.alert-warning`, `.alert-danger`, `.alert-info`
- `.form-container`, `.form-section`, `.form-row`, `.form-group`, `.form-check`, `.form-actions`
- `.input-group`, `.btn-icon`
- `.page-header`, `.page-header-actions`
- `.text-success`, `.text-warning`, `.text-danger`, `.text-info`

> **Règle absolue :** Ne jamais utiliser de couleurs hex dans les templates HTML ou dans un `{% block extra_css %}`. Toujours utiliser les variables CSS (`var(--primary)`, etc.). Les styles spécifiques à une page vont dans `styles.css` sauf exception justifiée.

---

## 6. Sécurité

### CSRF

- Token généré dans `core/security.py` → `generate_csrf_token()`
- Stocké en session Flask, exposé via `csrf_token()` dans les templates
- Validé avec `validate_csrf_token(token)` dans chaque POST handler

### Chiffrement de session

- `core/session_crypto.py` — chiffre les données sensibles (mot de passe AD) avec Fernet
- Sel stocké dans `core/data/crypto_salt.bin` (chemin : `Path(__file__).parent.parent / 'data' / 'crypto_salt.bin'`)

### Headers HTTP

- `core/security.py → add_security_headers()` — CSP, X-Frame-Options, HSTS, etc.
- Appliqué via `@app.after_request`

### Imports sécurité

```python
from core.security import escape_ldap_filter, validate_csrf_token
from core.audit import log_action, ACTIONS
```

> ⚠️ **Erreur courante :** écrire `from security import` ou `from audit import` au lieu de `from core.security import` et `from core.audit import`. Ces imports relatifs ne fonctionnent pas depuis les routes.

---

## 7. Service Windows (WinSW)

### Fichiers

- `nssm/ADWebInterface.exe` — binaire WinSW renommé
- `nssm/ADWebInterface.xml` — configuration XML

### Commandes (sans droits admin)

```powershell
.\nssm\ADWebInterface.exe stop
.\nssm\ADWebInterface.exe start
.\nssm\ADWebInterface.exe restart
.\nssm\ADWebInterface.exe status
```

> WinSW permet restart sans droits admin, contrairement à `Restart-Service` ou `sc.exe`.

### Caching des templates

Flask ne recharge **pas** les templates en production (`TEMPLATES_AUTO_RELOAD = False` par défaut). Après modification d'un template, il faut **redémarrer le service** pour voir les changements. Utiliser `.\nssm\ADWebInterface.exe restart`.

---

## 8. Validators (`routes/users/validators.py`)

`UserCreateRequest` est une dataclass qui valide les champs avant création LDAP.

**Points importants :**
- L'OU doit commencer par `DC=`, `OU=` ou `CN=` (les trois sont valides)
- Assigner l'OU par défaut (`CN=Users,<base_dn>`) **avant** d'appeler `validate()`
- Le username ne doit pas contenir de caractères spéciaux LDAP

---

## 9. Gestion des permissions granulaires

- Configurées dans `data/permissions.json`
- Logique dans `core/granular_permissions.py`
- 40 permissions réparties en catégories : users, groups, computers, ous, tools, admin
- L'utilisateur connecté a ses permissions calculées à la connexion et stockées dans `session['ad_permissions']`
- Décorateur `@require_permission('write')` dans les routes protégées

---

## 10. Pièges connus / Historique des bugs

| Bug | Cause | Fix |
|-----|-------|-----|
| Version affiche `0.0.0` | Deux processus sur port 5000 (process fantôme) | `Stop-Process -Id <pid> -Force` |
| Crash loop au démarrage | `from security import` sans `core.` → ImportError | Corriger les imports |
| `/permissions` erreur 500 | Route rendait `admin.html` (requiert `settings`) au lieu de `permissions.html` | Changer le nom du template |
| OU dropdown invalide | `str(e.distinguishedName)` sans `.value` → représentation objet | Utiliser `.value` |
| OU rejeté par validateur | Validateur n'acceptait que `DC=` et `OU=`, pas `CN=` | Ajouter `CN=` dans la condition |
| Fausse alerte "LDAP non sécurisé" | STARTTLS stockait `ad_use_ssl=False` | Ajouter `ad_starttls` en session |
| Templates non mis à jour | `TEMPLATES_AUTO_RELOAD` désactivé en prod | Redémarrer le service |
| `unicodePwd` refusé | `MODIFY_ADD` au lieu de `MODIFY_REPLACE` | Changer le mode |
| `crypto_salt.bin` non trouvé | Chemin relatif incorrect dans `session_crypto.py` | Utiliser `.parent.parent` depuis `__file__` |
| JS non chargé | `{% block extra_js %}` imbriqué dans `{% block content %}` | Déplacer les blocs au niveau racine |

---

## 11. Conventions de code

- **Encoding :** UTF-8, commentaires en français
- **Logging :** `import logging; logger = logging.getLogger(__name__)`
- **Flash messages :** catégories `'success'`, `'error'`, `'warning'`, `'info'`
- **Redirection après POST :** toujours via `redirect(url_for(...))` (pattern PRG)
- **Libération connexion LDAP :** toujours `conn.unbind()` dans un bloc `finally`
- **Templates :** étendent `base.html`, définissent `{% block title %}`, `{% block content %}`, optionnellement `{% block extra_css %}` et `{% block extra_js %}` (toujours à la **racine** du fichier, jamais imbriqués)

## Qwen Added Memories
- Procédure de release Git pour AD Web Interface : 1) Mettre à jour fichier VERSION, 2) Commit avec message "chore: Bump version to X.Y.Z", 3) Créer tag annoté "git tag -a vX.Y.Z -m "Version X.Y.Z - Mois YYYY"", 4) Pousser main "git push origin main", 5) Pousser tag explicitement "git push origin vX.Y.Z" (JAMAIS --tags), 6) Vérifier sur GitHub "git ls-remote --tags origin". Ne jamais utiliser "git push --tags" car cela peut échouer avec des tags existants. Toujours pousser les tags individuellement.
- Procédure de signature des scripts PowerShell pour AD Web Interface : 1) Utiliser scripts\sign_all.bat (en admin) OU scripts\sign_scripts.ps1, 2) Le script crée automatiquement un certificat auto-signé dans Cert:\LocalMachine\My, 3) Importe le certificat dans Trusted Root, 4) Signe tous les .ps1 avec Set-AuthenticodeSignature, 5) Vérifier avec Get-AuthenticodeSignature. Fichiers : sign_scripts.ps1 (script principal), sign_all.bat (wrapper batch), SIGNATURE_GUIDE.md (documentation). Version 1.36.2+.
