# 🛣️ Routes — Blueprints Flask

**Répertoire :** `routes/`

---

## 🎯 Rôle

Le répertoire `routes/` contient tous les **blueprints Flask** qui définissent les endpoints HTTP de l'application. Chaque blueprint gère un domaine fonctionnel spécifique (utilisateurs, groupes, ordinateurs, etc.).

---

## 📁 Architecture

```
routes/
├── __init__.py           # Package routes
├── core.py               # Helpers partagés (connexion AD, décorateurs)
├── main.py               # Blueprint principal (accueil, connexion)
├── api.py                # Endpoints JSON/API REST
├── admin_tools.py        # Outils d'administration (permissions, settings)
│
├── users/                # Gestion des utilisateurs AD
│   ├── __init__.py       # Déclaration du blueprint users_bp
│   ├── list_users.py     # GET /users/
│   ├── create.py         # GET/POST /users/create
│   ├── update.py         # GET/POST /users/<dn>/edit
│   ├── delete.py         # POST /users/<dn>/delete
│   ├── password.py       # POST /users/<dn>/password
│   ├── move.py           # POST /users/<dn>/move
│   ├── helpers.py        # Fonctions utilitaires partagées
│   └── validators.py     # Validation des données (dataclasses)
│
├── groups/               # Gestion des groupes AD
│   └── __init__.py       # Blueprint complet (list, create, edit, delete)
│
├── computers/            # Gestion des ordinateurs
│   └── __init__.py       # Blueprint complet
│
├── ous/                  # Gestion des Unités Organisationnelles
│   └── __init__.py       # Blueprint complet
│
├── tools/                # Outils avancés
│   ├── __init__.py       # Déclaration du blueprint tools_bp
│   ├── laps.py           # Gestion LAPS
│   ├── bitlocker.py      # Clés BitLocker
│   ├── accounts.py       # Comptes bloqués/expirés
│   ├── password.py       # Audit des mots de passe
│   ├── backups.py        # Sauvegardes AD
│   └── misc.py           # Outils divers
│
├── admin/                # Administration
│   └── __init__.py       # Page admin (settings, SMTP, menu)
│
└── debug/                # Debug (développement uniquement)
    └── __init__.py       # Routes de débogage
```

---

## 🗺️ Blueprints Enregistrés

| Blueprint | Préfixe URL | Fichier | Description |
|-----------|-------------|---------|-------------|
| `main_bp` | `/` | `main.py` | Accueil, connexion, déconnexion, dashboard |
| `users_bp` | `/users` | `users/__init__.py` | CRUD utilisateurs |
| `groups_bp` | `/groups` | `groups/__init__.py` | CRUD groupes |
| `computers_bp` | `/computers` | `computers/__init__.py` | CRUD ordinateurs |
| `ous_bp` | `/ous` | `ous/__init__.py` | CRUD OUs |
| `tools_bp` | `/tools` | `tools/__init__.py` | LAPS, BitLocker, audit |
| `admin_bp` | `/admin` | `admin/__init__.py` | Administration |
| `debug_bp` | `/_debug` | `debug/__init__.py` | Debug (réservé admin) |
| `api_bp` | `/api` | `api.py` | API JSON |
| `admin_tools_bp` | `/` | `admin_tools.py` | Permissions, settings |

---

## 🔑 Module `core.py` — Helpers Partagés

Ce fichier fournit des fonctions et décorateurs utilisés par tous les blueprints.

### Connexion Active Directory

```python
from routes.core import get_ad_connection, is_connected

# Obtenir une connexion LDAP
conn, error = get_ad_connection()
if not conn:
    # Gérer l'erreur
```

**Session Flask — clés stockées :**

| Clé | Type | Description |
|-----|------|-------------|
| `ad_server` | str | Hostname du contrôleur de domaine |
| `ad_port` | int | Port (389 ou 636) |
| `ad_base_dn` | str | DN de base (ex: `DC=corp,DC=local`) |
| `ad_username` | str | sAMAccountName de l'utilisateur |
| `ad_use_ssl` | bool | True si LDAPS (port 636) |
| `ad_starttls` | bool | True si STARTTLS activé |
| `ad_user_dn` | str | DN complet de l'utilisateur |
| `ad_permissions` | list | Permissions de l'utilisateur |

---

### Décorateurs de Sécurité

```python
from routes.core import require_connection, require_permission

@users_bp.route('/create', methods=['POST'])
@require_connection        # Vérifie que l'utilisateur est connecté
@require_permission('write')  # Vérifie la permission 'write'
def create_user():
    ...
```

**Décorateurs disponibles :**
- `@require_connection` — Redirige vers `/connect` si non connecté
- `@require_permission('permission_name')` — Vérifie une permission RBAC
- `@is_connected()` — Fonction pour templates (afficher navbar, etc.)

---

## 📝 Exemple de Route Complète

```python
# routes/users/create.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from routes.core import get_ad_connection, require_connection, require_permission
from core.security import validate_csrf_token, escape_ldap_filter
from core.audit import log_action, ACTIONS
from .validators import UserCreateRequest

@users_bp.route('/create', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def create_user():
    conn, error = get_ad_connection()
    if not conn:
        return redirect(url_for('main.connect'))
    
    if request.method == 'POST':
        # 1. Validation CSRF
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token CSRF invalide', 'error')
            return render_template('create_user.html')
        
        # 2. Validation des données
        validator = UserCreateRequest(
            username=request.form.get('username'),
            password=request.form.get('password'),
            ou=request.form.get('ou')
        )
        if not validator.validate():
            for err in validator.errors:
                flash(err, 'error')
            return render_template('create_user.html')
        
        # 3. Création LDAP
        try:
            user_dn = f"CN={validator.username},{validator.ou}"
            conn.add(user_dn, attributes={...})
            
            if conn.result['result'] == 0:
                log_action(ACTIONS['CREATE_USER'], session['ad_username'], 
                          {'dn': user_dn}, True, request.remote_addr)
                flash('Utilisateur créé', 'success')
                return redirect(url_for('users.list_users'))
            else:
                flash(f"Erreur: {conn.result['description']}", 'error')
        except Exception as e:
            flash(f'Erreur: {str(e)}', 'error')
        finally:
            conn.unbind()
    
    return render_template('create_user.html')
```

---

## 🔒 Sécurité

### 1. Protection CSRF

Tous les formulaires POST doivent valider le token CSRF :

```python
if not validate_csrf_token(request.form.get('csrf_token')):
    flash('Token CSRF invalide.', 'error')
    return redirect(url_for(...))
```

### 2. Échappement LDAP

```python
from core.security import escape_ldap_filter

safe_query = escape_ldap_filter(user_input)
search_filter = f'(&(objectClass=user)(cn=*{safe_query}*))'
```

### 3. Permissions Granulaires

```python
@require_permission('delete')  # Nécessite la permission 'delete'
def delete_user(dn):
    ...
```

---

## 🧩 Validators (`users/validators.py`)

Le module `validators.py` utilise des **dataclasses** pour valider les données avant création/modification.

```python
from routes.users.validators import UserCreateRequest

validator = UserCreateRequest(
    username='john.doe',
    password='P@ssw0rd123',
    ou='OU=Users,DC=corp,DC=local'
)

if validator.validate():
    # Données valides
else:
    # validator.errors contient les erreurs
```

**Règles de validation :**
- Username : pas de caractères spéciaux LDAP
- Password : complexité configurable
- OU : doit commencer par `DC=`, `OU=`, ou `CN=`

---

## 🛠️ Blueprint `tools/` — Outils Avancés

### LAPS (`laps.py`)

```python
@tools_bp.route('/laps')
@require_connection
def laps_passwords():
    """Liste des mots de passe LAPS."""
    ...
```

### BitLocker (`bitlocker.py`)

```python
@tools_bp.route('/bitlocker')
@require_connection
def bitlocker_keys():
    """Récupération des clés BitLocker."""
    ...
```

### Audit Mots de Passe (`password.py`)

```python
@tools_bp.route('/password-audit')
@require_connection
def password_audit():
    """Analyse de la force des mots de passe."""
    ...
```

---

## 🐛 Debug Blueprint

Le blueprint `debug/` est **réservé aux administrateurs** et uniquement en développement.

**Routes disponibles :**
- `/_debug/` — Dashboard de debug
- `/_debug/api` — Infos en JSON
- `/_debug/routes` — Liste des routes
- `/_debug/session` — Contenu de la session
- `/_debug/logs` — Logs récents
- `/_debug/test/<page>` — Test d'une page

---

## ⚠️ Pièges Connus

### 1. Imports Circulaires

```python
# ❌ FAUX — Import circulaire
from routes.users import users_bp
from routes.core import get_ad_connection

# ✅ CORRECT — Importer après déclaration du blueprint
from routes.core import get_ad_connection
```

### 2. Oubli de `conn.unbind()`

```python
# ✅ TOUJOURS libérer la connexion
try:
    conn.search(...)
finally:
    conn.unbind()
```

### 3. Mauvais Mode pour `unicodePwd`

```python
# ❌ FAUX
conn.modify(user_dn, {'unicodePwd': [(MODIFY_ADD, [pwd])]})

# ✅ CORRECT
conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [pwd])]})
```

### 4. STARTTLS vs LDAPS

```python
# Après connexion réussie :
session['ad_use_ssl'] = use_ssl      # True seulement si port 636
session['ad_starttls'] = starttls    # True seulement si STARTTLS

# Pour vérifier si le canal est chiffré :
can_set_password = session.get('ad_use_ssl', False) or session.get('ad_starttls', False)
```

---

## 🧪 Tests

Les routes sont testées dans le répertoire `tests/` :

```bash
pytest tests/test_users.py
pytest tests/test_connections.py
pytest tests/test_api.py
```

---

## 📊 Flux de Requête

```
1. Requête HTTP → Flask
2. Routing → Blueprint approprié
3. Décorateur @require_connection → Vérifie session
4. Décorateur @require_permission → Vérifie RBAC
5. Validation CSRF (si POST)
6. Validation des données (validators.py)
7. Connexion LDAP (get_ad_connection)
8. Opération LDAP
9. Log action (core/audit.py)
10. Libération connexion (conn.unbind())
11. Réponse HTTP (render_template ou redirect)
```

---

**Version :** 1.35.0  
**Mainteneur :** Équipe AD Web Interface
