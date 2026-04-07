# 📦 Core — Module Central

**Répertoire :** `core/`

---

## 🎯 Rôle

Le répertoire `core/` contient tous les **modules utilitaires** essentiels au fonctionnement de l'application AD Web Interface. Il s'agit d'un **package Python** qui centralise la logique métier transversale, indépendante des routes HTTP.

---

## 📁 Structure des Fichiers

| Fichier | Rôle |
|---------|------|
| `__init__.py` | Initialise le package `core` |
| `security.py` | **Sécurité :** CSRF, échappement LDAP, headers HTTP, configuration session |
| `session_crypto.py` | **Chiffrement :** Fernet pour les données sensibles (mots de passe AD) |
| `audit.py` | **Journalisation :** Log des actions administratives (CSV + mémoire) |
| `audit_history.py` | **Historique :** Lecture et filtrage des logs d'audit |
| `granular_permissions.py` | **RBAC :** 40 permissions granulaires par groupe AD |
| `context_processor.py` | **Jinja2 :** Injection de variables globales (`version`, `dark_mode`, `connected`) |
| `updater.py` | **Mises à jour :** Vérification des releases GitHub |
| `settings_manager.py` | **Configuration :** Lecture/écriture de `settings.json` |
| `features.py` | **Feature flags :** Activation/désactivation de fonctionnalités |
| `ldap_errors.py` | **Traduction :** Codes erreur LDAP → messages utilisateur en français |
| `password_generator.py` | **Génération :** Mots de passe sécurisés côté serveur |
| `translations.py` | **i18n :** Traductions minimales FR/EN |
| `ad_detect.py` | **Détection :** Auto-détection du domaine Active Directory |
| `alerts.py` | **Alertes :** Détection des comptes expirés, bloqués, inactifs |
| `auto_alerts.py` | **Notifications :** Déclenchement automatique des alertes par email |
| `backup.py` | **Sauvegarde :** Backup et restauration de la configuration |
| `dashboard_widgets.py` | **Dashboard :** Données pour les widgets du tableau de bord |
| `debug_utils.py` | **Debug :** Logger et utilitaires de débogage |
| `diagnostic.py` | **Diagnostic :** Tests de connectivité LDAP et réseau |
| `email_notifications.py` | **SMTP :** Envoi d'emails de notification |
| `path_security.py` | **Sécurité :** Validation des chemins de fichiers (anti-traversal) |
| `security_audit.py` | **Audit :** Détection de 8 problèmes de sécurité AD |

---

## 🔑 Modules Principaux

### 1. `security.py` — Sécurité HTTP & LDAP

```python
from core.security import (
    generate_csrf_token,      # Génération token CSRF
    validate_csrf_token,      # Validation token CSRF
    escape_ldap_filter,       # Échappement caractères LDAP
    add_security_headers,     # Headers CSP, X-Frame-Options, HSTS
    get_secure_session_config # Configuration cookie sécurisée
)
```

**Fonctions clés :**
- Protection CSRF sur tous les formulaires POST
- Échappement des filtres LDAP pour prévenir les injections
- Headers de sécurité HTTP (CSP, HSTS, X-Content-Type-Options...)
- Configuration des cookies de session (HttpOnly, Secure, SameSite)

---

### 2. `session_crypto.py` — Chiffrement des Sessions

```python
from core.session_crypto import init_crypto, encrypt_session_data, decrypt_session_data
```

**Caractéristiques :**
- Utilise **Fernet** (cryptography robuste)
- Sel stocké dans `core/data/crypto_salt.bin`
- Chiffre les mots de passe AD en session
- Initialisé au démarrage de l'application

---

### 3. `audit.py` — Journal d'Audit

```python
from core.audit import log_action, ACTIONS

log_action(
    action=ACTIONS['CREATE_USER'],
    username='admin',
    details={'dn': 'CN=John,OU=Users...', 'name': 'John'},
    success=True,
    ip_address='192.168.1.100'
)
```

**Stockage :**
- Fichier CSV : `data/audit_log.csv`
- Mémoire : pour consultation via l'interface
- Champs : timestamp, action, utilisateur, détails, succès/échec, IP

---

### 4. `granular_permissions.py` — Permissions Granulaires

```python
from core.granular_permissions import (
    get_user_permissions,   # Récupère les permissions d'un utilisateur
    has_permission,         # Vérifie une permission spécifique
    PERMISSIONS             # Liste des 40 permissions
)
```

**Catégories de permissions :**
- `users:*` — Gestion des utilisateurs (read, write, delete, move, reset_password)
- `groups:*` — Gestion des groupes
- `computers:*` — Gestion des ordinateurs
- `ous:*` — Gestion des OUs
- `tools:*` — Outils (LAPS, BitLocker, audit)
- `admin:*` — Administration

---

### 5. `settings_manager.py` — Gestion des Paramètres

```python
from core.settings_manager import load_settings, save_settings, reset_settings

settings = load_settings()  # Charge data/settings.json
settings['site']['title'] = 'Mon AD'
save_settings(settings)
```

**Structure de `settings.json` :**
```json
{
  "site": { "title", "logo", "footer", "theme_color" },
  "menu": { "items", "dropdown_items" },
  "features": { "dark_mode", "language_switch", "update_check", "pwa_enabled" },
  "security": { "session_timeout", "max_login_attempts", "require_https" },
  "smtp": { "enabled", "server", "port", "use_tls", "username", "password" },
  "password": { "default_password", "complexity", "length" }
}
```

---

## 📊 Données Runtime

Le sous-répertoire `core/data/` contient :

| Fichier | Rôle |
|---------|------|
| `crypto_salt.bin` | Sel de chiffrement Fernet (généré au 1er démarrage) |

**Ignoré par Git** via `.gitignore` — généré automatiquement.

---

## 🔧 Utilisation dans les Routes

```python
# Exemple dans routes/users/create.py
from core.security import validate_csrf_token, escape_ldap_filter
from core.audit import log_action, ACTIONS
from core.session_crypto import encrypt_session_data
from core.granular_permissions import require_permission
from core.ldap_errors import format_ldap_error
```

---

## ⚠️ Points Importants

### 1. Ordre d'Initialisation

```python
# Dans app.py — L'ordre est CRITIQUE
from core.session_crypto import init_crypto
init_crypto(config.SECRET_KEY)  # Doit être appelé avant toute route
```

### 2. Chemin du Sel de Chiffrement

```python
# Dans session_crypto.py
SALT_FILE = Path(__file__).parent.parent / 'data' / 'crypto_salt.bin'
# ↑ Utilise .parent.parent car core/ → data/
```

### 3. Imports Corrects

```python
# ✅ CORRECT
from core.security import validate_csrf_token
from core.audit import log_action

# ❌ FAUX (ImportError)
from security import validate_csrf_token
from audit import log_action
```

---

## 🧪 Tests

Les modules core sont testés indirectement via les tests d'intégration dans `tests/`.

---

## 📝 Bonnes Pratiques

1. **Pas de logique HTTP** dans `core/` — uniquement de la logique métier
2. **Fonctions pures** quand c'est possible (pas d'effets de bord)
3. **Logging** via `logging.getLogger(__name__)`
4. **Gestion d'erreurs** avec messages utilisateur via `ldap_errors.py`
5. **Documentation** des fonctions avec docstrings

---

## 🔄 Flux Typique

```
Requête HTTP (routes/)
    ↓
Validation CSRF (core/security.py)
    ↓
Vérification Permission (core/granular_permissions.py)
    ↓
Opération LDAP (ldap3)
    ↓
Log Action (core/audit.py)
    ↓
Réponse HTTP
```

---

**Version :** 1.35.0  
**Mainteneur :** Équipe AD Web Interface
