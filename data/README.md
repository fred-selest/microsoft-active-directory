# 📂 Data — Données Persistantes

**Répertoire :** `data/`

---

## 🎯 Rôle

Le répertoire `data/` stocke toutes les **données persistantes** de l'application : configurations, logs d'audit, sauvegardes, historiques, et thèmes personnalisés.

**Important :** Ce répertoire est **ignoré par Git** (sauf structure vide) pour des raisons de sécurité et de confidentialité.

---

## 📁 Structure

```
data/
├── settings.json             # Configuration de l'application
├── permissions.json          # Permissions granulaires par groupe AD
├── audit_log.csv             # Journal des actions (CSV)
├── crypto_salt.bin           # Sel de chiffrement Fernet (généré auto)
│
├── audit_history/            # Historique complet d'audit
│   ├── audit_2025-01.csv
│   ├── audit_2025-02.csv
│   └── ...
│
├── history/                  # Historique des actions
│   └── ...
│
├── backups/                  # Sauvegardes de configuration
│   ├── backup_20250101_120000.json
│   ├── backup_20250102_143022.json
│   └── ...
│
└── themes/                   # Thèmes personnalisés
    ├── dark_theme.json
    ├── light_theme.json
    └── custom_theme.json
```

---

## 📄 Fichiers Principaux

### 1. `settings.json` — Configuration

**Rôle :** Stocke tous les paramètres de l'application configurables via l'interface d'administration.

**Structure :**
```json
{
  "site": {
    "title": "AD Web Interface",
    "logo": "logo.png",
    "footer": "© 2025 - Société XYZ",
    "theme_color": "#0078d4"
  },
  
  "menu": {
    "items": [
      {
        "id": "dashboard",
        "label": "Tableau de bord",
        "enabled": true,
        "order": 1
      },
      {
        "id": "users",
        "label": "Utilisateurs",
        "enabled": true,
        "order": 2
      }
    ],
    "dropdown_items": [
      {
        "id": "tools",
        "label": "Outils",
        "enabled": true,
        "order": 1
      }
    ]
  },
  
  "features": {
    "dark_mode": true,
    "language_switch": false,
    "update_check": true,
    "pwa_enabled": true
  },
  
  "security": {
    "session_timeout": 30,
    "max_login_attempts": 5,
    "require_https": false
  },
  
  "smtp": {
    "enabled": false,
    "server": "smtp.company.com",
    "port": 587,
    "use_tls": true,
    "use_auth": true,
    "username": "adweb@company.com",
    "password": "***ENCRYPTED***",
    "from_email": "adweb@company.com",
    "from_name": "AD Web Interface"
  },
  
  "password": {
    "default_password": "P@ssw0rd123!",
    "password_complexity": "high",
    "password_length": 16,
    "exclude_ambiguous_chars": true,
    "must_change_at_next_login": true
  }
}
```

**Modification :**
- Via l'interface : `/admin`
- Manuellement : Éditer le fichier JSON (service arrêté)
- API : `POST /admin/save/*`

---

### 2. `permissions.json` — Permissions Granulaires

**Rôle :** Définit les permissions accordées à chaque groupe AD.

**Structure :**
```json
{
  "enabled": true,
  "default_role": "readonly",
  "groups": {
    "CN=Admins,OU=Groups,DC=corp,DC=local": {
      "role": "admin",
      "permissions": [
        "users:read",
        "users:write",
        "users:delete",
        "users:move",
        "users:reset_password",
        "groups:read",
        "groups:write",
        "groups:delete",
        "computers:read",
        "computers:write",
        "ous:read",
        "ous:write",
        "tools:laps",
        "tools:bitlocker",
        "tools:audit",
        "admin:settings"
      ]
    },
    "CN=HelpDesk,OU=Groups,DC=corp,DC=local": {
      "role": "operator",
      "permissions": [
        "users:read",
        "users:write",
        "users:reset_password",
        "computers:read",
        "tools:audit"
      ]
    }
  }
}
```

**40 Permissions Disponibles :**

| Catégorie | Permissions |
|-----------|-------------|
| `users:*` | `read`, `write`, `delete`, `move`, `reset_password`, `create`, `bulk_import`, `bulk_delete`, `export` |
| `groups:*` | `read`, `write`, `delete`, `create`, `manage_members` |
| `computers:*` | `read`, `write`, `delete`, `move`, `toggle` |
| `ous:*` | `read`, `write`, `delete`, `create` |
| `tools:*` | `laps`, `bitlocker`, `audit`, `backups`, `locked_accounts`, `expiring_accounts`, `recycle_bin`, `diagnostic`, `password_policy`, `password_audit` |
| `admin:*` | `settings`, `permissions`, `users_management`, `audit_logs`, `security_audit`, `alerts`, `reports` |

**Rôles Prédéfinis :**
- `admin` — Toutes les permissions
- `operator` — Lecture + écriture limitée
- `readonly` — Lecture seule
- `custom` — Permissions personnalisées

---

### 3. `audit_log.csv` — Journal des Actions

**Rôle :** Enregistre toutes les actions administratives pour traçabilité.

**Format CSV :**
```csv
timestamp,action,username,details,success,ip_address
2025-01-15 10:30:45,CREATE_USER,admin,"{""dn"": ""CN=John,OU=Users..."", ""name"": ""John""}",true,192.168.1.100
2025-01-15 10:32:12,RESET_PASSWORD,admin,"{""user"": ""john.doe""}",true,192.168.1.100
2025-01-15 10:35:00,DELETE_USER,admin,"{""dn"": ""CN=Old,OU=Users...""}",false,192.168.1.100
```

**Colonnes :**
| Colonne | Description |
|---------|-------------|
| `timestamp` | Date et heure (YYYY-MM-DD HH:MM:SS) |
| `action` | Type d'action (CREATE_USER, DELETE_GROUP, etc.) |
| `username` | Utilisateur ayant effectué l'action |
| `details` | Détails JSON de l'action |
| `success` | `true` ou `false` |
| `ip_address` | IP de la machine cliente |

**Actions Trackées :**
- `CREATE_USER`, `UPDATE_USER`, `DELETE_USER`, `MOVE_USER`, `RESET_PASSWORD`
- `CREATE_GROUP`, `UPDATE_GROUP`, `DELETE_GROUP`, `ADD_MEMBER`, `REMOVE_MEMBER`
- `CREATE_COMPUTER`, `UPDATE_COMPUTER`, `DELETE_COMPUTER`, `TOGGLE_COMPUTER`
- `CREATE_OU`, `UPDATE_OU`, `DELETE_OU`
- `LOGIN`, `LOGOUT`, `FAILED_LOGIN`
- `SETTINGS_CHANGE`, `PERMISSION_CHANGE`
- `LAPS_READ`, `BITLOCKER_READ`
- `AUDIT_EXPORT`, `BACKUP_CREATE`, `BACKUP_RESTORE`

**Consultation :**
- Interface : `/audit`
- Fichier : `data/audit_log.csv`
- API : `GET /api/audit`

---

### 4. `crypto_salt.bin` — Sel de Chiffrement

**Rôle :** Sel pour le chiffrement Fernet des données de session (mots de passe AD).

**Caractéristiques :**
- Généré automatiquement au premier démarrage
- 32 octets aléatoires
- **Ne jamais modifier** (perdrait toutes les sessions actives)
- **Sauvegarder** avec la configuration

**Emplacement :**
```
core/data/crypto_salt.bin
```

**⚠️ Important :**
- Si perdu → toutes les sessions actives sont invalidées
- Si modifié → les mots de passe chiffrés ne peuvent plus être déchiffrés
- À inclure dans les backups

---

## 📂 Sous-Répertoires

### 1. `audit_history/` — Historique Complet

**Rôle :** Archive mensuelle des logs d'audit.

**Format :**
```
audit_YYYY-MM.csv
```

**Rotation :**
- Nouveau fichier chaque mois
- Conservation configurable (défaut : 12 mois)
- Export PDF/Excel possible

---

### 2. `backups/` — Sauvegardes

**Rôle :** Sauvegardes automatiques et manuelles de la configuration.

**Nomming :**
```
backup_YYYYMMDD_HHMMSS.json
```

**Contenu :**
- `settings.json` complet
- `permissions.json` complet
- Métadonnées (date, utilisateur, version)

**Création :**
- Automatique : quotidienne à 2h00
- Manuelle : via `/admin` → "Sauvegarder"

**Restauration :**
```python
from core.backup import restore_backup
restore_backup('data/backups/backup_20250101_120000.json')
```

---

### 3. `history/` — Historique des Actions

**Rôle :** Historique détaillé pour fonctionnalités avancées.

**Utilisation :**
- Comparaison d'utilisateurs
- Suivi des modifications
- Rollback de changements

---

### 4. `themes/` — Thèmes Personnalisés

**Rôle :** Thèmes CSS personnalisés.

**Structure :**
```json
{
  "name": "Mon Thème",
  "variables": {
    "--primary": "#ff6600",
    "--primary-dark": "#cc5200",
    "--bg-primary": "#ffffff",
    "--text-primary": "#333333"
  }
}
```

**Application :**
- Via l'interface : `/admin/theme`
- API : `POST /admin/theme/apply`

---

## 🔒 Sécurité

### 1. Permissions Fichier

Le répertoire `data/` doit être lisible/inscriptible uniquement par :
- Le compte de service Windows
- Les administrateurs

**Commande PowerShell :**
```powershell
$acl = Get-Acl "C:\AD-WebInterface\data"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM",
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl "C:\AD-WebInterface\data" $acl
```

---

### 2. Chiffrement des Mots de Passe

Les mots de passe SMTP dans `settings.json` sont chiffrés :

```json
{
  "smtp": {
    "password": "gAAAAABhZ..."  // Chiffré avec Fernet
  }
}
```

**Déchiffrement automatique** au chargement par `settings_manager.py`.

---

### 3. Backup du Sel

**⚠️ CRITIQUE :** Sauvegarder `crypto_salt.bin` avec :
- `settings.json`
- `permissions.json`

Sans le sel, les sessions actives sont perdues.

---

## 🔄 Rotation des Logs

### Audit Log

```python
# Dans core/audit.py
def rotate_audit_log():
    """Archive le log mensuel et crée un nouveau fichier."""
    now = datetime.now()
    archive_name = f"audit_{now.year}-{now.month:02d}.csv"
    
    # Déplacer vers audit_history/
    shutil.move('data/audit_log.csv', f'data/audit_history/{archive_name}')
    
    # Créer nouveau fichier
    with open('data/audit_log.csv', 'w', encoding='utf-8') as f:
        f.write('timestamp,action,username,details,success,ip_address\n')
```

---

## 📊 API de Gestion

### Charger les Paramètres

```python
from core.settings_manager import load_settings, save_settings

settings = load_settings()
settings['site']['title'] = 'Nouveau Titre'
save_settings(settings)
```

### Charger les Permissions

```python
from core.granular_permissions import get_user_permissions

permissions = get_user_permissions('john.doe')
# → ['users:read', 'users:write', ...]
```

### Exporter la Configuration

```bash
curl http://localhost:5000/admin/export -o ad_settings.json
```

---

## 🧪 Tests

```bash
pytest tests/test_settings.py
pytest tests/test_permissions.py
pytest tests/test_audit.py
pytest tests/test_backup.py
```

---

## ⚠️ Pièges Connus

### 1. Fichier Verrouillé

**Erreur :** `PermissionError: [WinError 32]`

**Cause :** Le service utilise le fichier.

**Solution :**
```powershell
# Arrêter le service
.\nssm\ADWebInterface.exe stop

# Modifier le fichier

# Redémarrer
.\nssm\ADWebInterface.exe start
```

---

### 2. JSON Invalide

**Erreur :** `json.JSONDecodeError`

**Cause :** Fichier JSON mal formé.

**Solution :**
- Utiliser un validateur JSON (jsonlint.com)
- Vérifier les virgules, guillemets, crochets

---

### 3. Sel Manquant

**Erreur :** `FileNotFoundError: crypto_salt.bin`

**Solution :**
```python
# Le sel est régénéré automatiquement
# Mais les sessions actives seront perdues
from core.session_crypto import init_crypto
init_crypto(config.SECRET_KEY)
```

---

## 📝 Bonnes Pratiques

### 1. Sauvegardes Régulières

```powershell
# Script de backup quotidien
$today = Get-Date -Format "yyyyMMdd_HHmmss"
Copy-Item "C:\AD-WebInterface\data\settings.json" "C:\Backups\ADWeb\$today.json"
Copy-Item "C:\AD-WebInterface\data\crypto_salt.bin" "C:\Backups\ADWeb\$today.bin"
```

### 2. Rotation des Logs

Conserver maximum 12 mois d'historique d'audit.

### 3. Monitoring

Surveiller :
- Taille de `audit_log.csv` (> 100 Mo → rotation)
- Espace disque `data/`
- Permissions d'accès

---

**Version :** 1.35.0  
**Mainteneur :** Équipe AD Web Interface
