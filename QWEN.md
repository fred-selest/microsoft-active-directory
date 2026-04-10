# QWEN.md — Guide d'architecture pour assistants IA

> Ce fichier décrit l'architecture interne du projet **AD Web Interface** à l'intention des assistants IA (Claude, Qwen, GPT…) afin d'accélérer la compréhension du code et d'éviter les erreurs courantes.

**Version actuelle :** 1.44.0 (Avril 2026)

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

## 10. Système de mise à jour (`core/updater.py`)

### Architecture v2.0 (Avril 2026)

Le système de mise à jour a été entièrement repensé pour être plus rapide et plus robuste.

**Fonctionnalités principales :**
- **Téléchargement parallèle** : Utilisation de `ThreadPoolExecutor` pour télécharger plusieurs fichiers simultanément (défaut: 4 workers)
- **Cache intelligent** : Les informations de version et la liste des fichiers sont mises en cache pendant 5 minutes pour éviter les requêtes répétées
- **Statistiques de mise à jour** : La fonction `get_update_statistics()` fournit un résumé avant la mise à jour (nombre de fichiers, taille totale, types)
- **Gestion robuste des erreurs** : Retries automatiques, logging détaillé, rapport d'erreurs
- **Préservation des fichiers sensibles** : Les dossiers `.env`, `logs`, `data`, `venv`, `__pycache__`, `.git` sont exclus

**Fonctions clés :**

| Fonction | Description |
|----------|-------------|
| `get_current_version()` | Lit la version locale depuis le fichier `VERSION` |
| `get_remote_version()` | Récupère la version distante (avec cache 5 min) |
| `get_file_list()` | Liste tous les fichiers du repo GitHub avec SHA et taille (avec cache) |
| `perform_update_parallel(max_workers=4)` | Mise à jour avec téléchargement parallèle (recommandé) |
| `perform_update()` | Alias vers `perform_update_parallel(max_workers=1)` pour compatibilité |
| `check_for_updates_fast()` | Vérification rapide de disponibilité (utilise le cache) |
| `perform_fast_update(silent=False, max_workers=4)` | Mise à jour complète avec options |
| `get_update_statistics()` | Statistiques détaillées avant mise à jour |

**Utilisation en ligne de commande :**
```bash
python core/updater.py
```

**Utilisation via API :**
- `GET /api/check-update` — Vérifie les mises à jour disponibles
- `POST /api/perform-update` — Applique la mise à jour (nécessite permission admin)

**Performances :**
- Ancienne version : ~60-120 secondes pour 200 fichiers (séquentiel)
- Nouvelle version : ~15-30 secondes pour 200 fichiers (4 workers parallèles)
- Gain : **3-4x plus rapide** selon la connexion réseau

**Exemple d'utilisation programmatique :**
```python
from core.updater import check_for_updates_fast, perform_fast_update, get_update_statistics

# Vérifier les mises à jour
update_info = check_for_updates_fast()
if update_info['update_available']:
    # Afficher les statistiques
    stats = get_update_statistics()
    print(f"{stats['total_files']} fichiers à mettre à jour")
    print(f"Taille totale: {stats['total_size_mb']:.2f} Mo")
    
    # Appliquer la mise à jour
    result = perform_fast_update(max_workers=4)
    if result['success']:
        print(f"Mise à jour réussie: {result['files_updated']} fichiers")
    else:
        print(f"Erreurs: {result['errors']}")
```

**Améliorations par rapport à l'ancienne version :**
1. ✅ Parallélisation des téléchargements (4 workers par défaut)
2. ✅ Cache des requêtes GitHub (5 minutes) pour éviter les rate limits
3. ✅ Statistiques détaillées avant mise à jour (taille, nombre, types de fichiers)
4. ✅ Meilleure gestion des erreurs avec rapport détaillé
5. ✅ User-Agent personnalisé pour les requêtes GitHub
6. ✅ Timeout sur les subprocess (pip install)
7. ✅ Affichage du temps total de téléchargement
8. ✅ Protection améliorée avec plus de dossiers exclus (.github)

---

## 11. Pièges connus / Historique des bugs

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
| Mise à jour lente/timout | Ancienne version séquentielle sans cache | Utiliser `perform_update_parallel()` (v2.0+) |

---

## 12. Conventions de code

- **Encoding :** UTF-8, commentaires en français
- **Logging :** `import logging; logger = logging.getLogger(__name__)`
- **Flash messages :** catégories `'success'`, `'error'`, `'warning'`, `'info'`
- **Redirection après POST :** toujours via `redirect(url_for(...))` (pattern PRG)
- **Libération connexion LDAP :** toujours `conn.unbind()` dans un bloc `finally`
- **Templates :** étendent `base.html`, définissent `{% block title %}`, `{% block content %}`, optionnellement `{% block extra_css %}` et `{% block extra_js %}` (toujours à la **racine** du fichier, jamais imbriqués)
- **Mises à jour :** Toujours utiliser `perform_update_parallel()` plutôt que `perform_update()` pour de meilleures performances

## Qwen Added Memories
- Procédure de release Git pour AD Web Interface : 1) Mettre à jour fichier VERSION, 2) Commit avec message "chore: Bump version to X.Y.Z", 3) Créer tag annoté "git tag -a vX.Y.Z -m "Version X.Y.Z - Mois YYYY"", 4) Pousser main "git push origin main", 5) Pousser tag explicitement "git push origin vX.Y.Z" (JAMAIS --tags), 6) Vérifier sur GitHub "git ls-remote --tags origin". Ne jamais utiliser "git push --tags" car cela peut échouer avec des tags existants. Toujours pousser les tags individuellement.
- Procédure de signature des scripts PowerShell pour AD Web Interface : 1) Utiliser scripts\sign_all.bat (en admin) OU scripts\sign_scripts.ps1, 2) Le script crée automatiquement un certificat auto-signé dans Cert:\LocalMachine\My, 3) Importe le certificat dans Trusted Root, 4) Signe tous les .ps1 avec Set-AuthenticodeSignature, 5) Vérifier avec Get-AuthenticodeSignature. Fichiers : sign_scripts.ps1 (script principal), sign_all.bat (wrapper batch), SIGNATURE_GUIDE.md (documentation). Version 1.36.2+.
- ⚠️ IMPORTANT : Toujours vérifier que le fichier VERSION est à jour AVANT de commit/push. Après toute modification de code, mettre à jour VERSION (patch pour corrections, mineure pour features, majeure pour breaking changes). Le fichier VERSION doit toujours refléter la version réelle du code poussé sur GitHub.
- Procédure pour créer une release GitHub proprement : 1) git push origin main (vérifier avec origin/main..HEAD vide), 2) git tag -a vX.Y.Z -m "message", 3) git push origin vX.Y.Z IMMÉDIATEMENT après le push main — AVANT que GitHub ne crée automatiquement une release immutable. IMPORTANT : Ne JAMAIS pousser le tag après que GitHub ait créé une release automatique car elle devient immutable. Si le tag existe déjà sur le remote, utiliser l'interface web GitHub pour éditer la release manuellement. Alternative : configurer les règles du repo pour permettre la suppression de tags.

---
- Règle absolue : NE JAMAIS commiter ou pusher une correction de bug sans d'abord l'avoir testée localement. Toujours : 1) Appliquer la correction, 2) Redémarrer le service (.\nssm\ADWebInterface.exe restart), 3) Tester la page/fonction concernée, 4) Vérifier les logs (Get-Content logs\server.log -Tail 20), 5) SEULEMENT SI ça fonctionne → commit + push.

## 13. Fichiers manquants

Les fichiers suivants sont documentés dans le QWEN.md mais **n'existent pas physiquement** dans le projet :

| Fichier documenté | Statut | Alternative |
|-------------------|--------|-------------|
| `core/data/audit_history/` (répertoire) | ✅ Existe mais vide par défaut | Historique mensuel généré automatiquement |
| `static/js/display-debugger.js` | ⚠️ Existe mais usage inconnu | Outil de debug CSS — non critique |
| `static/icons/icon-192.png` / `icon-512.png` | ⚠️ À vérifier | Icônes PWA |
| `static/manifest.webmanifest` | ⚠️ À vérifier | Manifeste PWA |
| `static/sw.js` | ⚠️ À vérifier | Service Worker PWA |
| `data/backups/` (répertoire) | ✅ Existe mais vide par défaut | Sauvegardes générées automatiquement |
| `data/themes/` (répertoire) | ❌ N'existe pas | Thèmes personnalisés — non implémenté |
| `data/history/` (répertoire) | ❌ N'existe pas | Historique actions — non implémenté |
| `templates/partials/_navbar.html` | ❌ N'existe pas (navbar inline dans base.html) | — |
| `templates/partials/_sidebar.html` | ❌ N'existe pas (sidebar inline dans base.html) | — |
| `templates/partials/_alerts.html` | ❌ N'existe pas (alerts inline dans base.html) | — |
| `templates/partials/_footer.html` | ❌ N'existe pas (footer inline dans base.html) | — |
| `templates/partials/_pagination.html` | ❌ N'existe pas (pagination inline) | — |

> **Note :** Les partials listés ci-dessus sont intégrés directement dans `base.html` au lieu d'être des fichiers séparés. Ce n'est pas un bug mais une différence par rapport à la documentation.

---

## 14. Audit des bugs identifiés (Avril 2026)

### 🔴 Critical — À corriger immédiatement

| # | Fichier | Bug | Impact |
|---|---------|-----|--------|
| C1 | `routes/tools/accounts.py` | Conversion FILETIME incorrecte pour dates expiry/inactif | Toutes les dates de comptes expirés sont fausses |
| C2 | `routes/main.py` | Timestamp `lastLogon` mal converti dans alerts_page | Alertes comptes inactifs incorrectes |
| C3 | `routes/tools/laps.py` | Variables domaine non échappées avant appel PowerShell | Injection de commande potentielle |
| C4 | `routes/api.py:6` | `download_file` sans validation taille max fichier | Disque plein possible (fichier 500MB+) |
| C5 | `routes/tools/password.py` | Connexion LDAP non fermée dans `finally` si exception PDF | Fuite de connexions |

### 🟠 High — À corriger cette semaine

| # | Fichier | Bug | Impact |
|---|---------|-----|--------|
| H1 | `routes/main.py` dashboard | Pas de `size_limit` sur recherches LDAP | Crash si AD > 10k objets |
| H2 | `routes/users/list_users.py` | Pas de pagination LDAP | Charge tous les users en mémoire |
| H3 | `routes/groups/__init__.py` | Requête N+1 par membre de groupe | 500 membres = 500 requêtes |
| H4 | `routes/ous/__init__.py` | 4 requêtes LDAP par OU pour stats | 50 OUs = 200 requêtes |
| H5 | `routes/admin/__init__.py` | Logo upload sans `secure_filename` | Path traversal possible |
| H6 | `routes/tools/misc.py` | Clés API stockées en clair dans session | Exposition si session compromise |
| H7 | `core/updater.py` | Healthcheck trop léger (juste import app) | Serveur cassé non détecté |
| H8 | `routes/api.py` | Endpoint `/api/update/progress` public | Info update visible sans auth |

### 🟡 Medium — Prochain sprint

| # | Fichier | Problème | Impact |
|---|---------|----------|--------|
| M1 | `core/context_processor.py` | `inject_globals` appelé à chaque requête sans cache | Surcharge inutile |
| M2 | `routes/tools/password.py` | Password audit relancé à chaque clic (pas de cache) | Surcharge AD |
| M3 | `routes/admin_tools.py` | Page `/update` : 3 appels bloquants séquentiels | Page lente si GitHub injoignable |
| M4 | `core/updater.py` | `get_remote_file_hash()` jamais appelée | Code mort |
| M5 | `routes/groups/__init__.py` | `print()` debug laissés (supprimés en v1.39) | Logs pollués |
| M6 | `routes/api.py` | `_update_progress` dict global mutable | Race condition (fixé en v1.40) |

### 🟢 Low — Dette technique

| # | Fichier | Problème | Impact |
|---|---------|----------|--------|
| L1 | Plusieurs routes | Imports `from .core import` mélangés avec `from core.` | Incohérence style |
| L2 | `routes/admin/__init__.py` | Dict settings par défaut codé en dur (30+ lignes) | Maintenance difficile |
| L3 | `routes/tools/password.py` | Fonction PDF de 190 lignes | Non testable, non maintenable |
| L4 | `routes/admin_tools.py` | `alerts_page` de 220 lignes avec 8 try/except imbriqués | Découpage nécessaire |
| L5 | `routes/debug/__init__.py` | `import requests` non dans requirements.txt | Import optionnel non protégé |

---

## 15. Roadmap des nouveautés à venir

### v1.41 — Corrections urgentes (Semaine prochaine)

- [ ] **C1** : Fix conversion FILETIME dates comptes expirés/inactifs
- [ ] **C2** : Fix timestamp `lastLogon` dans alerts_page
- [ ] **C3** : Échappement variables domaine avant appel PowerShell (LAPS)
- [ ] **C4** : Validation taille max fichiers téléchargés (50MB)
- [ ] **C5** : `try/finally` avec `conn.unbind()` dans export PDF
- [ ] **H1-H4** : `size_limit` + pagination LDAP sur toutes les recherches
- [ ] **H5** : `secure_filename()` sur upload logo
- [ ] **H6** : Hash des clés API en session (plus de stockage brut)
- [ ] **H7** : Healthcheck amélioré (test routes critiques + LDAP)
- [ ] **H8** : `@require_connection` sur `/api/update/progress`

### v1.42 — Performance & Stabilité (Mois prochain)

- [ ] **Recherche LDAP paginée** — `paged_search` sur /users, /groups, /computers, /ous
- [ ] **Batch search membres groupes** — 1 requête au lieu de N pour les membres
- [ ] **Comptage OU optimisé** — 1 recherche par type au lieu de 4 par OU
- [ ] **Cache password audit** — Résultats cachés 5 min
- [ ] **Cache context_processor** — `inject_globals` optimisé
- [ ] **Page /update asynchrone** — Appels GitHub en AJAX côté client
- [ ] **Suppression code mort** — `get_remote_file_hash()`, `print()` debug restants
- [ ] **Refactoring** — Découper fonctions >100 lignes (PDF, alerts_page)

### v1.43 — Sécurité renforcée

- [ ] **Middleware CSRF global** — Decorateur automatique pour toutes les API POST/DELETE
- [ ] **Chiffrement Fernet SMTP password** — Plus de stockage en clair dans settings.json
- [ ] **Restart graceful** — Signal propre au lieu de `os._exit(0)`
- [ ] **Audit sécurité étendu** — 8 → 12 contrôles (Kerberos, DCSync, Shadow Credentials)
- [ ] **Rate limiting thread-safe** — Fonctionne across Waitress threads
- [ ] **2FA TOTP** — Support authentification 2 facteurs pour les admins
- [ ] **Validation scripts PowerShell** — Vérification intégrité avant exécution

### v1.44 — Features utilisateur

- [ ] **Recherche globale** — Barre unifiée (users + groups + computers + OUs)
- [ ] **Favoris AD** — Marquer des objets comme favoris
- [ ] **Historique modifications** — Timeline des changements par objet
- [ ] **Export CSV universel** — Sur toutes les listes (users, groups, computers, OUs)
- [ ] **Bulk operations** — Sélection multiple + actions en masse
- [ ] **Templates création** — Modèles prédéfinis pour utilisateurs
- [ ] **Notifications navigateur** — Fin de mise à jour, comptes verrouillés

### v1.45 — Infrastructure

- [ ] **Multi-serveur sync** — Sync config entre srv-dc01 et srv-dc02
- [ ] **Monitoring externe** — Endpoint `/api/health` pour Prometheus/Grafana
- [ ] **Backup planifié** — Quotidien avec rétention configurable
- [ ] **Rollback points** — Points de restauration avant chaque update
- [ ] **API REST documentée** — OpenAPI/Swagger automatique
- [ ] **Docker support** — Containerisation optionnelle

### v1.46 — Long terme

- [ ] **Kerberos auth** — Remplacer NTLM par Kerberos
- [ ] **SCIM provisioning** — Provisioning automatique depuis HR system
- [ ] **SSO Azure AD / Entra ID** — Intégration cloud
- [ ] **Webhooks** — Notifications sur événements AD (création, suppression, verrouillage)
- [ ] **Rapports planifiés** — Envoi auto par email (hebdo/mensuel)
- [ ] **Internationalisation** — Support complet EN + ES + DE
- [ ] **Thèmes personnalisés** — Interface de création de thèmes (dossier `data/themes/`)
