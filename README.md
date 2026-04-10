# 🔐 AD Web Interface

> **Interface Web Moderne pour Microsoft Active Directory**

[![Version](https://img.shields.io/github/v/release/fred-selest/microsoft-active-directory?label=Version&color=0078d4)](https://github.com/fred-selest/microsoft-active-directory/releases)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server-0078d4.svg)](https://www.microsoft.com/windows-server)

Gérez votre Active Directory depuis n'importe quel navigateur, sans installation cliente. Fonctionne en tant que service Windows natif.

**Dernière version :** v1.44.0 — Avril 2026

---

## 🆕 Nouveautés v1.44.0

### 🔴 2 Bugs Critical Corrigés
- **C1 — `change_expired_password()` utilisait `base_dn` au lieu du DN utilisateur** — le mot de passe ne pouvait jamais être modifié. Fix : recherche du DN via `sAMAccountName` avant modification.
- **C2 — Fuites de connexions LDAP dans `accounts.py`** — `conn.unbind()` était dans le bloc `try` au lieu de `finally`. Corrigé sur `recycle_bin()`, `locked_accounts()`, `expiring_accounts()`.

### 🟠 3 Bugs High Corrigés
- **H1 — `alerts_page()` fuite de connexion** — `finally: conn.unbind()` ajouté après 6 recherches LDAP.
- **H2 — Exports password audit** — `try/finally: conn.unbind()` sur CSV, JSON et PDF.
- **H3 — `api_ad_search()`** — `finally: conn.unbind()` unifié pour toutes les branches (group/user/ou).

### 🟡 5 Bugs Medium Corrigés
- **M1 — Injection PowerShell dans `laps.py`** — échappement des caractères spéciaux (`'`, `$`, `"`) avant interpolation dans les scripts.
- **M2 — `size_limit` sur `alerts_page()`** — 5 recherches LDAP limitées (100 à 5000 entrées).
- **M3 — `size_limit` sur `dashboard()`** — 3 recherches LDAP limitées (1000 à 5000 entrées).
- **M4 — `change_expired_password()` sans `finally`** — connexion non fermée en cas d'erreur.
- **M5 — Boucle inactive_accounts dupliquée** — la 2e boucle itérait sur Domain Admins au lieu de tous les users. Supprimée.

### 🟢 2 Bugs Low Corrigés
- **L1** — Message CSRF tronqué `'Token CSRF inval.'` → `'Token CSRF invalide.'`
- **L2** — `/api/update/progress` protégé par `@require_connection` (était public).

---

## 🆕 Nouveautés v1.43.0

### ⚡ Mise à jour par ZIP (v4.0)
- **1 seule requête HTTP** au lieu de 200+ — téléchargement du ZIP GitHub (~5 Mo)
- **Extraction différentielle SHA256** — seuls les fichiers modifiés sont écrits
- **Backup parallèle** avant écrasement + rollback automatique si healthcheck échoue
- **Écriture atomique** (tmp → rename) — plus d'état incohérent en cas de coupure

### 🔒 Cohérence parfaite Groupes ↔ Utilisateurs
- **Page Groupes** → formulaire "Ajouter un membre" avec **recherche AJAX** d'utilisateurs (autocomplete)
- **Page Utilisateur** → section "Appartenance aux groupes" avec **recherche AJAX** de groupes + liste des groupes actuels avec bouton "Retirer"
- **API** : `GET /api/users/search` + `GET /api/groups/search` — recherche par CN, sAMAccountName, displayName
- **Filtre `CN=Builtin`** — les groupes système sont exclus de toutes les recherches

### 🛡️ Protection des groupes système
- **Groupes Builtin** — message d'avertissement clair, boutons ajout/retrait masqués
- **Groupes AD protégés** — Domain Admins, Enterprise Admins, Schema Admins, etc.
- **Affichage des SID** — les membres sans CN (S-1-5-4) affichent leur SID complet

### 🔧 Gestion OU + Groupes dans l'édition utilisateur
- **Déplacement OU** — dropdown des OUs disponibles + bouton "Déplacer"
- **Ajout/Retrait de groupes** — recherche AJAX + boutons directs
- **Template edit_user.html reconstruit** — données pré-remplies, recherche BASE sur DN

### 🐛 Corrections de bugs
- **`entry.distinguishedName` → `entry.entry_dn`** (13 fichiers) — propriété ldap3 toujours disponible
- **71 groupes affichés** au lieu de 1 — `conn.entries` n'est plus écrasé par les recherches speciales
- **Permissions `testino`** — extraction du sAMAccountName depuis `SELEST\testino`
- **Mot de passe expiré** — détection LDAP data 773, redirection vers `/change-password`
- **Rôles prédéfinis** — uniquement les groupes AD natifs français (supprimé IT Support, Helpdesk, Domain Users)
- **`errors.html`** — normalisation API errors + protection `.indexOf()` sur undefined
- **`view_group`** — décodage URL des DN + fallback SUBTREE si BASE échoue (code 53)
- **Filtre `cn=builtin`** sur `/users/` et `/groups/` — groupes système masqués

---

## 🆕 Nouveautés v1.39.0

### 🐛 7 Bugs Critical Corrigés

- **C1 — Syntaxe LDAP `lockoutTime`** — remplacement du tuple invalide `(0, [(0, ...)])` par `(MODIFY_REPLACE, [bytes])` — le déblocage de comptes ne fonctionnait plus
- **C2 — Itérateur invalide dans boucle groupes** — pre-comptage des groupes spéciaux (computers, users, DC) **avant** la boucle `for entry in conn.entries` — évitait le crash lors de l'affichage des groupes avec membres basés sur `primaryGroupID`
- **C3 — Race condition `_update_progress`** — ajout de `threading.Lock()` sur toutes les lectures/écritures du dict partagé — évitait le crash si 2 mises à jour simultanées
- **C4 — XSS dans export PDF** — sanitisation du `domain_name` avec `re.sub(r'[^\w._-]', '_', ...)` dans le header `Content-Disposition` — empêchait l'injection de caractères spéciaux dans le nom de fichier
- **C5 — Erreur silencieuse `fix_type` inconnu** — retour HTTP 400 avec message explicite au lieu de 200 OK avec `success: False` sans détail

### 🧹 Nettoyage

- Suppression des `print()` debug dans `routes/groups/__init__.py`
- Import `MODIFY_REPLACE` de `ldap3` pour syntaxe LDAP correcte

---

## 🆕 Nouveautés v1.38.0

### 🔑 Permissions — Autocomplete AD en temps réel
- **Recherche LDAP en direct** — en tapant dans le champ, l'appli interroge LDAP et propose les groupes, utilisateurs et OUs correspondants
- **Support élargi** — autocomplete pour les groupes, les utilisateurs et les OUs
- **Correction du bug de sauvegarde silencieuse** — l'API retourne maintenant `{"success": true}` au lieu de `true` brut
- **Sujet user et OU** — ajout du support des utilisateurs et OUs en plus des groupes

### ⚡ Mise à jour différentielle & Robustesse
- **Mise à jour différentielle (SHA GitHub)** — télécharge seulement les fichiers modifiés, pas tout le repo
- **Backup automatique avant écrasement** — sauvegarde de sécurité + rollback automatique si le healthcheck échoue
- **Watchdog en arrière-plan** — surveillance continue : disque, LDAP, dépendances, rotation des logs
- **Barre de progression réelle** — feedback visuel précis sur la page de mise à jour
- **Messages d'erreur détaillés** — affichage clair en cas d'échec de la mise à jour web
- **Mise à jour via WinSW restart** — remplace `os.execl` pour un restart fiable du service Windows

### 🛠️ Corrections & Améliorations
- **Titre centré dans la topbar** — amélioration visuelle
- **Colonne OU tronquée avec ellipsis** — affichage propre des longs DN
- **Script `sync_check.ps1`** — détecte la dérive entre les deux serveurs (versions, fichiers)
- **Correction `UnboundLocalError auto_detected`** — crash dans `routes/main.py` lors d'échec de connexion (`auto_detected` non initialisé dans le bloc POST)
- **Correction `disabled_features` manquante** — erreur dans `admin.html`
- **`install_standalone.ps1` compatible WinSW/NSSM** — corrections de compatibilité service Windows
- **`sync_check.ps1` compatible Windows** — correction encodage (CRLF, ASCII pur sans BOM) pour éviter les erreurs de parsing PowerShell

---

## 🆕 Nouveautés v1.37.10

### 🐛 Correction erreur API update
- **API `/api/perform-update`** : retourne maintenant du JSON au lieu de HTML en cas d'erreur de permission
- **Détection Content-Type** : le client vérifie le type de réponse avant de parser le JSON
- **Messages d'erreur améliorés** : affichage clair de la permission requise en cas de refus
- **Fix erreur "Unexpected token '<'"** : résolution du problème de parsing JSON

---

## 🆕 Nouveautés v1.37.9

### ⚡ Système de mise à jour amélioré (v2.0)
- **Téléchargement parallèle** : 3-4x plus rapide avec ThreadPoolExecutor (4 workers)
- **Cache intelligent** : Requêtes GitHub mises en cache 5 minutes pour éviter les rate limits
- **Statistiques avant mise à jour** : Affichage du nombre de fichiers, taille totale, types
- **Gestion robuste des erreurs** : Rapports d'erreurs détaillés, retries automatiques
- **Protection améliorée** : Plus de dossiers exclus (.github, .git, logs, data, venv)

---

## 🆕 Nouveautés v1.37.8

### ⚡ Système de mise à jour amélioré (v2.0)
- **Téléchargement parallèle** : 3-4x plus rapide avec ThreadPoolExecutor (4 workers)
- **Cache intelligent** : Requêtes GitHub mises en cache 5 minutes pour éviter les rate limits
- **Statistiques avant mise à jour** : Affichage du nombre de fichiers, taille totale, types
- **Gestion robuste des erreurs** : Rapports d'erreurs détaillés, retries automatiques
- **Protection améliorée** : Plus de dossiers exclus (.github, .git, logs, data, venv)

---

## 🆕 Nouveautés v1.37.7

### ⚡ Système de mise à jour amélioré (v2.0)
- **Téléchargement parallèle** : 3-4x plus rapide avec ThreadPoolExecutor (4 workers)
- **Cache intelligent** : Requêtes GitHub mises en cache 5 minutes pour éviter les rate limits
- **Statistiques avant mise à jour** : Affichage du nombre de fichiers, taille totale, types
- **Gestion robuste des erreurs** : Rapports d'erreurs détaillés, retries automatiques
- **Protection améliorée** : Plus de dossiers exclus (.github, .git, logs, data, venv)

---

## 🆕 Nouveautés v1.37.5

### ✨ Améliorations
- **Filtres avancés sur /users/** : dropdown OU, filtre Actifs/Désactivés, bouton Effacer
- **Filtres avancés sur /computers/** : dropdown OU, filtre Actifs/Désactivés, filtre OS, bouton Effacer

### 🐛 Corrections
- **Ordinateurs (et utilisateurs) manquants** : recherche LDAP limitée à 1000 résultats max — remplacée par `paged_search` pour récupérer tous les objets AD sans troncature silencieuse

---

## 🆕 Nouveautés v1.37.4

### ✨ Améliorations
- **Bouton LDAPS sur création d'utilisateur** : le bandeau d'avertissement affiche désormais un bouton "🔒 Se reconnecter en LDAPS" qui pré-remplit automatiquement le formulaire de connexion avec port 636 et SSL coché

---

## 🆕 Nouveautés v1.37.3

### 🐛 Corrections
- **Fallback LDAP/389** : login fonctionne même si LDAPS/636 est rejeté par le DC
- **API JSON 401** : bouton "Installer la mise à jour" ne retourne plus `<!DOCTYPE` en JS
- **Page `/update` sécurisée** : nécessite d'être connecté en tant qu'admin
- **LAPS** : accessible dès le premier lancement sans configuration préalable

---

## 🆕 Nouveautés v1.37.2

### 🐛 Corrections de cohérence
- **Session timeout** : corrigé de 30 secondes à 30 minutes (`app.py` utilisait la valeur en minutes au lieu de secondes)
- **Sécurité installateur DC** : `DEFAULT_ROLE=reader` dans `install_ad.ps1` (était `admin` — risque élévation de privilèges)
- **OPENSSL_CONF** : configuré automatiquement dans `install_standalone.ps1` (support NTLM/MD4 Python 3.12+)
- **Routes API protégées** : `@require_connection` ajouté sur 6 routes non protégées dont `/api/perform-update`
- **`SESSION_COOKIE_NAME`** : désormais appliqué correctement dans Flask (`ad_session` au lieu du nom par défaut)

---

## 🆕 Nouveautés v1.37.1

### 🐛 Corrections critiques de l'installateur
- **Login corrigé** : `SESSION_COOKIE_SECURE=false` dans le `.env` généré — le cookie de session était rejeté par le navigateur en HTTP, rendant le token CSRF invalide
- **Installation NSSM corrigée** : chute de flux vers le bloc WinSW supprimée — le service s'installe et démarre correctement
- **Script PowerShell corrigé** : bloc de signature Authenticode invalide supprimé de `install_standalone.ps1`

---

## Nouveautés v1.36.0

### 📊 Analyse Automatique des Logs
- Analyse au démarrage de l'application
- Détection automatique des erreurs critiques
- Corrections automatiques disponibles
- Historique des analyses
- Export des rapports

### 🛠️ Gestion des Scripts PowerShell
- Exécution depuis l'interface web
- Téléchargement des scripts
- Historique des exécutions
- 9 scripts disponibles (fix_md4, fix_ntlm, fix_ldap_signing, etc.)

### 📁 Page /ous/ Enrichie
- Statistiques globales (OUs, users, groups, computers)
- Barre de recherche textuelle
- Filtres par type d'objet
- Badges cliquables vers users/groups/computers
- Export CSV

### 🔧 Page /diagnostic/ Améliorée
- 19 tests au lieu de 8
- Informations système détaillées
- Export du rapport en TXT
- Section avertissements dédiée

---

## ✨ Fonctionnalités

### 👥 Gestion Active Directory

| Fonctionnalité | Description |
|---------------|-------------|
| 👤 **Utilisateurs** | Créer, modifier, supprimer, réinitialiser MDP, activer/désactiver, déplacer |
| 👥 **Groupes** | Groupes de sécurité et distribution, membres, groupes spéciaux |
| 💻 **Ordinateurs** | Machines jointes au domaine avec détails complets |
| 📁 **OUs** | Unités d'organisation avec arborescence visuelle |
| 🔐 **LAPS** | Lecture des mots de passe locaux administrés |
| 🔒 **BitLocker** | Récupération des clés de chiffrement |

### 🛡️ Sécurité & Audit

| Fonctionnalité | Description |
|---------------|-------------|
| 🔍 **Audit MDP** | Analyse complète des mots de passe + score 0–100 |
| 🔐 **Audit Sécurité** | 8 problèmes détectés, 5 réparations automatiques |
| 🔑 **Permissions** | 40 permissions granulaires configurables par groupe AD |
| 📋 **Logs d'audit** | Journal complet de toutes les actions administratives |
| 🚨 **Alertes auto** | Notifications par email (comptes expirés, inactifs, etc.) |
| 🎲 **Générateur MDP** | Mots de passe sécurisés avec indicateur de complexité |

### 🔒 Connexions sécurisées

- **LDAP** (port 389) — connexion standard
- **STARTTLS** (port 389 + TLS) — chiffrement opportuniste
- **LDAPS** (port 636) — SSL/TLS natif

> La définition du mot de passe lors de la création d'un utilisateur requiert LDAPS ou STARTTLS. Un indicateur visuel vous avertit en temps réel.

### 📊 Tableau de Bord

- Score de sécurité en temps réel
- Alertes critiques
- Actions requises
- Statistiques d'audit
- Accès rapide aux fonctions clés

---

## 🚀 Installation (Windows Server)

### Prérequis

- Windows Server 2016 ou supérieur (ou Windows 10/11)
- Python 3.10 ou supérieur
- PowerShell 5.1 ou supérieur
- Accès réseau au contrôleur de domaine

### Installation en une commande

Ouvrez **PowerShell en tant qu'administrateur** depuis `C:\AD-WebInterface\` :

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\install_standalone.ps1
```

Le script effectue automatiquement :
1. Création de l'environnement virtuel Python (`venv\`)
2. Installation des dépendances (`pip install -r requirements.txt`)
3. Génération d'une `SECRET_KEY` aléatoire dans `.env`
4. Installation du service Windows via **WinSW** (`nssm\ADWebInterface.exe`)
5. Démarrage automatique du service

### Accès à l'interface

```
http://NOM_DU_SERVEUR:5000
```

ou depuis le serveur lui-même :

```
http://localhost:5000
```

### Gestion du service

```powershell
# Sans droits administrateur
.\nssm\ADWebInterface.exe start
.\nssm\ADWebInterface.exe stop
.\nssm\ADWebInterface.exe restart
.\nssm\ADWebInterface.exe status
```

---

## ⚙️ Configuration

### Fichier `.env`

Créé automatiquement par le script d'installation. Paramètres principaux :

```ini
# Obligatoire — générée automatiquement à l'installation
SECRET_KEY=<clé-aléatoire-64-caractères>

# Serveur web
AD_WEB_HOST=0.0.0.0
AD_WEB_PORT=5000

# Session
SESSION_TIMEOUT=30          # minutes

# Active Directory (optionnel — configurable via l'interface)
AD_SERVER=dc01.corp.local
AD_PORT=389
AD_USE_SSL=false

# Permissions
RBAC_ENABLED=true
RBAC_ADMIN_GROUPS=Domain Admins,Administrateurs du domaine

# Notifications email (optionnel)
EMAIL_ENABLED=false
SMTP_SERVER=smtp.corp.local
SMTP_PORT=587
SMTP_USERNAME=adweb@corp.local
SMTP_PASSWORD=mot-de-passe
```

---

## 🔑 Permissions Granulaires

Les permissions sont configurables par groupe Active Directory depuis `/permissions`.

| Catégorie | Permissions disponibles |
|-----------|------------------------|
| **👤 Users** | `create`, `read`, `update`, `delete`, `import`, `export` |
| **👥 Groups** | `create`, `read`, `update`, `delete` |
| **💻 Computers** | `create`, `read`, `update`, `delete` |
| **📁 OUs** | `create`, `read`, `update`, `delete` |
| **🔧 Tools** | `locked_accounts`, `expiring_accounts`, `password_audit`, `laps`, `bitlocker`, … |
| **⚙️ Admin** | `settings`, `backups`, `audit_logs`, `security_audit`, `permissions`, … |

### Rôles prédéfinis

| Groupe AD | Permissions | Profil |
|-----------|-------------|--------|
| **Domain Admins** | Toutes (40) | Accès complet |
| **IT Support** | 11 permissions | Lecture + modifications limitées |
| **Helpdesk** | 4 permissions | Réinitialisation MDP, déblocage |
| **Domain Users** | 4 permissions | Lecture seule |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Navigateur (tout appareil)                  │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP / HTTPS
┌────────────────────────▼────────────────────────────────────┐
│          Service Windows — WinSW + Waitress WSGI             │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                 Flask Application                     │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │   │
│  │  │  Users   │ │  Groups  │ │Computers │ │  OUs   │  │   │
│  │  │ Blueprint│ │ Blueprint│ │ Blueprint│ │Blueprint│  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────┘  │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │   │
│  │  │  Tools   │ │  Admin   │ │   API    │ │  Debug │  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────┘  │   │
│  │                                                      │   │
│  │  core/ : sécurité, audit, session, permissions       │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │ LDAP / LDAPS / STARTTLS
┌────────────────────────▼────────────────────────────────────┐
│               Microsoft Active Directory                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Users   │  │  Groups  │  │Computers │  │   OUs    │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Modules principaux (`core/`)

| Module | Rôle |
|--------|------|
| `security.py` | CSRF, échappement LDAP, headers HTTP de sécurité |
| `session_crypto.py` | Chiffrement Fernet des données de session sensibles |
| `audit.py` | Journal des actions (création, modification, suppression) |
| `granular_permissions.py` | Calcul des 40 permissions par groupe AD |
| `context_processor.py` | Variables globales Jinja2 (version, dark mode…) |
| `updater.py` | Lecture `VERSION` + vérification des nouvelles versions |
| `settings_manager.py` | Lecture/écriture `data/settings.json` |
| `security_audit.py` | Audit de sécurité AD (8 contrôles, 5 corrections auto) |

---

## 🔐 Audit de Sécurité

### Problèmes détectés automatiquement

| # | Problème | Sévérité | Correction auto |
|---|----------|----------|-----------------|
| 1 | Comptes orphelins (sans manager) | 🟡 Warning | ✅ |
| 2 | Trop de Domain Admins | 🔴 Critical | ❌ |
| 3 | Admins sans MFA activé | 🔴 Critical | ❌ |
| 4 | Groupes de sécurité vides | 🟡 Warning | ✅ |
| 5 | Privilèges spéciaux (DCSync) | 🟠 High | ❌ |
| 6 | Délégation Kerberos non contrainte | 🔴 Critical | ✅ |
| 7 | Comptes avec MDP sans expiration | 🟠 High | ✅ |
| 8 | Comptes inactifs depuis +90 jours | 🟡 Warning | ✅ |

---

## 🔧 Technologies

| Composant | Version | Rôle |
|-----------|---------|------|
| **Python** | 3.10+ | Langage |
| **Flask** | 3.0 | Framework web |
| **ldap3** | 2.9+ | Connexion Active Directory |
| **cryptography** | 41+ | Chiffrement des sessions (Fernet) |
| **Waitress** | 2.1+ | Serveur WSGI (Windows) |
| **WinSW** | 2.12+ | Gestionnaire de service Windows |

---

## 📈 Changelog

### v1.35.0 — Avril 2026
- ✅ Consolidation complète du CSS (design system unifié, variables CSS partout)
- ✅ Correction détection STARTTLS pour `can_set_password` dans `/users/create`
- ✅ Restauration du design de la landing page (hero, feature cards, system info)
- ✅ Générateur de mot de passe dans `/users/create` (avec indicateur de force)
- ✅ Correction `/permissions` (erreur 500 — mauvais template rendu)
- ✅ Correction dropdown OU dans la création d'utilisateur
- ✅ Script de signature Authenticode WinSW (self-signed, admin one-shot)

### v1.34.7 — Avril 2026
- ✅ Réorganisation en package `core/`
- ✅ Corrections chemins `core/data/crypto_salt.bin`
- ✅ Suppression des imports locaux incorrects

### v1.34.0 — Avril 2026
- ✅ Permissions granulaires (40 permissions par groupe AD)
- ✅ Page d'administration des permissions
- ✅ Audit de sécurité AD (8 contrôles)
- ✅ Dashboard avec widgets configurables
- ✅ Support STARTTLS + LDAPS avec détection automatique

[Voir le changelog complet](CHANGELOG.md)

---

## 📄 License

Distribué sous la licence MIT. Voir [LICENSE](LICENSE) pour plus d'informations.

---

## 👤 Auteur

**Frédéric SELEST** — [fred-selest](https://github.com/fred-selest)

---

## 📞 Support

- **Issues :** https://github.com/fred-selest/microsoft-active-directory/issues
- **Discussions :** https://github.com/fred-selest/microsoft-active-directory/discussions

---

<p align="center">
  <strong>Si ce projet vous est utile, une ⭐️ est toujours appréciée !</strong>
</p>
