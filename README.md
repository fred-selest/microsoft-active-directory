# 🔐 AD Web Interface

> **Interface Web Moderne pour Microsoft Active Directory**

[![Version](https://img.shields.io/github/v/release/fred-selest/microsoft-active-directory?label=Version&color=0078d4)](https://github.com/fred-selest/microsoft-active-directory/releases)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server-0078d4.svg)](https://www.microsoft.com/windows-server)

Gérez votre Active Directory depuis n'importe quel navigateur, sans installation cliente. Fonctionne en tant que service Windows natif.

**Dernière version :** v1.37.1 — Avril 2026

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
