# 🔐 AD Web Interface

> **Interface Web Moderne pour Microsoft Active Directory**

[![Version](https://img.shields.io/github/v/release/fred-selest/microsoft-active-directory?label=Version&color=0078d4)](https://github.com/fred-selest/microsoft-active-directory/releases)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-lightgrey.svg)](https://flask.palletsprojects.com/)

Gérez votre Active Directory depuis n'importe quel navigateur, sans installation cliente.

---

## ✨ Fonctionnalités Principales

### 👥 Gestion Active Directory

| Fonctionnalité | Description |
|---------------|-------------|
| 👤 **Utilisateurs** | Créer, modifier, supprimer, importer, exporter |
| 👥 **Groupes** | Groupes de sécurité et distribution |
| 💻 **Ordinateurs** | Machines jointes au domaine |
| 📁 **OUs** | Unités d'organisation avec arborescence |
| 🔐 **LAPS** | Gestion des mots de passe locaux |
| 🔒 **BitLocker** | Récupération des clés de chiffrement |

### 🛡️ Sécurité & Audit

| Fonctionnalité | Description |
|---------------|-------------|
| 🔍 **Audit MDP** | Analyse complète des mots de passe |
| 🔐 **Audit Sécurité** | 8 problèmes détectés + 5 réparations |
| 🔑 **Permissions** | 40 permissions granulaires par groupe |
| 📋 **Logs d'audit** | Journal complet de toutes les actions |
| 🚨 **Alertes auto** | Notifications automatiques par email |

### 📊 Tableau de Bord

- 📈 Score de sécurité en temps réel
- 🚨 Alertes critiques
- ⚡ Actions requises
- 📊 Statistiques d'audit
- ⚡ Accès rapide

---

## 🚀 Installation Rapide

### Windows Server (Recommandé)

```batch
# 1. Extraire dans C:\AD-Web\
# 2. Right-click install_service.bat → Run as Administrator
# 3. Accéder à http://SERVER_NAME:5000
```

### Linux

```bash
# Clone
git clone https://github.com/fred-selest/microsoft-active-directory.git
cd microsoft-active-directory

# Installation
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Configuration
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
echo "FLASK_ENV=production" >> .env

# Lancement
gunicorn -w 4 -b 0.0.0.0:5000 'app:app'
```

### Docker

```bash
docker run -d -p 5000:5000 \
  -v ./data:/app/data \
  -e SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))") \
  fred-selest/ad-web-interface:latest
```

---

## ⚙️ Configuration

### Fichier .env

```ini
# CRITIQUE: Générez une clé secrète
SECRET_KEY=votre-clé-secrète-ici

# Serveur
FLASK_ENV=production
AD_WEB_HOST=0.0.0.0
AD_WEB_PORT=5000

# Session
SESSION_COOKIE_SECURE=true
SESSION_TIMEOUT=30

# Active Directory (optionnel - configurable via UI)
AD_SERVER=dc01.company.local
AD_PORT=389
AD_USE_SSL=false

# RBAC
RBAC_ENABLED=true
DEFAULT_ROLE=reader
RBAC_ADMIN_GROUPS=Domain Admins,Administrateurs du domaine

# Email (pour alertes)
SMTP_SERVER=smtp.company.local
SMTP_PORT=587
SMTP_USERNAME=adweb@company.local
SMTP_PASSWORD=votre-mot-de-passe
EMAIL_ENABLED=false
```

---

## 🔑 Permissions Granulaires

Chaque groupe AD peut avoir des permissions spécifiques :

| Catégorie | Permissions |
|-----------|-------------|
| **👤 Users** | `create`, `read`, `update`, `delete`, `import`, `export` |
| **👥 Groups** | `create`, `read`, `update`, `delete` |
| **💻 Computers** | `create`, `read`, `update`, `delete` |
| **📁 OUs** | `create`, `read`, `update`, `delete` |
| **🔧 Tools** | `locked_accounts`, `expiring_accounts`, `password_audit`, ... |
| **⚙️ Admin** | `settings`, `backups`, `audit_logs`, `security_audit`, ... |

### Rôles Prédéfinis

| Groupe | Permissions | Description |
|--------|-------------|-------------|
| **Domain Admins** | Toutes (40) | Accès complet |
| **IT Support** | 11 permissions | Lecture + modification limitée |
| **Helpdesk** | 4 permissions | Réinitialisation MDP, déblocage |
| **Domain Users** | 4 permissions | Lecture seule |

---

## 🔐 Audit de Sécurité

### Problèmes Détectés

| # | Problème | Sévérité | Réparable |
|---|----------|----------|-----------|
| 1 | Comptes orphelins (sans manager) | 🟡 Warning | ✅ |
| 2 | Trop de Domain Admins | 🔴 Critical | ❌ |
| 3 | Admins sans MFA | 🔴 Critical | ❌ |
| 4 | Groupes de sécurité vides | 🟡 Warning | ✅ |
| 5 | Privilèges spéciaux (DCSync) | 🟠 High | ❌ |
| 6 | Délégation non contrainte | 🔴 Critical | ✅ |
| 7 | MDP n'expirant jamais | 🟠 High | ✅ |
| 8 | Comptes inactifs >90j | 🟡 Warning | ✅ |

### Réparations Automatiques

- 🔧 **Assigner un manager** - Pour comptes orphelins
- 🔧 **Supprimer groupes vides** - Groupes de sécurité inutilisés
- 🔧 **Désactiver délégation** - Délégation non contrainte
- 🔧 **Activer expiration MDP** - Comptes suspects
- 🔧 **Désactiver comptes inactifs** - Sans login >90 jours

---

## 📊 Captures d'Écran

### Dashboard
![Dashboard](https://via.placeholder.com/800x400/0078d4/ffffff?text=Dashboard+avec+Widgets)

### Audit MDP
![Audit MDP](https://via.placeholder.com/800x400/0078d4/ffffff?text=Audit+des+Mots+de+Passe)

### Permissions
![Permissions](https://via.placeholder.com/800x400/0078d4/ffffff?text=Permissions+Granulaires)

---

## 📖 Documentation Complète

La documentation complète est disponible dans [README_DOCUMENTATION.md](README_DOCUMENTATION.md)

- 📦 Installation détaillée
- ⚙️ Configuration avancée
- 📖 Guide d'utilisation
- 📡 API Reference
- 🐛 Dépannage

---

## 🔧 Technologies

| Composant | Version | Purpose |
|-----------|---------|---------|
| **Flask** | 3.0.0 | Framework web |
| **ldap3** | 2.9.1 | Connexion Active Directory |
| **cryptography** | 41.0.7 | Chiffrement des sessions |
| **waitress** | 2.1.2 | Serveur WSGI (Windows) |
| **gunicorn** | 21.2.0 | Serveur WSGI (Linux) |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Browser (Any Device)                     │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTPS
┌────────────────────────▼────────────────────────────────────┐
│                   Flask Web Application                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   RBAC +     │  │   Session    │  │    Audit     │      │
│  │ Permissions  │  │   Encrypt    │  │    Logger    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────────────────┬────────────────────────────────────┘
                         │ LDAP/LDAPS
┌────────────────────────▼────────────────────────────────────┐
│               Microsoft Active Directory                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Users   │  │  Groups  │  │ Computers│  │   OUs    │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 📈 Changelog

### v1.31.0 - Avril 2026
- ✅ Permissions granulaires par groupe AD (40 permissions)
- ✅ Page d'administration des permissions
- ✅ Rôles prédéfinis (Domain Admins, IT Support, Helpdesk)

### v1.30.0 - Avril 2026
- ✅ Audit de sécurité renforcé (8 problèmes)
- ✅ 5 réparations automatiques
- ✅ Boutons "Réparer" avec validation

### v1.29.0 - Avril 2026
- ✅ Dashboard avec 4 widgets
- ✅ Arborescence des OUs
- ✅ Widget alertes critiques

### v1.28.0 - Avril 2026
- ✅ Dashboard personnalisé
- ✅ Widget score de sécurité
- ✅ Widget actions requises

### v1.27.0 - Avril 2026
- ✅ Alertes automatiques par email
- ✅ Détection problèmes critiques
- ✅ Dark Mode optimisé

### v1.26.0 - Avril 2026
- ✅ Comptes admins MDP faible
- ✅ Comptes de service à risque
- ✅ Export PDF professionnel
- ✅ Historique des audits

[Voir le changelog complet](CHANGELOG.md)

---

## 🤝 Contributing

Les contributions sont les bienvenues !

1. Fork le projet
2. Crée une branche (`git checkout -b feature/AmazingFeature`)
3. Commit (`git commit -m 'Add AmazingFeature'`)
4. Push (`git push origin feature/AmazingFeature`)
5. Ouvre une Pull Request

---

## 📄 License

Distribué sous la licence MIT. Voir [LICENSE](LICENSE) pour plus d'informations.

---

## 👥 Auteurs

- **Frédéric SELEST** - *Développeur principal* - [fred-selest](https://github.com/fred-selest)

Voir aussi la liste des [contributeurs](https://github.com/fred-selest/microsoft-active-directory/graphs/contributors).

---

## 🙏 Remerciements

- Microsoft pour Active Directory
- La communauté Flask
- ldap3 pour la bibliothèque LDAP
- Tous les contributeurs open-source

---

## 📞 Support

- **Issues:** https://github.com/fred-selest/microsoft-active-directory/issues
- **Discussions:** https://github.com/fred-selest/microsoft-active-directory/discussions
- **Documentation:** [README_DOCUMENTATION.md](README_DOCUMENTATION.md)

---

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=fred-selest/microsoft-active-directory&type=Date)](https://star-history.com/#fred-selest/microsoft-active-directory&Date)

---

<p align="center">
  <strong>Si vous aimez ce projet, merci de mettre une étoile ⭐️ !</strong>
</p>

<p align="center">
  <sub>Fait avec ❤️ par la communauté</sub>
</p>
