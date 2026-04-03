# 🔐 Interface Web Microsoft Active Directory

**Version actuelle :** 1.31.0  
**Dernière mise à jour :** Avril 2026  
**Repository :** https://github.com/fred-selest/microsoft-active-directory

---

## 📖 Table des Matières

1. [Présentation](#présentation)
2. [Fonctionnalités](#fonctionnalités)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Guide d'utilisation](#guide-dutilisation)
6. [Permissions granulaires](#permissions-granulaires)
7. [Audit de sécurité](#audit-de-sécurité)
8. [API Reference](#api-reference)
9. [Dépannage](#dépannage)
10. [Changelog](#changelog)

---

## 📋 Présentation

Interface Web moderne pour gérer Microsoft Active Directory depuis n'importe quel navigateur, sans installation cliente.

### ✨ Points forts

- ✅ **100% Web** - Accessible depuis Chrome, Firefox, Edge
- ✅ **Multi-plateforme** - Windows, Linux, macOS
- ✅ **Responsive** - Desktop, tablette, mobile
- ✅ **Sécurisé** - Sessions chiffrées, RBAC, audit logging
- ✅ **Dark Mode** - Thème clair/sombre
- ✅ **Auto-update** - Mises à jour automatiques

---

## 🎯 Fonctionnalités

### Gestion Active Directory

| Fonctionnalité | Description |
|---------------|-------------|
| 👤 **Utilisateurs** | Créer, modifier, supprimer, importer, exporter |
| 👥 **Groupes** | Gestion des groupes de sécurité et distribution |
| 💻 **Ordinateurs** | Gestion des machines jointes au domaine |
| 📁 **OUs** | Unités d'organisation avec arborescence |
| 🔐 **LAPS** | Gestion des mots de passe locaux |
| 🔒 **BitLocker** | Récupération des clés de chiffrement |

### Outils Avancés

| Outil | Description |
|-------|-------------|
| 🔍 **Audit MDP** | Analyse complète de la sécurité des mots de passe |
| 📊 **Dashboard** | Vue d'ensemble avec widgets personnalisés |
| 📈 **Historique** | Suivi de l'évolution des audits |
| 🤖 **Comptes de service** | Détection des configurations à risque |
| 👑 **Admins à risque** | Surveillance des comptes privilégiés |
| 🔔 **Alertes auto** | Notifications automatiques par email |

### Sécurité Renforcée

| Fonction | Description |
|----------|-------------|
| 🔐 **Audit Sécurité** | 8 types de problèmes détectés |
| 🔧 **Réparations** | 5 actions correctives automatiques |
| 🔑 **Permissions** | 40 permissions granulaires par groupe |
| 📋 **Logs d'audit** | Journal complet de toutes les actions |
| 🛡️ **RBAC** | Rôles basés sur les groupes AD |

---

## 🚀 Installation

### Windows Server (Recommandé)

```batch
# 1. Extraire dans C:\AD-Web\ (sans accents/espaces)
# 2. Right-click install_service.bat → Run as Administrator
# 3. Accéder à http://SERVER_NAME:5000
```

### Linux (Ubuntu/Debian)

```bash
# Installation
git clone https://github.com/fred-selest/microsoft-active-directory.git
cd microsoft-active-directory

# Environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Dépendances
pip install -r requirements.txt

# Configuration
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
echo "FLASK_ENV=production" >> .env

# Production avec Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 'app:app'
```

### Docker

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

---

## ⚙️ Configuration

### Fichier .env

```ini
# ============================================================================
# CONFIGURATION AD WEB INTERFACE
# ============================================================================

# SECRET_KEY: CRITIQUE - Générez une clé forte
# python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=votre-clé-secrète-ici

# MODE DEBUG - Mettre à false en production
FLASK_DEBUG=false
FLASK_ENV=production

# SERVEUR
AD_WEB_HOST=0.0.0.0
AD_WEB_PORT=5000

# SESSION
SESSION_COOKIE_SECURE=true
SESSION_TIMEOUT=30

# ACTIVE DIRECTORY (optionnel - configurable via UI)
AD_SERVER=dc01.company.local
AD_PORT=389
AD_USE_SSL=false
AD_BASE_DN=DC=company,DC=local

# RBAC
RBAC_ENABLED=true
DEFAULT_ROLE=reader
RBAC_ADMIN_GROUPS=Domain Admins,Administrateurs du domaine

# EMAIL (optionnel - pour alertes)
SMTP_SERVER=smtp.company.local
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=adweb@company.local
SMTP_PASSWORD=votre-mot-de-passe
SMTP_FROM=adweb@company.local
EMAIL_TO=admin@company.local
EMAIL_ENABLED=false
```

### Configuration requise

| Composant | Minimum | Recommandé |
|-----------|---------|------------|
| **CPU** | 2 cores | 4 cores |
| **RAM** | 2 GB | 4 GB |
| **Disque** | 10 GB | 20 GB |
| **OS** | Windows Server 2016+ | Windows Server 2022 |
| **Python** | 3.8 | 3.12+ |

---

## 📖 Guide d'utilisation

### Première connexion

1. **Ouvrez** http://votre-serveur:5000
2. **Entrez** vos identifiants :
   - Serveur : `dc01.company.local`
   - Port : `389` (LDAP) ou `636` (LDAPS)
   - Utilisateur : `DOMAIN\admin` ou `admin@company.local`
   - Mot de passe : votre mot de passe
3. **Cliquez** sur "Se connecter"

### Dashboard

Le tableau de bord affiche :

- 🚨 **Alertes critiques** (si problèmes détectés)
- 📊 **Score de sécurité** (avec tendance)
- ⚡ **Actions requises** (critiques + warnings)
- 📈 **Statistiques audit** (historique, scores)
- ⚡ **Accès rapide** (pages fréquentes)

### Audit des mots de passe

1. **Allez** dans Outils → Audit MDP
2. **Cliquez** sur "🔍 Lancer l'audit"
3. **Attendez** la fin de l'analyse
4. **Consultez** les résultats :
   - Score global
   - Politique du domaine
   - Comptes à risque
   - Recommandations
5. **Exportez** en PDF/CSV/JSON

### Permissions granulaires

1. **Allez** dans Administration → 🔑 Permissions
2. **Cliquez** sur "➕ Ajouter un groupe"
3. **Saisissez** le nom du groupe AD
4. **Cochez** les permissions souhaitées
5. **Enregistrez**

**Exemple : Groupe Helpdesk**
```
Nom : Helpdesk N1
Permissions cochées :
✅ users:read
✅ users:update
✅ groups:read
✅ tools:locked_accounts
```

---

## 🔑 Permissions Granulaires

### Système de permissions

Chaque groupe AD peut avoir des permissions spécifiques sur :

| Catégorie | Permissions | Description |
|-----------|-------------|-------------|
| **users** | create, read, update, delete, import, export | Gestion des utilisateurs |
| **groups** | create, read, update, delete | Gestion des groupes |
| **computers** | create, read, update, delete | Gestion des ordinateurs |
| **ous** | create, read, update, delete | Gestion des OUs |
| **tools** | locked_accounts, expiring_accounts, password_policy, password_audit, expiring_pdf | Outils |
| **admin** | settings, backups, audit_logs, diagnostic, security_audit, alerts, user_templates | Administration |

### Rôles prédéfinis

| Groupe | Permissions | Description |
|--------|-------------|-------------|
| **Domain Admins** | Toutes (40) | Accès complet |
| **IT Support** | 11 permissions | Lecture + modification limitée |
| **Helpdesk** | 4 permissions | Réinitialisation MDP, déblocage |
| **Domain Users** | 4 permissions | Lecture seule |

### Utiliser les permissions

**Dans vos routes :**

```python
from routes.core import require_permission

@tools_bp.route('/create-user')
@require_permission('users:create')
def create_user():
    # Seuls les groupes avec users:create peuvent accéder
    ...
```

**Vérification manuelle :**

```python
from granular_permissions import has_permission

user_groups = session.get('user_groups', [])
if has_permission(user_groups, 'users:delete'):
    # Supprimer utilisateur
    ...
```

---

## 🔐 Audit de Sécurité

### Problèmes détectés

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

### Réparations automatiques

| Réparation | Description | Validation |
|------------|-------------|------------|
| **Assigner manager** | Définit un manager pour des comptes orphelins | DN du manager requis |
| **Supprimer groupes vides** | Supprime les groupes de sécurité sans membres | Confirmation requise |
| **Désactiver délégation** | Désactive la délégation non contrainte | Confirmation requise |
| **Activer expiration MDP** | Active l'expiration pour comptes suspects | Confirmation requise |
| **Désactiver comptes inactifs** | Désactive comptes sans login >90j | Confirmation requise |

### Accéder à l'audit

1. **Allez** dans Administration → 🔐 Sécurité
2. **Consultez** les problèmes détectés
3. **Cliquez** sur "🔧 Réparer" si disponible
4. **Validez** dans le modal
5. **Vérifiez** le résultat

---

## 📡 API Reference

### Endpoints publics

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/health` | GET | Santé de l'application |
| `/api/system-info` | GET | Informations système |

### Endpoints protégés (connexion requise)

| Endpoint | Méthode | Permission | Description |
|----------|---------|------------|-------------|
| `/api/password-audit` | GET | tools:password_audit | Lance un audit MDP |
| `/api/password-audit/history` | GET | tools:password_audit | Historique des audits |
| `/api/password-audit/alerts-summary` | GET | tools:password_audit | Résumé des alertes |
| `/api/security-fix` | POST | admin:security_audit | Applique une réparation |
| `/api/permissions` | POST | admin:settings | Sauvegarde permissions |
| `/api/permissions/<group>` | DELETE | admin:settings | Supprime permissions |
| `/api/errors` | GET | admin:audit_logs | Logs d'erreurs |

### Exemple d'utilisation

```bash
# Audit MDP
curl -X GET http://localhost:5000/api/password-audit \
  -H "Cookie: session=votre-session"

# Réparation sécurité
curl -X POST http://localhost:5000/api/security-fix \
  -H "Content-Type: application/json" \
  -H "Cookie: session=votre-session" \
  -d '{"fix_type": "disable_inactive_accounts", "accounts": ["user1", "user2"]}'
```

---

## 🐛 Dépannage

### Problèmes courants

| Problème | Cause | Solution |
|----------|-------|----------|
| **Port 5000 occupé** | Conflit de port | Changez `AD_WEB_PORT` dans `.env` |
| **Erreur MD4/NTLM** | Python 3.12+ | Utilisez `run_legacy.bat` |
| **Service ne démarre pas** | Erreur config | Vérifiez `logs\service_error.log` |
| **Connection refused** | Firewall | Vérifiez la règle firewall |
| **Erreur LDAP 49** | Format username | Utilisez `DOMAIN\user` ou `user@domain` |
| **Permissions non appliquées** | RBAC désactivé | Vérifiez `RBAC_ENABLED=true` |

### Logs

| Fichier | Contenu |
|---------|---------|
| `logs/audit.log` | Journal des actions |
| `logs/server.log` | Logs du serveur |
| `logs/service_error.log` | Erreurs service Windows |

### Commandes utiles

```bash
# Windows - Voir logs
Get-Content logs\server.log -Tail 50

# Linux - Voir logs
tail -f logs/server.log

# Redémarrer service
net stop ADWebInterface && net start ADWebInterface

# Tester connexion
python -c "from app import *; print(is_connected())"
```

---

## 📝 Changelog

### v1.31.0 - Avril 2026
- ✅ Permissions granulaires par groupe AD
- ✅ 40 permissions en 6 catégories
- ✅ Rôles prédéfinis (Domain Admins, IT Support, Helpdesk)
- ✅ Page d'administration des permissions

### v1.30.0 - Avril 2026
- ✅ Audit de sécurité renforcé
- ✅ 8 problèmes de sécurité détectés
- ✅ 5 réparations automatiques
- ✅ Boutons "Réparer" avec validation

### v1.29.1 - Avril 2026
- ✅ Corrections route /errors (encodage)
- ✅ Auto-reload v2 (logging, protection)

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
- ✅ Widget dashboard

### v1.26.0 - Avril 2026
- ✅ Comptes admins MDP faible
- ✅ Comptes de service à risque
- ✅ Export PDF professionnel
- ✅ Historique des audits
- ✅ Template décomposé en partials

---

## 📞 Support

- **Issues :** https://github.com/fred-selest/microsoft-active-directory/issues
- **Discussions :** https://github.com/fred-selest/microsoft-active-directory/discussions
- **Email :** support@adweb.local

---

## 📄 License

MIT License - Voir LICENSE pour plus de détails.

---

## 👥 Contributeurs

- **Développeur principal :** Frédéric SELEST
- **Contributeurs :** Voir https://github.com/fred-selest/microsoft-active-directory/graphs/contributors

---

## 🙏 Remerciements

- Microsoft pour Active Directory
- Flask pour le framework web
- ldap3 pour la connexion LDAP
- La communauté open-source

---

**Documentation générée le :** Avril 2026  
**Version documentée :** 1.31.0
