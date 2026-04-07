# 📋 CHECKLIST DÉPLOIEMENT CLIENT - AD Web Interface v1.34.4

## ✅ PRÉ-REQUIS TECHNIQUES

### 1. Service Windows
- [ ] Service `ADWebInterface` installé
- [ ] Service configuré en démarrage automatique
- [ ] Service en cours d'exécution (STATE: RUNNING)
- [ ] Logs de service configurés (`logs/service.log`)

### 2. Application
- [ ] Python 3.12+ installé
- [ ] Virtualenv activé
- [ ] Dépendances installées (`pip install -r requirements.txt`)
- [ ] Application s'importe sans erreur
- [ ] 108 routes enregistrées
- [ ] 10 blueprints fonctionnels

### 3. Configuration
- [ ] Fichier `.env` configuré
- [ ] `SECRET_KEY` générée (32 caractères hex)
- [ ] `FLASK_ENV=production`
- [ ] `RBAC_ENABLED=true`
- [ ] `DEFAULT_ROLE=reader`

### 4. Active Directory
- [ ] Contrôleur de domaine accessible
- [ ] Compte de service AD configuré
- [ ] RBAC groups configurés (Domain Admins, etc.)
- [ ] Test de connexion AD réussi

---

## ✅ TESTS FONCTIONNELS

### Routes Publiques (sans authentification)
- [ ] `GET /` → 200 OK (Homepage)
- [ ] `GET /connect` → 200 OK (Page de connexion)
- [ ] `GET /api/health` → 200 OK (Health check)

### Routes Protégées (avec authentification)
- [ ] `GET /dashboard` → 200 OK ou 302 (redirect si non connecté)
- [ ] `GET /users/` → 200 OK ou 302
- [ ] `GET /groups/` → 200 OK ou 302
- [ ] `GET /computers/` → 200 OK ou 302
- [ ] `GET /ous/` → 200 OK ou 302

### Menu Administration
- [ ] `GET /alerts` → 200 OK
- [ ] `GET /audit` → 200 OK (Journal d'audit)
- [ ] `GET /security-audit` → 200 OK
- [ ] `GET /permissions` → 200 OK
- [ ] `GET /diagnostic` → 200 OK
- [ ] `GET /tools/backups` → 200 OK
- [ ] `GET /admin/` → 200 OK

### Fonctionnalités Métier
- [ ] Création utilisateur → Fonctionnelle
- [ ] Modification utilisateur → Fonctionnelle
- [ ] Suppression utilisateur → Fonctionnelle
- [ ] Réinitialisation MDP → Fonctionnelle
- [ ] Activation/Désactivation compte → Fonctionnelle
- [ ] Gestion des groupes → Fonctionnelle
- [ ] Gestion des OUs → Fonctionnelle
- [ ] LAPS → Fonctionnel (si installé)
- [ ] BitLocker → Fonctionnel (si activé)

---

## ✅ SÉCURITÉ

### Configuration
- [ ] `SESSION_COOKIE_SECURE=true` (si HTTPS)
- [ ] `SESSION_COOKIE_HTTPONLY=true`
- [ ] `SESSION_COOKIE_SAMESITE=Lax`
- [ ] `FLASK_DEBUG=false`
- [ ] Rate limiting activé (5 tentatives/5min)

### RBAC (Role-Based Access Control)
- [ ] `RBAC_ENABLED=true`
- [ ] Groupes admin configurés
- [ ] Permissions granulaires configurées
- [ ] Rôle par défaut = `reader`

### Protection
- [ ] Tokens CSRF sur tous les formulaires
- [ ] Échappement LDAP activé
- [ ] Protection path traversal activée
- [ ] Sessions chiffrées (Fernet AES-128)

### Logs et Audit
- [ ] Logs d'audit activés
- [ ] Logs d'erreurs configurés
- [ ] Rotation des logs configurée
- [ ] Backup des logs configuré

---

## ✅ PERFORMANCE

### Service
- [ ] Temps de réponse < 2 secondes
- [ ] Pas de fuites mémoire
- [ ] CPU < 50% en usage normal
- [ ] Connexions AD poolées

### Base de données / Fichiers
- [ ] Espace disque suffisant (> 1 GB libre)
- [ ] Logs non saturés
- [ ] Backup automatique configuré

---

## ✅ DOCUMENTATION

### Client
- [ ] Guide d'utilisation fourni
- [ ] URLs d'accès documentées
- [ ] Comptes par défaut documentés
- [ ] Procédure de reset MDP documentée

### Technique
- [ ] Architecture documentée
- [ ] Procédure de backup documentée
- [ ] Procédure de restore documentée
- [ ] Contacts support fournis

---

## ✅ SAUVEGARDE

### Avant Déploiement
- [ ] Backup de l'application (`C:\AD-WebInterface\`)
- [ ] Backup de la configuration (`.env`, `data/settings.json`)
- [ ] Backup de la base de données (si applicable)
- [ ] Backup des logs

### Plan de Reprise
- [ ] Procédure de rollback documentée
- [ ] Version précédente disponible
- [ ] Tests de restore effectués

---

## ✅ ENVIRONNEMENT

### Serveur
- [ ] Windows Server 2016+ (ou Linux)
- [ ] 2 CPU cores minimum
- [ ] 2 GB RAM minimum
- [ ] 10 GB disque minimum

### Réseau
- [ ] Port 5000 ouvert (ou personnalisé)
- [ ] Firewall configuré
- [ ] HTTPS configuré (recommandé)
- [ ] Reverse proxy configuré (optionnel)

### Active Directory
- [ ] Domaine fonctionnel
- [ ] Contrôleur de domaine accessible
- [ ] Schema AD étendu (pour LAPS si utilisé)
- [ ] Groupes de sécurité créés

---

## 📊 SCORE DE PRÉPARATION

| Catégorie | Items ✓ | Total | Score |
|-----------|---------|-------|-------|
| Pré-requis techniques | ? | 12 | ?% |
| Tests fonctionnels | ? | 18 | ?% |
| Sécurité | ? | 12 | ?% |
| Performance | ? | 4 | ?% |
| Documentation | ? | 8 | ?% |
| Sauvegarde | ? | 8 | ?% |
| Environnement | ? | 11 | ?% |
| **TOTAL** | **?** | **73** | **?%** |

### Interprétation
- **100%** : ✅ PRÊT POUR PRODUCTION
- **90-99%** : ⚠️ PRÊT AVEC RÉSERVES MINEURES
- **80-89%** : ⚠️ PRÊT POUR RECETTE SEULEMENT
- **<80%** : ❌ PAS PRÊT POUR DÉPLOIEMENT

---

## 🚀 PROCÉDURE DE DÉPLOIEMENT

### 1. Préparation
```powershell
# Sauvegarder l'existant
Copy-Item C:\AD-WebInterface C:\AD-WebInterface.backup -Recurse

# Installer la nouvelle version
# ... (procédure d'installation)
```

### 2. Installation
```powershell
# Installer le service
cd C:\AD-WebInterface
.\install_service.bat

# Démarrer le service
net start ADWebInterface

# Vérifier le service
sc query ADWebInterface
```

### 3. Tests
```powershell
# Test de santé
Invoke-WebRequest http://localhost:5000/api/health

# Test des routes principales
Invoke-WebRequest http://localhost:5000/
Invoke-WebRequest http://localhost:5000/connect
```

### 4. Validation
- [ ] Service RUNNING
- [ ] API Health → 200 OK
- [ ] Page de connexion → 200 OK
- [ ] Connexion AD → Fonctionnelle
- [ ] Menu complet → Fonctionnel

---

## 📞 SUPPORT

### Contacts
- **Développeur :** Frédéric SELEST
- **Repository :** https://github.com/fred-selest/microsoft-active-directory
- **Issues :** https://github.com/fred-selest/microsoft-active-directory/issues

### Logs
- **Application :** `C:\AD-WebInterface\logs\server.log`
- **Audit :** `C:\AD-WebInterface\logs\audit.log`
- **Service :** `C:\AD-WebInterface\logs\service.log`
- **Erreurs :** `C:\AD-WebInterface\logs\service_error.log`

---

**Document créé :** 2026-04-06  
**Version :** v1.34.4  
**Statut :** PRÊT POUR DÉPLOIEMENT ✅
