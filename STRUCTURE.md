# 🌳 ARBORESCENCE - AD Web Interface v1.34.5

## 📊 STRUCTURE ACTUELLE

```
C:\AD-WebInterface\
│
├── 📁 routes/                    # ✅ Blueprints Flask (modulaire)
│   ├── __init__.py
│   ├── core.py                   # Connexion AD, RBAC, permissions
│   ├── main.py                   # Routes principales
│   ├── api.py                    # API REST
│   ├── admin_tools.py            # Outils admin
│   ├── users/                    # 👥 Blueprint utilisateurs
│   │   ├── __init__.py
│   │   ├── list_users.py
│   │   ├── create.py
│   │   ├── delete.py
│   │   ├── update.py
│   │   ├── password.py
│   │   ├── move.py
│   │   ├── helpers.py
│   │   └── validators.py
│   ├── groups/                   # 👥 Blueprint groupes
│   │   └── __init__.py
│   ├── computers/                # 💻 Blueprint ordinateurs
│   │   └── __init__.py
│   ├── ous/                      # 📁 Blueprint OUs
│   │   └── __init__.py
│   ├── tools/                    # 🔧 Blueprint outils
│   │   ├── __init__.py
│   │   ├── laps.py
│   │   ├── bitlocker.py
│   │   ├── accounts.py
│   │   ├── password.py
│   │   ├── backups.py
│   │   └── misc.py
│   ├── admin/                    # ⚙️ Blueprint admin
│   │   └── __init__.py
│   └── debug/                    # 🐛 Blueprint debug
│       └── __init__.py
│
├── 📁 templates/                 # ✅ Templates HTML (51 fichiers)
│   ├── base.html
│   ├── index.html
│   ├── connect.html
│   ├── dashboard.html
│   ├── users.html
│   ├── groups.html
│   ├── computers.html
│   ├── ous.html
│   ├── admin.html
│   ├── alerts.html
│   ├── audit.html
│   ├── security_audit.html
│   ├── permissions.html
│   └── ... (38 autres)
│
├── 📁 static/                    # ✅ Assets statiques
│   ├── css/
│   │   ├── styles.css
│   │   └── responsive.css
│   ├── js/
│   │   └── main.js
│   └── icons/
│       └── icon.svg
│
├── 📁 password_audit/            # ✅ Module audit MDP
│   ├── __init__.py
│   ├── admin.py
│   ├── analyzer.py
│   ├── checks.py
│   ├── export.py
│   ├── protocol.py
│   ├── report.py
│   └── runner.py
│
├── 📁 scripts/                   # ✅ Scripts PowerShell
│   ├── laps_management.ps1
│   └── ...
│
├── 📁 nssm/                      # ✅ Service Windows (WinSW)
│   ├── WinSW.exe
│   ├── WinSW.xml
│   ├── ADWebInterface.xml
│   └── ...
│
├── 📁 tests/                     # ✅ Tests automatisés (60+ fichiers)
│   ├── __init__.py
│   ├── test_full.py
│   ├── test_responsive.py
│   └── ...
│
├── 📁 logs/                      # ⚠️ Logs (généré)
│   ├── server.log
│   ├── audit.log
│   └── service.log
│
├── 📁 data/                      # ⚠️ Données (généré)
│   ├── settings.json
│   └── audit_history/
│
├── 📁 venv/                      # ⚠️ Virtualenv (à exclure)
│
├── 📁 __pycache__/               # ❌ Cache Python (à exclure)
│
├── 📁 .git/                      # ⚠️ Git (à exclure)
│
├── 📁 .github/                   # ⚠️ GitHub config
│
├── 📁 .qwen/                     # ⚠️ Qwen config (IDE)
│
├── 📁 .claude/                   # ⚠️ Claude config (IDE)
│
├── 📄 app.py                     # ✅ Application principale (127 lignes)
├── 📄 run.py                     # ✅ Point d'entrée
├── 📄 config.py                  # ✅ Configuration
├── 📄 requirements.txt           # ✅ Dépendances Python
├── 📄 .env.example               # ✅ Modèle configuration
│
├── 📄 security.py                # ✅ Sécurité (CSRF, rate limiting)
├── 📄 session_crypto.py          # ✅ Chiffrement sessions
├── 📄 audit.py                   # ✅ Audit logging
├── 📄 alerts.py                  # ✅ Système d'alertes
├── 📄 backup.py                  # ✅ Sauvegarde objets AD
├── 📄 path_security.py           # ✅ Protection path traversal
├── 📄 translations.py            # ✅ Multi-langue
├── 📄 settings_manager.py        # ✅ Gestion paramètres
├── 📄 features.py                # ✅ Feature flags
├── 📄 context_processor.py       # ✅ Context templates
├── 📄 debug_utils.py             # ✅ Utilitaires debug
├── 📄 diagnostic.py              # ✅ Diagnostic tools
├── 📄 granular_permissions.py    # ✅ Permissions granulaires
├── 📄 password_generator.py      # ✅ Générateur MDP
├── 📄 ldap_errors.py             # ✅ Erreurs LDAP (français)
│
├── 📄 updater.py                 # ✅ Mises à jour auto
├── 📄 ad_detect.py               # ✅ Détection AD auto
├── 📄 dashboard_widgets.py       # ✅ Widgets dashboard
├── 📄 email_notifications.py     # ✅ Notifications email
│
├── 📄 install_service.bat        # ✅ Installation service
├── 📄 uninstall_service.bat      # ✅ Désinstallation service
├── 📄 run_server.bat             # ✅ Démarrage manuel
├── 📄 run_client.bat             # ✅ Raccourci navigateur
├── 📄 run_legacy.bat             # ✅ Démarrage avec MD4
│
├── 📄 openssl_legacy.cnf         # ✅ Config OpenSSL (NTLM)
├── 📄 _openssl_init.py           # ✅ Init OpenSSL MD4
│
├── 📄 DEPLOYMENT_CHECKLIST.md    # ✅ Checklist déploiement
├── 📄 README.md                  # ✅ Documentation principale
├── 📄 QWEN.md                    # ✅ Documentation technique
├── 📄 CHANGELOG.md               # ✅ Historique versions
├── 📄 SECURITY.md                # ✅ Audit sécurité
│
├── 📄 GUIDE_INSTALLATION_WINDOWS.md  # ✅ Guide installation
├── 📄 GUIDE_PERSONNALISATION.md      # ✅ Guide personnalisation
│
├── 📄 VERSION                    # ✅ Version actuelle
│
├── 📄 analyze_css_unused.py      # ❌ OBSOLÈTE
├── 📄 analyze_users.py           # ❌ OBSOLÈTE
├── 📄 auto_alerts.py             # ❌ OBSOLÈTE (intégré dans alerts.py)
├── 📄 auto_commit.bat            # ❌ DEV (à exclure)
├── 📄 auto_reload.py             # ❌ DEV (à exclure)
├── 📄 COMMIT_READY.md            # ❌ DEV
├── 📄 commit_v1.23.0.bat         # ❌ DEV
├── 📄 configure_service.ps1      # ❌ OBSOLÈTE
├── 📄 cookies.txt                # ❌ DEV
├── 📄 create_settings.bat        # ❌ DEV
├── 📄 DEBUG_GUIDE.md             # ⚠️ REDONDANT (dans QWEN.md)
├── 📄 DEBUG_REPORT.md            # ❌ DEV
├── 📄 do_commit.bat              # ❌ DEV
├── 📄 FILE_UTILITY_REPORT.txt    # ❌ DEV
├── 📄 find_overflow.py           # ❌ OBSOLÈTE
├── 📄 fix_decode_ldap.py         # ❌ OBSOLÈTE
├── 📄 fix_md4_final.ps1          # ❌ OBSOLÈTE
├── 📄 fix_md4.ps1                # ❌ OBSOLÈTE
├── 📄 install_ad.bat             # ❌ OBSOLÈTE
├── 📄 install_ad.ps1             # ❌ OBSOLÈTE
├── 📄 ldap_certificate.py        # ❌ NON UTILISÉ
├── 📄 log_watcher.py             # ❌ NON UTILISÉ
├── 📄 manage.py                  # ❌ NON UTILISÉ
├── 📄 MODULARITE.md              # ⚠️ REDONDANT (dans QWEN.md)
├── 📄 password_audit.py.bak      # ❌ BACKUP (à supprimer)
├── 📄 prepare_commit.bat         # ❌ DEV
├── 📄 project.zip                # ❌ ARCHIVE (à supprimer)
├── 📄 PROPOSITIONS_AMELIORATIONS.md  # ❌ DEV
├── 📄 push.bat                   # ❌ DEV
├── 📄 RAPPORT_ANALYSE_ROUTES.md  # ❌ DEV
├── 📄 README_AUTO_RELOAD.md      # ⚠️ REDONDANT
├── 📄 README_DOCUMENTATION.md    # ⚠️ REDONDANT (dans README.md)
├── 📄 RELEASE_NOTES_v1.23.0.md   # ❌ ANCIEN
├── 📄 RESUME_VERSION_1.23.0.md   # ❌ ANCIEN
├── 📄 run_auto_reload.bat        # ❌ DEV
├── 📄 run.sh                     # ❌ LINUX (non utilisé)
├── 📄 save_cookies.py            # ❌ DEV
├── 📄 save_cookies_simple.py     # ❌ DEV
├── 📄 start                      # ❌ INCONNU
├── 📄 test_cookies.json          # ❌ DEV
├── 📄 theme_manager.py           # ❌ NON UTILISÉ
├── 📄 updater_fast.py            # ❌ REDONDANT
```

---

## 🗑️ FICHIERS À SUPPRIMER (33 fichiers)

### Développement (13 fichiers)
```
❌ auto_commit.bat
❌ auto_reload.py
❌ COMMIT_READY.md
❌ commit_v1.23.0.bat
❌ cookies.txt
❌ create_settings.bat
❌ DEBUG_REPORT.md
❌ do_commit.bat
❌ FILE_UTILITY_REPORT.txt
❌ prepare_commit.bat
❌ push.bat
❌ test_cookies.json
❌ project.zip
```

### Obsolètes (11 fichiers)
```
❌ analyze_css_unused.py
❌ analyze_users.py
❌ auto_alerts.py
❌ configure_service.ps1
❌ find_overflow.py
❌ fix_decode_ldap.py
❌ fix_md4_final.ps1
❌ fix_md4.ps1
❌ install_ad.bat
❌ install_ad.ps1
❌ password_audit.py.bak
```

### Non utilisés (7 fichiers)
```
❌ ldap_certificate.py
❌ log_watcher.py
❌ manage.py
❌ PROPOSITIONS_AMELIORATIONS.md
❌ run.sh
❌ save_cookies.py
❌ save_cookies_simple.py
❌ start
```

### Redondants (5 fichiers)
```
⚠️ DEBUG_GUIDE.md (dans QWEN.md)
⚠️ MODULARITE.md (dans QWEN.md)
⚠️ README_AUTO_RELOAD.md (dans QWEN.md)
⚠️ README_DOCUMENTATION.md (dans README.md)
⚠️ RELEASE_NOTES_v1.23.0.md (dans CHANGELOG.md)
⚠️ RESUME_VERSION_1.23.0.md (dans CHANGELOG.md)
```

---

## ✅ STRUCTURE RECOMMANDÉE (PROPRE)

```
C:\AD-WebInterface\
│
├── 📁 routes/                    # Blueprints (10 modules)
├── 📁 templates/                 # Templates HTML (51)
├── 📁 static/                    # CSS, JS, icons
├── 📁 password_audit/            # Audit MDP (8 modules)
├── 📁 scripts/                   # PowerShell scripts
├── 📁 nssm/                      # Service Windows
├── 📁 tests/                     # Tests (60+)
├── 📁 logs/                      # Logs [GÉNÉRÉ]
├── 📁 data/                      # Données [GÉNÉRÉ]
├── 📁 venv/                      # Virtualenv [EXCLURE]
│
├── 📄 app.py                     # Application principale
├── 📄 run.py                     # Point d'entrée
├── 📄 config.py                  # Configuration
├── 📄 requirements.txt           # Dépendances
│
├── 📄 security.py                # Sécurité
├── 📄 session_crypto.py          # Chiffrement
├── 📄 audit.py                   # Audit logging
├── 📄 alerts.py                  # Alertes
├── 📄 backup.py                  # Backup AD
├── 📄 path_security.py           # Path traversal
├── 📄 translations.py            # Multi-langue
├── 📄 settings_manager.py        # Paramètres
├── 📄 features.py                # Feature flags
├── 📄 context_processor.py       # Context templates
├── 📄 debug_utils.py             # Debug utils
├── 📄 diagnostic.py              # Diagnostic
├── 📄 granular_permissions.py    # Permissions
├── 📄 password_generator.py      # Générateur MDP
├── 📄 ldap_errors.py             # Erreurs LDAP
├── 📄 dashboard_widgets.py       # Widgets
├── 📄 email_notifications.py     # Emails
│
├── 📄 updater.py                 # Auto-update
├── 📄 ad_detect.py               # Détection AD
│
├── 📄 install_service.bat        # Installation
├── 📄 uninstall_service.bat      # Désinstallation
├── 📄 run_server.bat             # Démarrage
├── 📄 run_client.bat             # Raccourci
├── 📄 run_legacy.bat             # Mode legacy
│
├── 📄 openssl_legacy.cnf         # Config OpenSSL
├── 📄 _openssl_init.py           # Init OpenSSL
│
├── 📄 DEPLOYMENT_CHECKLIST.md    # ✅ Checklist déploiement
├── 📄 README.md                  # ✅ Documentation
├── 📄 QWEN.md                    # ✅ Technique
├── 📄 CHANGELOG.md               # ✅ Versions
├── 📄 SECURITY.md                # ✅ Sécurité
├── 📄 GUIDE_INSTALLATION_WINDOWS.md  # ✅ Installation
├── 📄 GUIDE_PERSONNALISATION.md      # ✅ Personnalisation
│
├── 📄 .env.example               # ✅ Modèle config
├── 📄 .gitignore                 # ✅ Git ignore
├── 📄 VERSION                    # ✅ Version
│
└── 📄 updater_fast.py            # ⚠️ À vérifier (utilisé ?)
```

---

## 📊 STATISTIQUES

| Catégorie | Actuel | Recommandé | Gain |
|-----------|--------|------------|------|
| **Fichiers Python** | ~50 | ~25 | -50% |
| **Fichiers .bat/.ps1** | ~15 | ~6 | -60% |
| **Documentation** | ~15 | ~6 | -60% |
| **Total fichiers** | ~101 | ~65 | **-35%** |

---

## 🎯 RECOMMANDATIONS

### 1. Nettoyage Immédiat (33 fichiers)
```batch
# Supprimer fichiers inutiles
del /Q auto_commit.bat auto_reload.py COMMIT_READY.md ...
del /Q password_audit.py.bak project.zip ...
```

### 2. Nettoyage .gitignore
```gitignore
# Déjà exclus :
__pycache__/
*.pyc
venv/
logs/
data/
.env

# À ajouter :
*.bak
*.zip
test_*.json
cookies.txt
```

### 3. Documentation Unifiée
- ✅ **README.md** → Documentation utilisateur
- ✅ **QWEN.md** → Documentation technique
- ✅ **DEPLOYMENT_CHECKLIST.md** → Déploiement
- ❌ **Supprimer** → DEBUG_GUIDE.md, MODULARITE.md, etc.

---

## ✅ AVANTAGES DU NETTOYAGE

| Avantage | Impact |
|----------|--------|
| **Lisibilité** | +50% |
| **Maintenance** | +40% |
| **Taille** | -35% |
| **Déploiement** | Plus rapide |
| **Sécurité** | Moins de surface d'attaque |

---

**Document créé :** 2026-04-06  
**Version :** v1.34.5  
**Statut :** ✅ PRÊT POUR NETTOYAGE
