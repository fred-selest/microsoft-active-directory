# AD Web Interface - Project Documentation

**Version:** 1.34.2  
**Last Updated:** December 2025  
**Repository:** https://github.com/fred-selest/microsoft-active-directory  
**Directory:** `C:\AD-WebInterface\`

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Project Structure](#project-structure)
5. [Technology Stack](#technology-stack)
6. [Security](#security)
7. [Development](#development)
8. [Deployment](#deployment)
9. [Testing](#testing)
10. [Changelog](#changelog)

---

## 🎯 Overview

**AD Web Interface** is a modern web application for managing Microsoft Active Directory from any browser, without client installation.

**Key Value Proposition:**
- ✅ 100% Web-based - No client installation required
- ✅ Cross-platform - Windows, Linux, macOS
- ✅ Responsive - Desktop, tablet, mobile support
- ✅ Secure - Encrypted sessions, RBAC, audit logging
- ✅ Modular - 10 blueprints, 102 routes
- ✅ French language - Full French UI and error messages

---

## ✨ Features

### Active Directory Management

| Feature | Description | Status |
|---------|-------------|--------|
| 👥 **Users** | Create, modify, delete, reset password, enable/disable | ✅ |
| 👥 **Groups** | Security & distribution groups, special groups detection | ✅ |
| 💻 **Computers** | Interactive rows with full details modal | ✅ |
| 📁 **OUs** | Organizational units with tree view | ✅ |
| 🔐 **LAPS** | Local admin password management | ✅ |
| 🔒 **BitLocker** | Recovery keys retrieval | ✅ |

### Security & Audit

| Feature | Description | Status |
|---------|-------------|--------|
| 🔍 **Password Audit** | Full analysis with score 0-100 | ✅ |
| 🔐 **Security Audit** | 8 issues detected + 5 auto-fixes | ✅ |
| 🔑 **Permissions** | 40 granular permissions per AD group | ✅ |
| 📋 **Audit Logs** | Complete journal of all actions | ✅ |
| 🚨 **Auto Alerts** | Email notifications for critical issues | ✅ |
| 🎲 **Password Generator** | Configurable complexity | ✅ |
| 🛡️ **LDAP Errors** | French messages with solutions | ✅ |

### Dashboard

- 📈 Real-time security score
- 🚨 Critical alerts widget
- ⚡ Required actions widget
- 📊 Audit statistics
- ⚡ Quick access shortcuts

---

## 🏗️ Architecture

### Modular Design

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
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │              10 Modular Blueprints                  │    │
│  │  main, api, admin_tools, users, groups, computers, │    │
│  │  ous, tools, admin, debug                           │    │
│  └────────────────────────────────────────────────────┘    │
└────────────────────────┬────────────────────────────────────┘
                         │ LDAP/LDAPS (389/636)
┌────────────────────────▼────────────────────────────────────┐
│               Microsoft Active Directory                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Users   │  │  Groups  │  │ Computers│  │   OUs    │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Blueprints

| Blueprint | Routes | Purpose |
|-----------|--------|---------|
| `main` | 7 | Index, connect, disconnect, dashboard, ous, audit, toggle-dark-mode |
| `api` | 12 | REST API endpoints (health, diagnostic, password-audit, alerts, etc.) |
| `admin_tools` | 6 | Admin settings, SMTP, password config |
| `users` | 7 | User management (list, create, edit, delete, reset-password, toggle, move) |
| `groups` | 5 | Group management (list, view, create, edit, delete) |
| `computers` | 4 | Computer management (list, view, toggle, move) |
| `ous` | 4 | OU management (list, create, edit, delete) |
| `tools` | 8 | Tools (LAPS, BitLocker, locked accounts, expiring, password policy, etc.) |
| `admin` | 10 | Administration (settings, permissions, security audit, backups) |
| `debug` | 8 | Debug dashboard and utilities |

**Total:** 102 routes across 10 blueprints

---

## 📁 Project Structure

```
C:\AD-WebInterface\
│
├── app.py                          # Main Flask application (127 lines)
├── run.py                          # Entry point (auto-generates .env)
├── config.py                       # Multi-platform configuration
├── requirements.txt                # Python dependencies
│
├── routes/                         # Flask blueprints (modular)
│   ├── core.py                     # AD connection, RBAC, permissions
│   ├── main.py                     # Main routes (index, connect, dashboard)
│   ├── api.py                      # REST API endpoints
│   ├── admin_tools.py              # Admin settings, password config, SMTP
│   ├── groups/                     # Groups blueprint (modular)
│   │   └── __init__.py             # 8 routes: list, view, create, edit, delete, add/remove member, nested
│   ├── computers/                  # Computers blueprint (modular)
│   │   └── __init__.py             # 4 routes: list, toggle, delete, move
│   ├── ous/                        # OUs blueprint (modular)
│   │   └── __init__.py             # 4 routes: list, create, edit, delete
│   ├── tools/                      # Tools blueprint (modular)
│   │   ├── __init__.py             # Blueprint registration + routes import
│   │   ├── laps.py                 # LAPS passwords
│   │   ├── bitlocker.py            # BitLocker keys
│   │   ├── accounts.py             # Recycle bin, locked accounts, expiring
│   │   ├── password.py             # Password policy, audit, history
│   │   ├── backups.py              # Backups management
│   │   └── misc.py                 # Templates, favorites, API docs
│   ├── admin/                      # Admin blueprint (modular)
│   │   └── __init__.py             # 12 routes: settings, permissions, security audit, alerts
│   └── debug/                      # Debug blueprint (modular)
│       └── __init__.py             # 8 routes: debug dashboard, logs, routes, templates
│
├── templates/                      # Jinja2 HTML templates (51 files)
│   ├── base.html                   # Base template
│   ├── index.html                  # Homepage
│   ├── connect.html                # Login page
│   ├── dashboard.html              # Dashboard
│   ├── users.html                  # Users list
│   ├── create_user.html            # Create user form
│   ├── edit_user.html              # Edit user form
│   ├── reset_password.html         # Reset password form
│   ├── groups.html                 # Groups list
│   ├── computers.html              # Computers list (interactive)
│   ├── ous.html                    # OUs list
│   ├── admin.html                  # Admin settings
│   ├── password_audit.html         # Password audit dashboard
│   └── ... (38 more templates)
│
├── static/                         # Static assets
│   ├── css/                        # Stylesheets
│   │   ├── styles.css              # Main styles
│   │   └── responsive.css          # Mobile responsive
│   ├── js/                         # JavaScript files
│   │   └── main.js                 # Main JavaScript
│   └── icons/                      # PWA icons
│
├── tests/                          # Automated tests (60+ files)
│   ├── __init__.py
│   ├── test_full.py                # Full test suite
│   ├── test_responsive.py          # Responsive design tests
│   ├── test_users_complete.py      # Users module tests
│   └── ... (60+ test files)
│
├── password_audit/                 # Password audit package
│   ├── __init__.py                 # Public API
│   ├── admin.py                    # Admin accounts audit
│   ├── analyzer.py                 # Policy analysis
│   ├── checks.py                   # AD checks
│   ├── export.py                   # CSV/JSON export
│   ├── protocol.py                 # SMB, NTLM, LDAP protocols
│   ├── report.py                   # Specops report
│   └── runner.py                   # Entry point
│
├── ldap_errors.py                  # LDAP error handling (French)
├── password_generator.py           # Secure password generator
├── security.py                     # Security utilities (CSRF, rate limiting)
├── session_crypto.py               # Session encryption (Fernet)
├── audit.py                        # Audit logging
├── alerts.py                       # Alert system
├── backup.py                       # AD object backup
├── path_security.py                # Path traversal protection
├── translations.py                 # Multi-language (FR/EN)
├── settings_manager.py             # User settings management
├── features.py                     # Feature flags system
├── context_processor.py            # Template context injection
├── debug_utils.py                  # Debug utilities
│
├── logs/                           # Application logs
│   ├── server.log                  # Server logs
│   ├── audit.log                   # Audit journal
│   └── test_results/               # Test results
│
├── data/                           # Persistent data
│   ├── settings.json               # User settings
│   └── audit_history/              # Audit history files
│
├── nssm/                           # Windows service files (WinSW)
│
├── .env.example                    # Configuration template
├── .gitignore                      # Git ignore rules
├── README.md                       # User documentation
├── QWEN.md                         # This file (developer docs)
└── requirements.txt                # Python dependencies
```

---

## 🛠️ Technology Stack

| Component | Version | Purpose |
|-----------|---------|---------|
| **Flask** | 3.0.0 | Web framework |
| **Werkzeug** | 3.0.1 | WSGI utilities |
| **Python** | 3.12+ | Runtime |
| **ldap3** | 2.9.1 | Active Directory connectivity |
| **cryptography** | 41.0.7 | Session encryption (Fernet/AES-128) |
| **python-dotenv** | 1.0.0 | Environment configuration |
| **waitress** | 2.1.2 | WSGI server (Windows) |
| **gunicorn** | 21.2.0 | WSGI server (Linux) |
| **pycryptodome** | 3.20.0 | MD4/NTLM support (Python 3.12+) |
| **playwright** | latest | Automated testing |

---

## 🔒 Security

### Implemented Protections

| Feature | Description | Status |
|---------|-------------|--------|
| Session Encryption | Fernet (AES-128 CBC) + PBKDF2 (100k iterations) | ✅ |
| Unique Salt | PBKDF2 salt per deployment (`data/crypto_salt.bin`) | ✅ |
| LDAP Injection | Special character escaping | ✅ |
| CSRF Protection | Tokens on all forms | ✅ |
| Rate Limiting | 5 attempts / 5 minutes on login | ✅ |
| Security Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options | ✅ |
| RBAC | Enabled by default with reader minimum role | ✅ |
| Secure Cookies | SESSION_COOKIE_SECURE=true by default | ✅ |
| Path Traversal | Path validation | ✅ |
| DN Validation | Distinguished Name sanitization | ✅ |

### Security Checklist

```bash
# Production checklist
[ ] SECRET_KEY generated (python -c 'import secrets; print(secrets.token_hex(32))')
[ ] HTTPS enabled with valid certificate
[ ] SESSION_COOKIE_SECURE=true
[ ] FLASK_DEBUG=false
[ ] FLASK_ENV=production
[ ] RBAC_ENABLED=true
[ ] DEFAULT_ROLE=reader
[ ] LDAPS enabled (port 636) recommended
[ ] Firewall configured (restricted access)
[ ] Logs protected with restrictive permissions
```

---

## 💻 Development

### ⚠️ IMPORTANT : Redémarrage requis

**Après chaque modification de code, de template ou de configuration :**

```bash
# Redémarrer le service Windows
net stop ADWebInterface && net start ADWebInterface

# Ou en mode développement
python run.py
```

**Pourquoi ?**
- Les templates HTML sont mis en cache
- Les blueprints sont chargés au démarrage
- `data/settings.json` est lu au démarrage
- Les modules Python sont importés une seule fois

**Vérification :**
```bash
# Vérifier que le service est actif
sc query ADWebInterface

# Vérifier la santé de l'application
curl http://localhost:5000/api/health
```

### Quick Start (Development)

```bash
# Clone repository
git clone https://github.com/fred-selest/microsoft-active-directory.git
cd microsoft-active-directory

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# or: source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Generate configuration
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
echo "FLASK_DEBUG=true" >> .env

# Run development server
python run.py
```

### Running Tests

```bash
# Run full test suite
python tests/test_full.py

# Run specific test
python tests/test_users_complete.py

# Run responsive tests
python tests/test_responsive.py
```

### Code Style

- **Python:** 3.12+ compatible
- **Docstrings:** French
- **Function names:** English
- **Comments:** French
- **Type hints:** Used moderately

---

## 🚀 Deployment

### Windows Server (Production)

```batch
# 1. Extract to C:\AD-Web\ (no accents/spaces)
# 2. Right-click install_service.bat → Run as Administrator
# 3. Access http://SERVER_NAME:5000
```

### Linux Production

```bash
# Clone
git clone https://github.com/fred-selest/microsoft-active-directory.git
cd microsoft-active-directory

# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Configuration
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
echo "FLASK_ENV=production" >> .env

# Production with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 'app:app'
```

### Service Management (Windows)

```batch
net start ADWebInterface      # Start
net stop ADWebInterface       # Stop
sc query ADWebInterface       # Status
uninstall_service.bat         # Uninstall (admin)
```

---

## 🧪 Testing

### Test Coverage

| Category | Files | Status |
|----------|-------|--------|
| **Full Tests** | test_full.py | ✅ |
| **Responsive** | test_responsive.py, test_*.py | ✅ |
| **Users** | test_users_complete.py | ✅ |
| **Groups** | test_groups.py | ✅ |
| **Computers** | test_computers.py | ✅ |
| **Security** | test_alerts*.py | ✅ |
| **Debug** | test_debug*.py | ✅ |

**Total:** 60+ automated test files

---

## 📝 Changelog

### v1.34.2 - December 2025
- 🧹 **Cleanup:** Tests moved to `tests/` directory (60+ files)
- 📁 **Organization:** Root directory cleaned up
- 📖 **Docs:** QWEN.md updated with full structure

### v1.34.1 - December 2025
- 🎲 **Password Generator:** Configurable complexity (low/medium/high/very_high)
- 🏛️ **Special AD Groups:** Detection and real member count (Domain Computers, etc.)
- 💻 **Interactive Computers:** Clickable rows with details modal
- 🐛 **Fixes:** unwillingToPerform error, special groups showing 0 members
- 🛡️ **LDAP Errors:** French messages with solutions
- 📦 **Modularization:** app.py reduced 1259→127 lines (-89.9%)

### v1.34.0 - December 2025
- 📧 **SMTP Configuration:** Admin page with email test
- 🔐 **Security Audit:** Exclusion of Windows system groups (80+ groups)

### v1.33.0 - December 2025
- ✅ **Toggle User:** Fixed activation/deactivation
- 📝 **Logging:** Detailed traces for debugging

### v1.32.0 - December 2025
- ⚡ **Rate Limiting:** Reinforced (5 attempts/5min)
- ✅ **Confirmation Pages:** Login/logout dedicated pages
- ♻️ **Restore:** Deleted object restoration + bulk unlock

---

## 📞 Support

- **Issues:** https://github.com/fred-selest/microsoft-active-directory/issues
- **Discussions:** https://github.com/fred-selest/microsoft-active-directory/discussions
- **Releases:** https://github.com/fred-selest/microsoft-active-directory/releases

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

**Last Updated:** December 2025  
**Maintained By:** Frédéric SELEST
