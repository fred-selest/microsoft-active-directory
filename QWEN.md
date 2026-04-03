# Interface Web Microsoft Active Directory - Project Context

## Project Overview

**Name:** Interface Web Microsoft Active Directory  
**Current Version:** 1.21.0  
**Type:** Flask-based web application for managing Microsoft Active Directory  
**Repository:** https://github.com/fred-selest/microsoft-active-directory  

A web-based administration tool for Microsoft Active Directory that allows managing users, groups, computers, and OUs from any browser without client installation.

### Key Features

- **AD Management:** Users, groups, computers, OUs (create, modify, delete, move)
- **LDAP/LDAPS Support:** Ports 389 (LDAP) and 636 (LDAPS)
- **RBAC:** Role-based access control (admin/operator/reader roles based on AD groups)
- **Audit Logging:** Complete journal of all actions
- **Alerts:** Expiring accounts, expiring passwords, inactive accounts
- **Export:** CSV/Excel export for users and groups
- **Responsive UI:** Desktop, tablet, mobile support
- **Dark Mode:** Light/dark theme toggle
- **Multi-language:** French and English
- **Auto-updates:** In-app update detection and installation

### Technology Stack

| Component | Version | Purpose |
|-----------|---------|---------|
| Flask | 3.0.0 | Web framework |
| Werkzeug | 3.0.1 | WSGI utilities |
| ldap3 | 2.9.1 | Active Directory connectivity |
| cryptography | 41.0.7 | Session encryption (Fernet/AES-128) |
| python-dotenv | 1.0.0 | Environment configuration |
| waitress | 2.1.2 | WSGI server (Windows) |
| gunicorn | 21.2.0 | WSGI server (Linux) |
| pycryptodome | 3.20.0 | MD4/NTLM support (Python 3.12+) |

---

## Project Structure

```
C:\AD-WebInterface\
├── app.py                        # Main Flask application
├── run.py                        # Entry point (auto-generates .env)
├── config.py                     # Multi-platform configuration
├── requirements.txt              # Python dependencies
├── routes/                       # Flask blueprints
│   ├── core.py                   # AD connection, RBAC, permissions
│   ├── users.py                  # User management
│   ├── groups.py                 # Group management
│   ├── computers.py              # Computer management
│   ├── ous.py                    # OU management
│   ├── tools.py                  # Utility tools
│   └── admin.py                  # Administration
├── templates/                    # Jinja2 HTML templates (45 files)
├── static/                       # CSS, JavaScript, icons
├── security.py                   # LDAP escaping, CSRF, rate limiting
├── session_crypto.py             # Fernet encryption for sessions
├── audit.py                      # Audit logging
├── alerts.py                     # Alert system
├── backup.py                     # AD object backup
├── path_security.py              # Path traversal protection
├── translations.py               # Multi-language (fr/en)
├── settings_manager.py           # User settings
├── updater.py / updater_fast.py  # Auto-update system
├── diagnostic.py                 # Diagnostic tools
├── password_audit.py             # Password audit
├── ad_detect.py                  # AD auto-detection
├── _openssl_init.py              # OpenSSL MD4/NTLM init (Python 3.12+)
├── openssl_legacy.cnf            # OpenSSL config for NTLM support
├── install_service.bat           # Windows service installation
├── uninstall_service.bat         # Windows service removal
├── run_server.bat                # Manual Windows startup
├── run_legacy.bat                # Startup with MD4 support
├── run_client.bat                # Browser shortcut
├── tests.py                      # Automated test suite
└── .env.example                  # Configuration template
```

### Data Directories

| Directory | Contents |
|-----------|----------|
| `logs/` | Application logs |
| `logs/audit.log` | Audit journal |
| `logs/service.log` | Windows service logs |
| `data/` | Persistent data |
| `data/backups/` | AD object backups |
| `data/crypto_salt.bin` | Unique PBKDF2 salt per deployment |

---

## Building and Running

### Quick Start (Windows Server)

```bat
# 1. Extract to C:\AD-Web\ (no accents/spaces in path)
# 2. Right-click install_service.bat → Run as Administrator
# 3. Access http://SERVER_NAME:5000
```

### Manual Windows Startup

```bat
# Development mode
python run.py

# Production (via service)
net start ADWebInterface

# With MD4/NTLM support (Python 3.12+)
run_legacy.bat
```

### Linux Production

```bash
git clone https://github.com/fred-selest/microsoft-active-directory.git
cd microsoft-active-directory

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Generate configuration
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
echo "FLASK_ENV=production" >> .env

# Production with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 'app:app'
```

### Running Tests

```bash
# Run full test suite
python tests.py

# Expected: 14/14 tests passed
# Report: logs/test_report.json
```

### Service Management (Windows)

```bat
net start ADWebInterface      # Start
net stop ADWebInterface       # Stop
sc query ADWebInterface       # Status
uninstall_service.bat         # Uninstall (admin)
```

---

## Configuration

### Environment Variables (.env)

```ini
# CRITICAL: Generate with python -c 'import secrets; print(secrets.token_hex(32))'
SECRET_KEY=your-secret-key

# Server
FLASK_ENV=production
FLASK_DEBUG=false
AD_WEB_HOST=0.0.0.0
AD_WEB_PORT=5000

# Session
SESSION_COOKIE_SECURE=true
SESSION_TIMEOUT=30

# Active Directory (optional - configurable via UI)
AD_SERVER=dc01.company.local
AD_PORT=389
AD_USE_SSL=false
AD_BASE_DN=DC=company,DC=local

# RBAC
RBAC_ENABLED=true
DEFAULT_ROLE=reader
RBAC_ADMIN_GROUPS=Domain Admins,Administrateurs du domaine
```

### RBAC Roles

| Role | Permissions | Default Groups |
|------|-------------|----------------|
| `admin` | read, write, delete, admin | Domain Admins, Administrateurs du domaine |
| `operator` | read, write | IT Support, Helpdesk |
| `reader` | read | Domain Users (default) |

### Permission Matrix

| Action | admin | operator | reader |
|--------|-------|----------|--------|
| View users/groups/computers | ✅ | ✅ | ✅ |
| Create/modify users | ✅ | ✅ | ❌ |
| Create/modify groups | ✅ | ✅ | ❌ |
| Delete objects | ✅ | ❌ | ❌ |
| RBAC management | ✅ | ❌ | ❌ |
| Audit logs | ✅ | ❌ | ❌ |

---

## Development Conventions

### Code Style

- **Python:** 3.8+ compatible
- **Docstrings:** French
- **Function names:** English
- **Comments:** French
- **Type hints:** Used moderately

### Error Handling Pattern

```python
# ✅ Good: Log errors
try:
    # ...
except Exception as e:
    logger.warning(f"Error: {e}", exc_info=True)

# ❌ Bad: Silent ignore
try:
    # ...
except:
    pass
```

### Security Patterns

**LDAP Injection Protection:**
```python
from security import escape_ldap_filter
safe_filter = escape_ldap_filter(user_input)  # Escapes: \ * ( ) etc.
```

**CSRF Protection:**
```python
from security import generate_csrf_token, validate_csrf_token
# In template: <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
# In route: if not validate_csrf_token(request.form.get('csrf_token')): ...
```

**Session Encryption:**
```python
from session_crypto import encrypt_password, decrypt_password
# Passwords encrypted with Fernet (AES-128 CBC) + PBKDF2 (100k iterations)
```

**RBAC Permission Check:**
```python
from routes.core import require_permission

@users_bp.route('/delete', methods=['POST'])
@require_permission('delete')
def delete_user():
    # Only admin can access
```

### Logging

| File | Content | Level |
|------|---------|-------|
| `logs/audit.log` | Audit journal (all actions) | INFO |
| `logs/service.log` | Windows service logs | INFO |
| `logs/service_error.log` | Service errors | ERROR |
| `logs/server.log` | Flask/Waitress logs | INFO |

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check (Docker/K8s) |
| `/api/system-info` | GET | System information |
| `/api/check-update` | GET | Check for updates |
| `/api/perform-update` | POST | Perform update |
| `/api/diagnostic` | GET | Run diagnostics |
| `/api/password-audit` | GET | Password audit |

---

## Security Features

### Implemented Protections

| Feature | Description | Status |
|---------|-------------|--------|
| Session encryption | Fernet (AES-128 CBC) + PBKDF2 (100k iterations) | ✅ |
| Unique salt | PBKDF2 salt per deployment (`data/crypto_salt.bin`) | ✅ |
| LDAP injection | Special character escaping | ✅ |
| CSRF protection | Tokens on all forms | ✅ |
| Rate limiting | 5 attempts / 5 minutes on login | ✅ |
| Security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options | ✅ |
| RBAC | Enabled by default with reader minimum role | ✅ |
| Secure cookies | SESSION_COOKIE_SECURE=true by default | ✅ |
| Path traversal | Path validation | ✅ |
| DN validation | Distinguished Name sanitization | ✅ |

### Security Checklist

- [ ] SECRET_KEY generated (32 bytes hex)
- [ ] HTTPS enabled with valid certificate
- [ ] `SESSION_COOKIE_SECURE=true`
- [ ] `FLASK_DEBUG=false` in production
- [ ] `RBAC_ENABLED=true`
- [ ] `DEFAULT_ROLE=reader`
- [ ] LDAPS enabled (port 636) recommended
- [ ] Firewall configured (restricted access)
- [ ] Logs protected with restrictive permissions

---

## Common Issues

| Problem | Cause | Solution |
|---------|-------|---------|
| Port 5000 in use | Port conflict | Set `AD_WEB_PORT=8080` in `.env` |
| MD4/NTLM error (Python 3.12+) | MD4 hash disabled | Use `run_legacy.bat` or check `openssl_legacy.cnf` |
| Service won't start | Configuration error | Check `logs\service_error.log` and Event Viewer |
| Connection refused from network | Firewall blocking | Verify rule: `netsh advfirewall firewall show rule name="AD Web Interface"` |
| Invalid credentials (LDAP 49) | Wrong username format | Use `DOMAIN\user` or `user@domain.local` |
| `python3-venv` not found (Ubuntu) | Missing package | `sudo apt install python3-venv` |
| Slow startup (60+s) | Waitress issue | Fixed in v1.17.4+ |

---

## File Reading Guide

### Core Files

| File | When to Read |
|------|--------------|
| `app.py` | Main application, routes, Flask setup |
| `config.py` | Configuration classes, environment variables |
| `run.py` | Entry point, .env auto-generation |
| `routes/core.py` | AD connection, RBAC, permissions |
| `security.py` | LDAP escaping, CSRF, rate limiting |
| `session_crypto.py` | Session encryption (Fernet) |

### Feature Files

| File | When to Read |
|------|--------------|
| `routes/users.py` | User management blueprint |
| `routes/groups.py` | Group management blueprint |
| `routes/computers.py` | Computer management blueprint |
| `routes/ous.py` | OU management blueprint |
| `audit.py` | Audit logging system |
| `alerts.py` | Alert system |
| `backup.py` | AD object backup |

### Installation Files

| File | When to Read |
|------|--------------|
| `install_service.bat` | Windows service installation script |
| `GUIDE_INSTALLATION_WINDOWS.md` | Windows installation guide |
| `.env.example` | Configuration template |

---

## Testing

### Test Categories

| Test | Description |
|------|-------------|
| Configuration | SECRET_KEY validation, RBAC, default role |
| LDAP escaping | Injection protection |
| CSRF tokens | Generation and validation |
| Session encryption | AES-128 Fernet with PBKDF2 |
| Translations | French/English support |
| Audit module | 20+ actions defined |
| Core routes | admin/operator/reader roles |
| Flask app | 45+ routes registered |
| Health endpoint | `/api/health` |
| Update endpoint | `/api/check-update` |
| Homepage | Accessibility |
| Directories | logs/, data/ exist |
| .env file | Valid configuration |
| Dependencies | 6 critical modules |

---

## Update System

The application includes automatic update detection and installation:

1. **Check:** `/api/check-update` compares local VERSION with GitHub releases
2. **Download:** `updater_fast.py` downloads release ZIP
3. **Install:** Extracts files, preserves `.env` and `data/`
4. **Dependencies:** Updates pip packages
5. **Restart:** Restarts service automatically

---

## Architecture Notes

### Connection Flow

```
Browser → Flask (Waitress/Gunicorn) → LDAP3 → Active Directory
                ↓
        Session encryption (Fernet)
                ↓
        RBAC (AD group membership)
                ↓
        Audit logging
```

### Authentication Flow

1. User submits credentials on `/connect`
2. Rate limiting check (5 attempts / 5 min)
3. Try multiple auth methods: NTLM → STARTTLS → LDAPS
4. On success: encrypt password, store in session
5. Determine role from AD group membership
6. Log audit entry

### Session Management

- Sessions stored in Flask session cookie
- Password encrypted with Fernet (AES-128)
- Key derived from SECRET_KEY + unique salt (PBKDF2, 100k iterations)
- Salt persisted in `data/crypto_salt.bin`
- Session timeout: 30 minutes (configurable)

---

## Important Constants

```python
# RBAC Permissions
ROLE_PERMISSIONS = {
    'admin': ['read', 'write', 'delete', 'admin'],
    'operator': ['read', 'write'],
    'reader': ['read']
}

# LDAP Escape Characters
LDAP_ESCAPE_CHARS = {
    '\\': r'\5c',
    '*': r'\2a',
    '(': r'\28',
    ')': r'\29',
    '\x00': r'\00',
}

# Audit Actions
ACTIONS = {
    'CREATE_USER': 'create_user',
    'EDIT_USER': 'edit_user',
    'DELETE_USER': 'delete_user',
    'LOGIN': 'login',
    'LOGOUT': 'logout',
    # ... 20+ actions
}
```

---

## Related Documentation

- [README.md](README.md) - User-facing documentation
- [GUIDE_INSTALLATION_WINDOWS.md](GUIDE_INSTALLATION_WINDOWS.md) - Windows installation guide
- [SECURITY.md](SECURITY.md) - Security audit report
- [CHANGELOG.md](CHANGELOG.md) - Version history
- [.env.example](.env.example) - Configuration reference

## Qwen Added Memories
- Projet AD Web Interface - En cours de refactoring pour modularité complète. Objectifs : (1) Corriger routes manquantes (restore_deleted_object, bulk_unlock_accounts), (2) Rendre toutes fonctionnalités désactivables via config, (3) Remplacer redirections 302 par pages dédiées, (4) Architecture modulaire avec feature flags. Stack: Flask 3.0, Python 3.12, LDAP3, Waitress. Répertoire: C:\AD-WebInterface
