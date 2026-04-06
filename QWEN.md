# Interface Web Microsoft Active Directory - Project Context

## Project Overview
- **Name:** Interface Web Microsoft Active Directory
- **Version:** 1.34.2
- **Repository:** https://github.com/fred-selest/microsoft-active-directory
- **Directory:** C:\AD-WebInterface\
- **Latest Release:** v1.34.2 - https://github.com/fred-selest/microsoft-active-directory/releases/tag/v1.34.2

## Key Features
- 👥 Users, groups, computers, OUs management
- 🔐 LDAP/LDAPS Support (ports 389/636)
- 🔑 RBAC (admin/operator/reader) + 40 granular permissions
- 🔒 Session Encryption (Fernet AES-128 + PBKDF2)
- 🎲 Password Generator (configurable complexity)
- 🏛️ Special AD Groups Detection (Domain Computers, etc.)
- 💻 Interactive Computers Page (clickable rows)
- 🛡️ LDAP Errors in French with solutions

## Technology Stack
| Component | Version | Purpose |
|-----------|---------|---------|
| Flask | 3.0.0 | Web framework |
| Python | 3.12+ | Runtime |
| ldap3 | 2.9.1 | AD connectivity |
| cryptography | 41.0.7 | Session encryption |
| waitress | 2.1.2 | WSGI server (Windows) |

## Project Structure
```
C:\AD-WebInterface\
├── app.py                        # Main Flask app (127 lines, was 1259)
├── run.py                        # Entry point
├── config.py                     # Configuration
├── requirements.txt              # Dependencies
├── routes/                       # Modular blueprints
│   ├── core.py                   # AD connection, RBAC, permissions
│   ├── main.py                   # Index, connect, disconnect, dashboard
│   ├── api.py                    # REST API endpoints
│   ├── admin_tools.py            # Admin settings, password config
│   ├── users/                    # Users blueprint (modular)
│   │   ├── __init__.py
│   │   ├── list_users.py
│   │   ├── create.py
│   │   ├── delete.py
│   │   ├── update.py
│   │   ├── password.py
│   │   ├── move.py
│   │   ├── helpers.py
│   │   └── validators.py
│   ├── groups/                   # Groups blueprint
│   ├── computers/                # Computers blueprint
│   ├── ous/                      # OUs blueprint
│   ├── tools/                    # Tools blueprint (LAPS, audits, etc.)
│   ├── admin/                    # Admin blueprint
│   └── debug/                    # Debug blueprint
├── templates/                    # Jinja2 HTML templates
├── static/                       # CSS, JavaScript, icons
├── tests/                        # Automated tests (60+ files)
│   ├── __init__.py
│   ├── test_full.py
│   ├── test_responsive.py
│   ├── test_users_complete.py
│   └── ... (60+ test files)
├── password_audit/               # Password audit package
│   ├── __init__.py
│   ├── admin.py
│   ├── analyzer.py
│   ├── checks.py
│   ├── export.py
│   ├── protocol.py
│   ├── report.py
│   └── runner.py
├── logs/                         # Application logs
├── data/                         # Persistent data (settings, backups)
│   ├── settings.json
│   └── audit_history/
├── nssm/                         # Windows service files
└── [Utility files]
```

## New Files (v1.34.1-v1.34.2)
| File | Purpose |
|------|---------|
| `ldap_errors.py` | LDAP error handling in French |
| `password_generator.py` | Secure password generator |
| `routes/main.py` | Main routes (was in app.py) |
| `routes/api.py` | API routes (was in app.py) |
| `routes/admin_tools.py` | Admin tools routes |
| `routes/users/*.py` | Modular users blueprint |
| `tests/*.py` | 60+ automated test files |

## Architecture
- **app.py:** Reduced from 1259 to 127 lines (-89.9%)
- **10 Blueprints:** main, api, admin_tools, users, groups, computers, ous, tools, admin, debug
- **102 Routes:** All organized by blueprint
- **Modular Design:** Each feature in its own module

## Security Checklist
- [x] SECRET_KEY generated (32 bytes hex)
- [x] HTTPS configurable
- [x] `SESSION_COOKIE_SECURE=true`
- [x] `FLASK_DEBUG=false` in production
- [x] `RBAC_ENABLED=true`
- [x] `DEFAULT_ROLE=reader`
- [x] LDAP injection protection
- [x] CSRF tokens on all forms
- [x] Rate limiting (5 attempts/5min)
- [x] Session encryption (Fernet + PBKDF2)

## Qwen Added Memories
- **v1.34.2:** Tests cleanup (root → tests/), 60+ files organized
- **v1.34.1:** app.py 1259→127 lines, 10 blueprints, 102 routes
- **New:** ldap_errors.py, password_generator.py
- **Features:** Special AD groups detection, interactive computers page
- **Fixes:** unwillingToPerform error, special groups showing 0 members
