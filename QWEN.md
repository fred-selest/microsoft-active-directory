# Interface Web Microsoft Active Directory - Project Context

## Project Overview
- Name: Interface Web Microsoft Active Directory
- Version: 1.34.0
- Repository: https://github.com/fred-selest/microsoft-active-directory
- Directory: C:\AD-WebInterface\

## Key Features
- Users, groups, computers, OUs management
- LDAP/LDAPS Support
- RBAC (admin/operator/reader)
- Session Encryption

## Technology Stack
- Flask 3.0.0
- Python 3.12+
- ldap3 2.9.1

## Files Status
- ESSENTIAL: app.py, run.py, config.py, security.py
- UNUSED: 31 files to delete

## Routes to Implement
- restore_deleted_object
- bulk_unlock_accounts
- /admin/code-health

## Security Checklist
- SECRET_KEY generated
- HTTPS enabled
- RBAC_ENABLED=true

## Qwen Added Memories
- v1.34.0: app.py 1259 to 127 lines
- 10 blueprints, 102 routes
- New: ldap_errors.py, password_generator.py
- Special AD groups detection
