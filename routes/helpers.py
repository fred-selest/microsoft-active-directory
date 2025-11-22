"""
Fonctions helpers partagées entre les routes.
"""
from functools import wraps
from flask import session, redirect, url_for, flash, request
from ldap3 import SUBTREE


def decode_ldap_value(value):
    """Decoder correctement une valeur LDAP en UTF-8."""
    if value is None:
        return ''
    if hasattr(value, 'value'):
        val = value.value
    else:
        val = value
    if val is None:
        return ''
    if isinstance(val, bytes):
        try:
            return val.decode('utf-8')
        except:
            return val.decode('latin-1')
    if isinstance(val, list):
        return [decode_ldap_value(v) for v in val]
    return str(val)


def is_connected():
    """Vérifier si l'utilisateur est connecté à AD."""
    return all([
        session.get('ad_server'),
        session.get('ad_username'),
        session.get('ad_password')
    ])


def require_connection(f):
    """Décorateur pour exiger une connexion AD."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_connected():
            flash('Veuillez vous connecter à Active Directory.', 'warning')
            return redirect(url_for('main.connect'))
        return f(*args, **kwargs)
    return decorated_function


def require_permission(permission):
    """Decorateur pour verifier les permissions RBAC."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from config import get_config
            config = get_config()
            ROLE_PERMISSIONS = {
                'admin': ['read', 'write', 'delete', 'admin'],
                'operator': ['read', 'write'],
                'reader': ['read']
            }
            if config.RBAC_ENABLED:
                user_role = session.get('user_role', config.DEFAULT_ROLE)
                if permission not in ROLE_PERMISSIONS.get(user_role, []):
                    flash('Permission refusee. Vous n\'avez pas les droits necessaires.', 'error')
                    return redirect(url_for('main.index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
