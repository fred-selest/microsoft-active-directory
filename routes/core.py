"""
Fonctions core partagées entre tous les blueprints.
"""
import ssl
from functools import wraps
from flask import session, redirect, url_for, flash, request
from ldap3 import Server, Connection, ALL, SUBTREE, Tls, NTLM, SIMPLE
from ldap3.core.exceptions import LDAPException

from config import get_config
from security import escape_ldap_filter
from session_crypto import decrypt_password

config = get_config()

ROLE_PERMISSIONS = {
    'admin': ['read', 'write', 'delete', 'admin'],
    'operator': ['read', 'write'],
    'reader': ['read']
}


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
            return redirect(url_for('connect'))
        return f(*args, **kwargs)
    return decorated_function


def require_permission(permission):
    """Decorateur pour verifier les permissions RBAC."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if config.RBAC_ENABLED:
                user_role = session.get('user_role', config.DEFAULT_ROLE)
                if permission not in ROLE_PERMISSIONS.get(user_role, []):
                    flash('Permission refusee.', 'error')
                    return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_ad_connection(server=None, username=None, password=None, use_ssl=False, port=None):
    """Créer une connexion à Active Directory."""
    if server is None:
        server = session.get('ad_server')
    if username is None:
        username = session.get('ad_username')
    if password is None:
        encrypted_password = session.get('ad_password')
        if encrypted_password:
            try:
                password = decrypt_password(encrypted_password)
            except ValueError:
                return None, "Session invalide"
    if use_ssl is False:
        use_ssl = session.get('ad_use_ssl', False)
    if port is None:
        port = session.get('ad_port')

    if not all([server, username, password]):
        return None, "Non connecté"

    if port is None:
        port = 636 if use_ssl else 389

    tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS)

    # Format NTLM
    ntlm_user = username
    if '\\' not in username and '@' not in username:
        domain = None
        if server and '.' in server:
            parts = server.split('.')
            if len(parts) >= 2:
                domain = parts[1].upper()
        if not domain:
            base_dn = session.get('ad_base_dn', '')
            if base_dn:
                dc_parts = [p.split('=')[1] for p in base_dn.upper().split(',') if p.startswith('DC=')]
                if dc_parts:
                    domain = dc_parts[0]
        if domain:
            ntlm_user = f"{domain}\\{username}"

    def try_connection(srv, usr, pwd, auth_type=NTLM):
        """Tenter une connexion avec les paramètres donnés."""
        try:
            conn = Connection(srv, user=usr, password=pwd, authentication=auth_type, auto_bind=True)
            return conn, None
        except Exception as e:
            return None, str(e)

    def try_ssl_connection(srv_host, ntlm_usr, simple_usr, pwd):
        """Tenter connexion SSL sur port 636."""
        ssl_port = 636
        ad_server_ssl = Server(srv_host, port=ssl_port, use_ssl=True,
                              tls=tls_config, get_info=ALL)

        # Essayer NTLM avec SSL
        conn, ssl_err = try_connection(ad_server_ssl, ntlm_usr, pwd, NTLM)
        if conn:
            session['ad_use_ssl'] = True
            session['ad_port'] = ssl_port
            return conn, None

        # Essayer simple bind avec SSL
        conn, ssl_err2 = try_connection(ad_server_ssl, simple_usr, pwd, SIMPLE)
        if conn:
            session['ad_use_ssl'] = True
            session['ad_port'] = ssl_port
            return conn, None

        # Essayer STARTTLS sur le port 389
        try:
            ad_server_tls = Server(srv_host, port=389, get_info=ALL)
            conn = Connection(ad_server_tls, user=ntlm_usr, password=pwd, authentication=NTLM)
            conn.start_tls()
            if conn.bind():
                session['ad_use_ssl'] = False
                session['ad_port'] = 389
                return conn, None
        except Exception:
            pass

        return None, f"SSL/TLS requis. Erreur: {ssl_err or ssl_err2}"

    try:
        ad_server = Server(server, port=port, use_ssl=use_ssl,
                          tls=tls_config if use_ssl else None, get_info=ALL)

        all_errors = []

        # NTLM auth
        conn, ntlm_err = try_connection(ad_server, ntlm_user, password, NTLM)
        if conn:
            return conn, None
        if ntlm_err:
            all_errors.append(ntlm_err)

        # Simple bind fallback
        conn, simple_err = try_connection(ad_server, username, password, SIMPLE)
        if conn:
            return conn, None
        if simple_err:
            all_errors.append(simple_err)

        # Dernière tentative sans auto_bind
        conn = Connection(ad_server, user=username, password=password)
        if conn.bind():
            return conn, None
        last_err = conn.result.get('description', 'erreur inconnue')
        all_errors.append(last_err)

        # Si strongerAuthRequired dans une des erreurs et pas déjà en SSL, réessayer avec SSL
        if not use_ssl and any('strongerAuthRequired' in str(e) for e in all_errors):
            return try_ssl_connection(server, ntlm_user, username, password)

        return None, f"Échec authentification: {last_err}"

    except LDAPException as e:
        err_str = str(e)
        if 'strongerAuthRequired' in err_str and not use_ssl:
            return try_ssl_connection(server, ntlm_user, username, password)
        return None, err_str
    except Exception as e:
        err_str = str(e)
        if 'strongerAuthRequired' in err_str and not use_ssl:
            return try_ssl_connection(server, ntlm_user, username, password)
        return None, f"Erreur: {err_str}"


def get_user_role_from_groups(conn, username, debug=False):
    """Déterminer le rôle de l'utilisateur en fonction de ses groupes AD."""
    info = {'groups': [], 'error': None}

    if not config.RBAC_ENABLED:
        return (config.DEFAULT_ROLE, info) if debug else config.DEFAULT_ROLE

    try:
        base_dn = session.get('ad_base_dn', '')
        if not base_dn and conn.server.info and conn.server.info.naming_contexts:
            base_dn = str(conn.server.info.naming_contexts[0])

        search_user = username.split('\\')[-1].split('@')[0]

        conn.search(base_dn, f'(sAMAccountName={escape_ldap_filter(search_user)})',
                    search_scope=SUBTREE, attributes=['memberOf'])

        if not conn.entries:
            info['error'] = f'Utilisateur {search_user} non trouve'
            return (config.DEFAULT_ROLE, info) if debug else config.DEFAULT_ROLE

        user_groups = []
        if hasattr(conn.entries[0], 'memberOf') and conn.entries[0].memberOf:
            for dn in conn.entries[0].memberOf.values:
                if str(dn).upper().startswith('CN='):
                    user_groups.append(str(dn).split(',')[0][3:])

        info['groups'] = user_groups
        groups_lower = [g.lower() for g in user_groups]

        for role, groups_config in [('admin', config.ADMIN_GROUPS),
                                     ('operator', config.OPERATOR_GROUPS),
                                     ('reader', config.READER_GROUPS)]:
            if any(g.lower() in groups_lower for g in groups_config if g):
                return (role, info) if debug else role

        return (config.DEFAULT_ROLE, info) if debug else config.DEFAULT_ROLE

    except Exception as e:
        info['error'] = str(e)
        return (config.DEFAULT_ROLE, info) if debug else config.DEFAULT_ROLE
