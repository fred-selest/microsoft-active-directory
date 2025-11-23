"""
Fonctions core partagées entre tous les blueprints.
"""
import ssl
from functools import wraps
from flask import session, redirect, url_for, flash
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

# Configuration TLS partagée
_tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS)


def decode_ldap_value(value):
    """Decoder une valeur LDAP en UTF-8."""
    if value is None:
        return ''
    val = value.value if hasattr(value, 'value') else value
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
    return all([session.get('ad_server'), session.get('ad_username'), session.get('ad_password')])


def require_connection(f):
    """Décorateur pour exiger une connexion AD."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_connected():
            flash('Veuillez vous connecter à Active Directory.', 'warning')
            return redirect(url_for('connect'))
        return f(*args, **kwargs)
    return decorated


def require_permission(permission):
    """Decorateur pour verifier les permissions RBAC."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if config.RBAC_ENABLED:
                user_role = session.get('user_role', config.DEFAULT_ROLE)
                if permission not in ROLE_PERMISSIONS.get(user_role, []):
                    flash('Permission refusee.', 'error')
                    return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated
    return decorator


# === Helpers pour connexion AD ===

def _is_md4_error(error_msg):
    """Vérifier si l'erreur est liée à MD4 (Python 3.12+)."""
    return any(x in str(error_msg) for x in ['MD4', 'unsupported hash', 'md4'])


def _get_upn_user(server, username):
    """Construire le format UPN (user@domain) pour SIMPLE bind."""
    if '@' in username:
        return username
    simple_user = username.split('\\')[-1] if '\\' in username else username
    if '.' in server:
        domain = '.'.join(server.split('.')[1:])
        return f"{simple_user}@{domain}"
    return simple_user


def _get_ntlm_user(server, username):
    """Construire le format NTLM (DOMAIN\\user)."""
    if '\\' in username or '@' in username:
        return username
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
    return f"{domain}\\{username}" if domain else username


def _try_bind(server_obj, user, password, auth_type=NTLM):
    """Tenter une connexion LDAP."""
    try:
        conn = Connection(server_obj, user=user, password=password, authentication=auth_type, auto_bind=True)
        return conn, None
    except Exception as e:
        return None, str(e)


def _try_secure_connection(server, ntlm_user, username, password):
    """Tenter connexion sécurisée avec fallback MD4."""
    errors = []
    md4_error = False

    # 1. NTLM sur port 389
    try:
        srv = Server(server, port=389, get_info=ALL)
        conn = Connection(srv, user=ntlm_user, password=password, authentication=NTLM, auto_bind=True)
        if conn.bound:
            session['ad_use_ssl'] = False
            session['ad_port'] = 389
            return conn, None
    except Exception as e:
        errors.append(f"NTLM: {str(e)[:60]}")
        md4_error = _is_md4_error(str(e))

    # 2. Si MD4, essayer SIMPLE sur LDAPS
    if md4_error:
        upn = _get_upn_user(server, username)
        try:
            srv = Server(server, port=636, use_ssl=True, tls=_tls_config, get_info=ALL)
            conn = Connection(srv, user=upn, password=password, authentication=SIMPLE, auto_bind=True)
            if conn.bound:
                session['ad_use_ssl'] = True
                session['ad_port'] = 636
                return conn, None
        except Exception as e:
            errors.append(f"SIMPLE LDAPS: {str(e)[:60]}")

    # 3. LDAPS avec NTLM
    try:
        srv = Server(server, port=636, use_ssl=True, tls=_tls_config, get_info=ALL)
        conn, err = _try_bind(srv, ntlm_user, password, NTLM)
        if conn:
            session['ad_use_ssl'] = True
            session['ad_port'] = 636
            return conn, None
        if err:
            errors.append(f"LDAPS: {err[:60]}")
            md4_error = md4_error or _is_md4_error(err)
    except Exception as e:
        errors.append(f"LDAPS: {str(e)[:60]}")

    # 4. Fallback final SIMPLE sur LDAPS
    if md4_error:
        upn = _get_upn_user(server, username)
        try:
            srv = Server(server, port=636, use_ssl=True, tls=_tls_config, get_info=ALL)
            conn = Connection(srv, user=upn, password=password, authentication=SIMPLE, auto_bind=True)
            if conn.bound:
                session['ad_use_ssl'] = True
                session['ad_port'] = 636
                return conn, None
        except Exception as e:
            errors.append(f"SIMPLE fallback: {str(e)[:60]}")

    # Message d'erreur
    if md4_error:
        msg = "Erreur MD4 (Python 3.12+). Activez LDAPS ou utilisez user@domain.com"
    else:
        msg = "Connexion sécurisée impossible. Activez LDAPS ou désactivez LDAP signing dans GPO"
    return None, f"{msg}\nErreurs: {'; '.join(errors)}"


def get_ad_connection(server=None, username=None, password=None, use_ssl=False, port=None):
    """Créer une connexion à Active Directory."""
    # Récupérer les paramètres depuis la session si non fournis
    server = server or session.get('ad_server')
    username = username or session.get('ad_username')
    if password is None:
        encrypted = session.get('ad_password')
        if encrypted:
            try:
                password = decrypt_password(encrypted)
            except ValueError:
                return None, "Session invalide"
    use_ssl = use_ssl or session.get('ad_use_ssl', False)
    port = port or session.get('ad_port') or (636 if use_ssl else 389)

    if not all([server, username, password]):
        return None, "Non connecté"

    ntlm_user = _get_ntlm_user(server, username)

    try:
        srv = Server(server, port=port, use_ssl=use_ssl,
                     tls=_tls_config if use_ssl else None, get_info=ALL)

        # Essayer NTLM
        conn, err = _try_bind(srv, ntlm_user, password, NTLM)
        if conn:
            return conn, None

        # Si MD4, basculer vers connexion sécurisée
        if err and _is_md4_error(err) and not use_ssl:
            return _try_secure_connection(server, ntlm_user, username, password)

        # Essayer SIMPLE
        conn, err2 = _try_bind(srv, username, password, SIMPLE)
        if conn:
            return conn, None

        # Dernière tentative
        conn = Connection(srv, user=username, password=password)
        if conn.bind():
            return conn, None

        last_err = conn.result.get('description', 'erreur inconnue')

        # Si strongerAuthRequired ou MD4
        if not use_ssl and ('strongerAuthRequired' in str(err) + str(err2) + last_err or
                           _is_md4_error(str(err) + str(err2))):
            return _try_secure_connection(server, ntlm_user, username, password)

        return None, f"Échec authentification: {last_err}"

    except LDAPException as e:
        if not use_ssl and ('strongerAuthRequired' in str(e) or _is_md4_error(str(e))):
            return _try_secure_connection(server, ntlm_user, username, password)
        return None, str(e)
    except Exception as e:
        if not use_ssl and ('strongerAuthRequired' in str(e) or _is_md4_error(str(e))):
            return _try_secure_connection(server, ntlm_user, username, password)
        return None, f"Erreur: {e}"


def get_user_role_from_groups(conn, username, debug=False):
    """Déterminer le rôle utilisateur selon ses groupes AD."""
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
            info['error'] = f'Utilisateur {search_user} non trouvé'
            return (config.DEFAULT_ROLE, info) if debug else config.DEFAULT_ROLE

        user_groups = []
        if hasattr(conn.entries[0], 'memberOf') and conn.entries[0].memberOf:
            for dn in conn.entries[0].memberOf.values:
                if str(dn).upper().startswith('CN='):
                    user_groups.append(str(dn).split(',')[0][3:])

        info['groups'] = user_groups
        groups_lower = [g.lower() for g in user_groups]

        for role, groups_cfg in [('admin', config.ADMIN_GROUPS),
                                  ('operator', config.OPERATOR_GROUPS),
                                  ('reader', config.READER_GROUPS)]:
            if any(g.lower() in groups_lower for g in groups_cfg if g):
                return (role, info) if debug else role

        return (config.DEFAULT_ROLE, info) if debug else config.DEFAULT_ROLE

    except Exception as e:
        info['error'] = str(e)
        return (config.DEFAULT_ROLE, info) if debug else config.DEFAULT_ROLE
