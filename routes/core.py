"""
Fonctions core partagées entre tous les blueprints.
Gestion des autorisations granulaires par groupe AD.
"""

# IMPORTANT: OpenSSL MD4/NTLM init (DOIT ÊTRE LE PREMIER IMPORT)
import _openssl_init

import ssl
from functools import wraps
from flask import session, redirect, url_for, flash, g, current_app
from ldap3 import Server, Connection, ALL, SUBTREE, Tls, NTLM, SIMPLE, IP_V4_PREFERRED
from ldap3.core.exceptions import LDAPException
from config import get_config
from security import escape_ldap_filter
from session_crypto import decrypt_password
from granular_permissions import has_permission as has_granular_permission
import logging

logger = logging.getLogger('ad_core')
config = get_config()

# Permissions par rôle (système legacy - pour rétrocompatibilité)
ROLE_PERMISSIONS = {
    'admin': ['read', 'write', 'delete', 'admin'],
    'operator': ['read', 'write'],
    'reader': ['read']
}

# Groupes AD spécifiques par permission (configurable)
# Format: 'permission': ['CN=Group1,OU=...', 'CN=Group2,OU=...']
AD_GROUP_PERMISSIONS = {
    'read': [],  # Tous les utilisateurs connectés
    'write': [],  # Opérateurs + Admins
    'delete': [],  # Admins uniquement
    'admin': [],  # Admins uniquement
    'audit_logs': [],  # Groupe spécifique pour voir les logs d'audit
    'password_reset': [],  # Groupe spécifique pour réinitialiser les MDP
    'user_create': [],  # Groupe spécifique pour créer des utilisateurs
    'user_delete': [],  # Groupe spécifique pour supprimer des utilisateurs
    'group_modify': [],  # Groupe spécifique pour modifier les groupes
    'backup_restore': [],  # Groupe spécifique pour restaurer les backups
    'debug_access': [],  # Groupe spécifique pour le debug
}

# Configuration TLS sécurisée
_tls_config = Tls(
    validate=ssl.CERT_NONE,
    version=ssl.PROTOCOL_TLS,
    ciphers='HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA'
)


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
    """Decorateur pour verifier les permissions RBAC granulaires."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if config.RBAC_ENABLED:
                # Vérifier d'abord avec le système granulaire
                user_groups = session.get('user_groups', [])
                
                if user_groups and has_granular_permission(user_groups, permission):
                    return f(*args, **kwargs)
                
                # Fallback sur l'ancien système par rôle
                user_role = session.get('user_role', config.DEFAULT_ROLE)
                if permission not in ROLE_PERMISSIONS.get(user_role, []):
                    flash('Permission refusee.', 'error')
                    return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated
    return decorator


# === Helpers pour connexion AD ===

def _extract_username(username):
    """Extraire le nom d'utilisateur simple."""
    return username.split('\\')[-1].split('@')[0]


def _extract_domain(server, username):
    """Extraire le domaine depuis le serveur ou username."""
    if '@' in username:
        return username.split('@')[1].split('.')[0].upper()
    if server and '.' in server:
        return server.split('.')[0].upper()
    base_dn = session.get('ad_base_dn', '')
    if base_dn:
        dc_parts = [p.split('=')[1] for p in base_dn.upper().split(',') if p.startswith('DC=')]
        if dc_parts:
            return dc_parts[0]
    return None


def _get_upn_user(server, username):
    """Construire le format UPN (user@domain)."""
    if '@' in username:
        return username
    simple_user = _extract_username(username)
    return f"{simple_user}@{server.split('.', 1)[1]}" if '.' in server else simple_user


def _get_ntlm_user(server, username):
    """Construire le format NTLM (DOMAIN\\user)."""
    if '\\' in username:
        return username
    domain = _extract_domain(server, username)
    return f"{domain}\\{_extract_username(username)}" if domain else _extract_username(username)


def _is_md4_error(error_msg):
    """Vérifier si l'erreur est liée à MD4."""
    return 'MD4' in str(error_msg) or 'unsupported hash' in str(error_msg)


def _is_invalid_credentials_error(error_msg):
    """Vérifier si l'erreur indique des identifiants incorrects (LDAP code 49)."""
    msg = str(error_msg).lower()
    return 'invalidcredentials' in msg or 'error 49' in msg or '80090308' in msg


def _make_server(server, port, use_ssl, ip_mode=IP_V4_PREFERRED):
    """Créer un objet Server ldap3 avec le mode IP donné."""
    return Server(server, port=port, use_ssl=use_ssl,
                  tls=_tls_config if use_ssl else None,
                  get_info=ALL, mode=ip_mode,
                  connect_timeout=5,  # Timeout de connexion (secondes)
                  allowed_referral_hosts=[('*')])  # Autoriser les referrals


def _try_connection(server, username, password):
    """Essayer différentes méthodes de connexion AD."""
    errors = []
    ntlm_user = _get_ntlm_user(server, username)
    upn_user = _get_upn_user(server, username)
    
    # Méthodes: (port, ssl, user, auth, label, starttls)
    methods = [
        (389, False, ntlm_user, NTLM, "NTLM", False),
        (389, False, upn_user, SIMPLE, "STARTTLS", True),
        (636, True, upn_user, SIMPLE, "LDAPS", False),
    ]

    for port, use_ssl, user, auth, label, starttls in methods:
        try:
            srv = _make_server(server, port, use_ssl)
            conn = Connection(srv, user=user, password=password, authentication=auth, auto_bind=False)
            
            if starttls:
                conn.open()
                conn.start_tls(_tls_config)
            
            if conn.bind():
                session['ad_use_ssl'] = use_ssl
                session['ad_port'] = port
                return conn, None
                
        except Exception as e:
            err_str = str(e)
            if _is_invalid_credentials_error(err_str):
                return None, f"{label}: identifiants incorrects"
            
            # IPv6 non supporté → réessayer en IPv4
            if 'WinError 1' in err_str:
                try:
                    srv = _make_server(server, port, use_ssl, IP_V4_PREFERRED)
                    conn = Connection(srv, user=user, password=password, authentication=auth, auto_bind=False)
                    if starttls:
                        conn.open()
                        conn.start_tls(_tls_config)
                    if conn.bind():
                        session['ad_use_ssl'] = use_ssl
                        session['ad_port'] = port
                        return conn, None
                except Exception as e2:
                    err_str = str(e2)
            
            errors.append(f"{label}: {err_str[:80]}")
            if label == "NTLM" and _is_md4_error(err_str):
                continue  # Essayer STARTTLS

    return None, '; '.join(errors)


def get_ad_connection(server=None, username=None, password=None, use_ssl=False, port=None):
    """Créer une connexion à Active Directory avec gestion des erreurs améliorée."""
    import logging
    logger = logging.getLogger('ad_connection')
    
    # Récupérer depuis la session
    server = server or session.get('ad_server')
    username = username or session.get('ad_username')
    if password is None:
        encrypted = session.get('ad_password')
        if encrypted:
            try:
                password = decrypt_password(encrypted)
            except ValueError:
                logger.warning("Session invalide - décryptage échoué")
                return None, "Session invalide"
    use_ssl = use_ssl or session.get('ad_use_ssl', False)
    port = port or session.get('ad_port') or (636 if use_ssl else 389)

    if not all([server, username, password]):
        return None, "Non connecté"

    # Connexion directe si port/SSL spécifiés
    if port != 389 or use_ssl:
        try:
            srv = _make_server(server, port, use_ssl)
            user = _get_upn_user(server, username) if use_ssl else _get_ntlm_user(server, username)
            conn = Connection(srv, user=user, password=password,
                            authentication=SIMPLE if use_ssl else NTLM, 
                            auto_bind=True,
                            receive_timeout=10)  # Timeout de réception
            if conn.bound:
                logger.info(f"Connexion réussie: {server}:{port} (SSL={use_ssl})")
                return conn, None
        except Exception as e:
            error_msg = str(e)
            if not _is_md4_error(error_msg):
                logger.warning(f"Connexion directe échouée: {error_msg[:100]}")
                return None, error_msg

    # Essayer toutes les méthodes
    conn, errors = _try_connection(server, username, password)
    if conn:
        logger.info(f"Connexion réussie (méthode automatique): {server}")
        return conn, None

    hint = " [MD4: executez fix_md4.ps1 pour activer le support NTLM]" if _is_md4_error(errors) else ""
    logger.error(f"Connexion échouée: {errors[:200]}")
    return None, f"Connexion impossible.{hint} Verifiez: 1) serveur AD, 2) ports 389/636, 3) identifiants\n{errors}"


def get_user_role_from_groups(conn, username, debug=False):
    """Déterminer le rôle utilisateur selon ses groupes AD."""
    import logging
    logger = logging.getLogger('ad_role')
    
    info = {'groups': [], 'error': None}

    if not config.RBAC_ENABLED:
        return (config.DEFAULT_ROLE, info) if debug else config.DEFAULT_ROLE

    try:
        base_dn = session.get('ad_base_dn', '')
        if not base_dn and conn.server.info and conn.server.info.naming_contexts:
            base_dn = str(conn.server.info.naming_contexts[0])

        search_user = _extract_username(username)
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
        logger.error(f"Erreur détermination rôle: {str(e)[:100]}")
        info['error'] = str(e)
        return (config.DEFAULT_ROLE, info) if debug else config.DEFAULT_ROLE


def ldap_search_with_retry(conn, base_dn, search_filter, attributes=None,
                           max_retries=2, timeout=10):
    """
    Effectuer une recherche LDAP avec retry automatique.

    Args:
        conn: Connexion LDAP
        base_dn: Base DN pour la recherche
        search_filter: Filtre de recherche
        attributes: Liste des attributs à récupérer
        max_retries: Nombre maximum de tentatives
        timeout: Timeout en secondes

    Returns:
        list: Résultats de la recherche ou liste vide en cas d'erreur
    """
    import logging
    logger = logging.getLogger('ldap_search')

    if attributes is None:
        attributes = ['*']

    for attempt in range(max_retries):
        try:
            conn.search(base_dn, search_filter, SUBTREE,
                       attributes=attributes,
                       get_operational_attributes=False,
                       time_limit=timeout)

            if conn.entries:
                return list(conn.entries)
            return []

        except Exception as e:
            logger.warning(f"LDAP search attempt {attempt + 1}/{max_retries} failed: {str(e)[:100]}")
            if attempt == max_retries - 1:
                logger.error(f"LDAP search failed after {max_retries} attempts")
                return []

    return []


def get_user_permissions(conn, username):
    """
    Obtenir les permissions granulaires de l'utilisateur basées sur ses groupes AD.

    Args:
        conn: Connexion LDAP
        username: Nom d'utilisateur

    Returns:
        dict: Permissions de l'utilisateur
    """
    user_role = session.get('user_role', config.DEFAULT_ROLE)
    base_permissions = ROLE_PERMISSIONS.get(user_role, [])

    permissions = {
        'role': user_role,
        'base': base_permissions,
        'granular': {},
        'groups': []
    }

    try:
        base_dn = session.get('ad_base_dn', '')
        if not base_dn and conn.server.info and conn.server.info.naming_contexts:
            base_dn = str(conn.server.info.naming_contexts[0])

        search_user = _extract_username(username)
        conn.search(base_dn, f'(sAMAccountName={escape_ldap_filter(search_user)})',
                    SUBTREE, attributes=['memberOf', 'cn', 'displayName'])

        if conn.entries:
            entry = conn.entries[0]
            user_groups = []

            if hasattr(entry, 'memberOf') and entry.memberOf:
                for dn in entry.memberOf.values:
                    dn_str = str(dn)
                    if dn_str.upper().startswith('CN='):
                        cn = dn_str.split(',')[0][3:]
                        user_groups.append(cn)
                        permissions['groups'].append(cn)

            # Vérifier les permissions granulaires par groupe
            for perm, allowed_groups in AD_GROUP_PERMISSIONS.items():
                if allowed_groups:
                    # Si des groupes sont configurés pour cette permission
                    has_access = any(g in user_groups for g in allowed_groups)
                    permissions['granular'][perm] = has_access
                else:
                    # Sinon, utiliser les permissions de base du rôle
                    permissions['granular'][perm] = perm in base_permissions

    except Exception as e:
        logger.warning(f"Error getting user permissions: {str(e)[:100]}")
        # En cas d'erreur, utiliser les permissions de base
        for perm in AD_GROUP_PERMISSIONS.keys():
            permissions['granular'][perm] = perm in base_permissions

    return permissions


def has_permission(permission):
    """
    Vérifier si l'utilisateur actuel a une permission spécifique.

    Args:
        permission: Nom de la permission à vérifier

    Returns:
        bool: True si l'utilisateur a la permission
    """
    if not config.RBAC_ENABLED:
        return True

    user_role = session.get('user_role', config.DEFAULT_ROLE)

    # Vérifier les permissions de base du rôle
    if permission in ROLE_PERMISSIONS.get(user_role, []):
        return True

    # Vérifier les permissions granulaires si disponibles en session
    user_permissions = session.get('user_permissions', {})
    return user_permissions.get('granular', {}).get(permission, False)


def require_permission(permission):
    """
    Décorateur pour vérifier les permissions granulaires.

    Args:
        permission: Permission requise pour accéder à la route
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if config.RBAC_ENABLED:
                if not has_permission(permission):
                    user_role = session.get('user_role', config.DEFAULT_ROLE)
                    flash(f'Permission refusée. Rôle requis: {permission}', 'error')

                    # Rediriger selon le rôle
                    if user_role == 'admin':
                        return redirect(url_for('admin.admin_page'))
                    elif user_role == 'operator':
                        return redirect(url_for('dashboard'))
                    else:
                        return redirect(url_for('index'))

            return f(*args, **kwargs)
        return decorated
    return decorator
