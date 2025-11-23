"""
Blueprint pour les outils (LAPS, BitLocker, Corbeille, etc.).
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE
from ldap3.core.exceptions import LDAPException

from .core import (get_ad_connection, decode_ldap_value, is_connected,
                   require_connection, require_permission, config)
from security import escape_ldap_filter

tools_bp = Blueprint('tools', __name__)


# === LAPS ===
@tools_bp.route('/laps')
@require_connection
@require_permission('admin')
def laps_passwords():
    """Afficher les mots de passe LAPS."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')

    if search_query:
        safe_query = escape_ldap_filter(search_query)
        search_filter = f'(&(objectClass=computer)(cn=*{safe_query}*))'
    else:
        search_filter = '(objectClass=computer)'

    computers = []
    try:
        # Essayer les attributs LAPS (ancien et nouveau)
        conn.search(base_dn, search_filter, SUBTREE,
                   attributes=['cn', 'distinguishedName', 'ms-Mcs-AdmPwd',
                              'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-Password',
                              'msLAPS-PasswordExpirationTime'])

        for entry in conn.entries:
            pwd = None
            exp = None
            # Ancien LAPS
            if hasattr(entry, 'ms-Mcs-AdmPwd'):
                pwd = decode_ldap_value(getattr(entry, 'ms-Mcs-AdmPwd', None))
                exp = decode_ldap_value(getattr(entry, 'ms-Mcs-AdmPwdExpirationTime', None))
            # Nouveau LAPS
            if not pwd and hasattr(entry, 'msLAPS-Password'):
                pwd = decode_ldap_value(getattr(entry, 'msLAPS-Password', None))
                exp = decode_ldap_value(getattr(entry, 'msLAPS-PasswordExpirationTime', None))

            if pwd:
                computers.append({
                    'cn': decode_ldap_value(entry.cn),
                    'dn': decode_ldap_value(entry.distinguishedName),
                    'password': pwd,
                    'expiration': exp
                })
        conn.unbind()
    except Exception as e:
        flash(f'Erreur LAPS: {str(e)}', 'error')

    return render_template('laps.html', computers=computers, search=search_query,
                         connected=is_connected())


# === BITLOCKER ===
@tools_bp.route('/bitlocker')
@require_connection
@require_permission('admin')
def bitlocker_keys():
    """Afficher les clés de récupération BitLocker."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')
    keys = []

    try:
        # Chercher les objets BitLocker
        if search_query:
            safe_query = escape_ldap_filter(search_query)
            search_filter = f'(&(objectClass=msFVE-RecoveryInformation)(cn=*{safe_query}*))'
        else:
            search_filter = '(objectClass=msFVE-RecoveryInformation)'

        conn.search(base_dn, search_filter, SUBTREE,
                   attributes=['cn', 'distinguishedName', 'msFVE-RecoveryPassword',
                              'msFVE-VolumeGuid', 'whenCreated'])

        for entry in conn.entries:
            # Extraire le nom de l'ordinateur du DN
            dn = decode_ldap_value(entry.distinguishedName)
            computer_name = ''
            parts = dn.split(',')
            for p in parts:
                if p.upper().startswith('CN=') and not p.startswith('CN={'):
                    computer_name = p[3:]
                    break

            keys.append({
                'computer': computer_name,
                'dn': dn,
                'recovery_password': decode_ldap_value(getattr(entry, 'msFVE-RecoveryPassword', '')),
                'volume_guid': decode_ldap_value(getattr(entry, 'msFVE-VolumeGuid', '')),
                'created': decode_ldap_value(entry.whenCreated)
            })
        conn.unbind()
    except Exception as e:
        flash(f'Erreur BitLocker: {str(e)}', 'error')

    return render_template('bitlocker.html', keys=keys, search=search_query,
                         connected=is_connected())


# === CORBEILLE AD ===
@tools_bp.route('/recycle-bin')
@require_connection
@require_permission('admin')
def recycle_bin():
    """Afficher la corbeille AD."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    deleted_objects = []
    try:
        # Chercher dans le conteneur Deleted Objects
        base_dn = session.get('ad_base_dn', '')
        deleted_dn = f'CN=Deleted Objects,{base_dn}'

        conn.search(deleted_dn, '(isDeleted=TRUE)', SUBTREE,
                   attributes=['cn', 'distinguishedName', 'whenChanged', 'objectClass'],
                   controls=[('1.2.840.113556.1.4.417', True, None)])  # Show deleted

        for entry in conn.entries:
            deleted_objects.append({
                'cn': decode_ldap_value(entry.cn),
                'dn': decode_ldap_value(entry.distinguishedName),
                'deleted': decode_ldap_value(entry.whenChanged),
                'type': 'user' if 'user' in (entry.objectClass.values or []) else 'other'
            })
        conn.unbind()
    except Exception as e:
        flash(f'Corbeille AD non disponible: {str(e)}', 'warning')

    return render_template('recycle_bin.html', objects=deleted_objects,
                         connected=is_connected())


# === COMPTES VERROUILLES ===
@tools_bp.route('/locked-accounts')
@require_connection
def locked_accounts():
    """Afficher les comptes verrouillés."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    locked = []

    try:
        # Chercher les comptes verrouillés (lockoutTime > 0)
        conn.search(base_dn, '(&(objectClass=user)(lockoutTime>=1))', SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'distinguishedName', 'lockoutTime'])

        for entry in conn.entries:
            locked.append({
                'cn': decode_ldap_value(entry.cn),
                'sAMAccountName': decode_ldap_value(entry.sAMAccountName),
                'dn': decode_ldap_value(entry.distinguishedName),
                'lockoutTime': decode_ldap_value(entry.lockoutTime)
            })
        conn.unbind()
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')

    return render_template('locked_accounts.html', accounts=locked,
                         connected=is_connected())


# === MODELES UTILISATEURS ===
@tools_bp.route('/templates')
@require_connection
def user_templates():
    """Gestion des modèles utilisateurs."""
    flash('Fonctionnalité modèles disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))


# === FAVORIS ===
@tools_bp.route('/favorites')
@require_connection
def favorites():
    """Gestion des favoris."""
    flash('Fonctionnalité favoris disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))


# === COMPTES EXPIRANT ===
@tools_bp.route('/expiring')
@require_connection
def expiring_accounts():
    """Comptes expirant bientôt."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    expiring = []

    try:
        # Chercher les comptes avec une date d'expiration
        conn.search(base_dn, '(&(objectClass=user)(accountExpires>=1))', SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'accountExpires'])

        for entry in conn.entries:
            expiring.append({
                'cn': decode_ldap_value(entry.cn),
                'sAMAccountName': decode_ldap_value(entry.sAMAccountName),
                'accountExpires': decode_ldap_value(entry.accountExpires)
            })
        conn.unbind()
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')

    return render_template('expiring_accounts.html', accounts=expiring,
                         connected=is_connected())


# === ALERTES ===
@tools_bp.route('/alerts')
@require_connection
def alerts():
    """Gestion des alertes."""
    flash('Fonctionnalité alertes disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))


# === DOCUMENTATION API ===
@tools_bp.route('/api-docs')
@require_connection
@require_permission('admin')
def api_documentation():
    """Documentation de l'API."""
    flash('Documentation API disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))


# === POLITIQUE DE MOTS DE PASSE ===
@tools_bp.route('/password-policy')
@require_connection
def password_policy():
    """Afficher la politique de mots de passe du domaine."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    policy = {}

    try:
        # Lire la politique de mot de passe par défaut du domaine
        conn.search(base_dn, '(objectClass=domain)', 'BASE',
                   attributes=['minPwdLength', 'pwdHistoryLength', 'maxPwdAge',
                              'minPwdAge', 'lockoutThreshold', 'lockoutDuration',
                              'lockoutObservationWindow', 'pwdProperties'])

        if conn.entries:
            entry = conn.entries[0]

            # Conversion des valeurs
            def get_value(attr):
                if hasattr(entry, attr) and getattr(entry, attr).value is not None:
                    return getattr(entry, attr).value
                return None

            policy = {
                'minPwdLength': get_value('minPwdLength') or 0,
                'pwdHistoryLength': get_value('pwdHistoryLength') or 0,
                'maxPwdAge': get_value('maxPwdAge'),
                'minPwdAge': get_value('minPwdAge'),
                'lockoutThreshold': get_value('lockoutThreshold') or 0,
                'lockoutDuration': get_value('lockoutDuration'),
                'lockoutObservationWindow': get_value('lockoutObservationWindow'),
                'pwdProperties': get_value('pwdProperties') or 0
            }

            # Convertir les durées (format Windows: -valeur * 100ns)
            def convert_duration(val):
                if val is None or val == 0:
                    return "Non défini"
                # Valeur négative en intervalles de 100ns
                seconds = abs(int(val)) / 10000000
                if seconds < 60:
                    return f"{int(seconds)} secondes"
                elif seconds < 3600:
                    return f"{int(seconds/60)} minutes"
                elif seconds < 86400:
                    return f"{int(seconds/3600)} heures"
                else:
                    return f"{int(seconds/86400)} jours"

            policy['maxPwdAge_display'] = convert_duration(policy['maxPwdAge'])
            policy['minPwdAge_display'] = convert_duration(policy['minPwdAge'])
            policy['lockoutDuration_display'] = convert_duration(policy['lockoutDuration'])
            policy['lockoutObservationWindow_display'] = convert_duration(policy['lockoutObservationWindow'])

            # Propriétés du mot de passe
            pwd_props = int(policy['pwdProperties'])
            policy['complexity_enabled'] = bool(pwd_props & 1)
            policy['reversible_encryption'] = bool(pwd_props & 16)

        conn.unbind()
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')

    return render_template('password_policy.html', policy=policy, connected=is_connected())
