"""Routes gestion des comptes : corbeille AD, comptes verrouillés, comptes expirant."""
from datetime import datetime, timedelta
from flask import render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE

from . import tools_bp
from ..core import get_ad_connection, decode_ldap_value, is_connected, require_connection, require_permission


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
        base_dn = session.get('ad_base_dn', '')
        deleted_dn = f'CN=Deleted Objects,{base_dn}'
        conn.search(deleted_dn, '(isDeleted=TRUE)', SUBTREE,
                    attributes=['cn', 'distinguishedName', 'whenChanged', 'objectClass'],
                    controls=[('1.2.840.113556.1.4.417', True, None)])

        for entry in conn.entries:
            deleted_objects.append({
                'cn': decode_ldap_value(entry.cn),
                'dn': decode_ldap_value(entry.distinguishedName),
                'deleted': decode_ldap_value(entry.whenChanged),
                'type': 'user' if 'user' in (entry.objectClass.values or []) else 'other',
            })
        conn.unbind()
    except Exception as e:
        flash(f'Corbeille AD non disponible: {e}', 'warning')

    return render_template('recycle_bin.html', objects=deleted_objects, connected=is_connected())


@tools_bp.route('/recycle-bin/<path:dn>/restore', methods=['POST'])
@require_connection
@require_permission('admin')
def restore_deleted_object(dn):
    """Restaurer un objet supprimé (placeholder — nécessite corbeille AD activée)."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.recycle_bin'))
    try:
        flash("La restauration d'objets supprimés n'est pas encore implémentée.", 'warning')
    finally:
        conn.unbind()
    return redirect(url_for('tools.recycle_bin'))


# === COMPTES VERROUILLÉS ===

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
        conn.search(base_dn, '(&(objectClass=user)(lockoutTime>=1))', SUBTREE,
                    attributes=['cn', 'sAMAccountName', 'distinguishedName', 'lockoutTime'])
        for entry in conn.entries:
            locked.append({
                'cn': decode_ldap_value(entry.cn),
                'sAMAccountName': decode_ldap_value(entry.sAMAccountName),
                'dn': decode_ldap_value(entry.distinguishedName),
                'lockoutTime': decode_ldap_value(entry.lockoutTime),
            })
        conn.unbind()
    except Exception as e:
        flash(f'Erreur: {e}', 'error')

    return render_template('locked_accounts.html', accounts=locked, connected=is_connected())


@tools_bp.route('/locked-accounts/unlock', methods=['POST'])
@require_connection
@require_permission('admin')
def bulk_unlock_accounts():
    """Débloquer un ou plusieurs comptes utilisateurs."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.locked_accounts'))

    selected = request.form.getlist('selected_accounts')
    if not selected:
        flash('Aucun compte sélectionné.', 'warning')
        return redirect(url_for('tools.locked_accounts'))

    unlocked = failed = 0
    try:
        for dn in selected:
            try:
                conn.modify(dn, {'lockoutTime': [(0, [(0, b'\x00\x00\x00\x00\x00\x00\x00\x00')])]})
                if conn.result['result'] == 0:
                    unlocked += 1
                else:
                    failed += 1
            except Exception:
                failed += 1

        if unlocked:
            flash(f'{unlocked} compte(s) débloqué(s).', 'success')
        if failed:
            flash(f'{failed} échec(s) lors du déblocage.', 'warning')
    except Exception as e:
        flash(f'Erreur lors du déblocage: {e}', 'error')
    finally:
        conn.unbind()

    return redirect(url_for('tools.locked_accounts'))


# === COMPTES EXPIRANT ===

_AD_EPOCH_DELTA = 116444736000000000  # 100ns intervals between 1601-01-01 and 1970-01-01


def _safe_ad_date(entry, attr):
    """Convertit un attribut FILETIME AD en datetime, retourne None si invalide."""
    try:
        val = getattr(entry, attr, None)
        if val and val.value:
            v = val.value
            if isinstance(v, datetime):
                return v
            # FILETIME (int): 100-nanosecond intervals since 1601-01-01
            if isinstance(v, int) and v > 0:
                return datetime(1970, 1, 1) + timedelta(microseconds=(v - _AD_EPOCH_DELTA) // 10)
    except Exception:
        pass
    return None


@tools_bp.route('/expiring')
@require_connection
def expiring_accounts():
    """Comptes expirant bientôt."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    now = datetime.now()
    expiry_threshold = now + timedelta(days=30)
    password_threshold = now + timedelta(days=14)
    inactive_threshold = now - timedelta(days=90)

    expiring_accounts_list = []
    password_expiring_list = []
    inactive_accounts_list = []

    try:
        conn.search(base_dn, '(&(objectClass=user)(accountExpires>=1))', SUBTREE,
                    attributes=['cn', 'sAMAccountName', 'accountExpires',
                                'mail', 'distinguishedName', 'pwdLastSet', 'lastLogon'])

        for entry in conn.entries:
            data = {
                'cn': decode_ldap_value(entry.cn),
                'sAMAccountName': decode_ldap_value(entry.sAMAccountName),
                'mail': decode_ldap_value(entry.mail) if hasattr(entry, 'mail') else None,
                'dn': decode_ldap_value(entry.distinguishedName),
            }

            expiry = _safe_ad_date(entry, 'accountExpires')
            if expiry:
                data['accountExpires'] = expiry.strftime('%Y-%m-%d')
                if expiry <= expiry_threshold:
                    expiring_accounts_list.append(dict(data))

            pwd_date = _safe_ad_date(entry, 'pwdLastSet')
            if pwd_date and pwd_date <= password_threshold:
                data['pwdLastSet'] = pwd_date.strftime('%Y-%m-%d')
                password_expiring_list.append(dict(data))

            last_logon = _safe_ad_date(entry, 'lastLogon')
            data['lastLogon'] = last_logon.strftime('%Y-%m-%d') if last_logon else 'Jamais'
            if not last_logon or last_logon <= inactive_threshold:
                inactive_accounts_list.append(dict(data))

        conn.unbind()
    except Exception as e:
        flash(f'Erreur: {e}', 'error')

    return render_template('expiring_accounts.html',
                           expiring_accounts=expiring_accounts_list,
                           password_expiring=password_expiring_list,
                           inactive_accounts=inactive_accounts_list,
                           connected=is_connected())


@tools_bp.route('/expiring/export-pdf')
@require_connection
@require_permission('admin')
def export_expiring_pdf():
    """Export PDF des comptes expirants (placeholder)."""
    flash('Export PDF non implémenté.', 'info')
    return redirect(url_for('tools.expiring_accounts'))
