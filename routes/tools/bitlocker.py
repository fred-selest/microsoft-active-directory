"""Routes BitLocker (clés de récupération)."""
from flask import render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE

from . import tools_bp
from ..core import get_ad_connection, decode_ldap_value, is_connected, require_connection, require_permission
from security import escape_ldap_filter


@tools_bp.route('/bitlocker')
@require_connection
@require_permission('admin')
def bitlocker_keys():
    """Afficher les clés de récupération BitLocker."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('main.connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')
    keys = []

    try:
        if search_query:
            safe_query = escape_ldap_filter(search_query)
            search_filter = f'(&(objectClass=msFVE-RecoveryInformation)(cn=*{safe_query}*))'
        else:
            search_filter = '(objectClass=msFVE-RecoveryInformation)'

        conn.search(base_dn, search_filter, SUBTREE,
                    attributes=['cn', 'distinguishedName', 'msFVE-RecoveryPassword',
                                'msFVE-VolumeGuid', 'whenCreated'])

        for entry in conn.entries:
            dn = decode_ldap_value(entry.distinguishedName)
            computer_name = next(
                (p[3:] for p in dn.split(',') if p.upper().startswith('CN=') and not p.startswith('CN={')),
                ''
            )
            keys.append({
                'computer': computer_name,
                'dn': dn,
                'recovery_password': decode_ldap_value(getattr(entry, 'msFVE-RecoveryPassword', '')),
                'volume_guid': decode_ldap_value(getattr(entry, 'msFVE-VolumeGuid', '')),
                'created': decode_ldap_value(entry.whenCreated),
            })
        conn.unbind()
    except Exception as e:
        flash(f'Erreur BitLocker: {e}', 'error')

    return render_template('bitlocker.html', keys=keys, search=search_query,
                           connected=is_connected())
