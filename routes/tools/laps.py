"""Routes LAPS (Local Administrator Password Solution)."""
from flask import render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPAttributeError

from . import tools_bp
from ..core import get_ad_connection, decode_ldap_value, is_connected, require_connection, require_permission
from security import escape_ldap_filter


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
    search_filter = f'(&(objectClass=computer)(cn=*{escape_ldap_filter(search_query)}*))' if search_query else '(objectClass=computer)'

    computers = []
    laps_available = True

    try:
        conn.search(base_dn, '(objectClass=computer)', SUBTREE,
                    attributes=['objectClass'],
                    get_operational_attributes=True)

        schema_attrs = conn.server.schema.attribute_types if conn.server.schema else []
        has_legacy_laps = 'ms-Mcs-AdmPwd' in schema_attrs
        has_new_laps = 'msLAPS-Password' in schema_attrs

        if not has_legacy_laps and not has_new_laps:
            laps_available = False
            flash("LAPS n'est pas installé sur ce domaine.", 'warning')
        else:
            attrs = ['cn', 'distinguishedName', 'operatingSystem']
            if has_legacy_laps:
                attrs.extend(['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'])
            if has_new_laps:
                attrs.extend(['msLAPS-Password', 'msLAPS-PasswordExpirationTime'])

            conn.search(base_dn, search_filter, SUBTREE, attributes=attrs)

            for entry in conn.entries:
                pwd = exp = None
                laps_type = 'Aucun'

                if has_legacy_laps and hasattr(entry, 'ms-Mcs-AdmPwd'):
                    pwd_val = getattr(entry, 'ms-Mcs-AdmPwd', None)
                    if pwd_val and pwd_val.value:
                        pwd = decode_ldap_value(pwd_val)
                        laps_type = 'LAPS (Legacy)'
                        exp_val = getattr(entry, 'ms-Mcs-AdmPwdExpirationTime', None)
                        exp = decode_ldap_value(exp_val) if exp_val else None

                if not pwd and has_new_laps and hasattr(entry, 'msLAPS-Password'):
                    pwd_val = getattr(entry, 'msLAPS-Password', None)
                    if pwd_val and pwd_val.value:
                        pwd = decode_ldap_value(pwd_val)
                        laps_type = 'Windows LAPS'
                        exp_val = getattr(entry, 'msLAPS-PasswordExpirationTime', None)
                        exp = decode_ldap_value(exp_val) if exp_val else None

                if pwd:
                    computers.append({
                        'cn': decode_ldap_value(entry.cn),
                        'os': decode_ldap_value(getattr(entry, 'operatingSystem', None)) or 'Inconnu',
                        'dn': decode_ldap_value(entry.distinguishedName),
                        'laps_type': laps_type,
                        'laps_password': pwd,
                        'laps_expiration': exp or 'Inconnue',
                    })

    except LDAPAttributeError as e:
        laps_available = False
        flash(f"LAPS n'est pas installé: {e}", 'warning')
    except Exception as e:
        flash(f'Erreur LAPS: {e}', 'error')
    finally:
        conn.unbind()

    return render_template('laps.html', computers=computers, search=search_query,
                           connected=is_connected(), laps_available=laps_available)
