"""
Blueprint pour la gestion des ordinateurs.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException

from .core import (get_ad_connection, decode_ldap_value, is_connected,
                   require_connection, require_permission, config)
from security import escape_ldap_filter, validate_csrf_token
from audit import log_action, ACTIONS

computers_bp = Blueprint('computers', __name__, url_prefix='/computers')


@computers_bp.route('/')
@require_connection
def list_computers():
    """Liste des ordinateurs Active Directory."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = config.ITEMS_PER_PAGE

    if search_query:
        safe_query = escape_ldap_filter(search_query)
        search_filter = f'(&(objectClass=computer)(|(cn=*{safe_query}*)(description=*{safe_query}*)))'
    else:
        search_filter = '(objectClass=computer)'

    try:
        conn.search(base_dn, search_filter, SUBTREE,
                   attributes=['cn', 'description', 'distinguishedName',
                              'operatingSystem', 'lastLogon', 'userAccountControl'])

        computer_list = []
        for entry in conn.entries:
            uac = entry.userAccountControl.value if hasattr(entry, 'userAccountControl') and entry.userAccountControl else 4096
            is_disabled = bool(int(uac) & 2) if uac else False
            computer_list.append({
                'cn': decode_ldap_value(entry.cn),
                'description': decode_ldap_value(entry.description),
                'dn': decode_ldap_value(entry.distinguishedName),
                'os': decode_ldap_value(entry.operatingSystem),
                'disabled': is_disabled
            })
        conn.unbind()

        # Pagination
        total = len(computer_list)
        total_pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        paginated = computer_list[start:start + per_page]

        return render_template('computers.html', computers=paginated, search=search_query,
                             page=page, total_pages=total_pages, total=total,
                             connected=is_connected())
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
        return render_template('computers.html', computers=[], search=search_query,
                             page=1, total_pages=1, total=0, connected=is_connected())


@computers_bp.route('/<path:dn>/toggle', methods=['POST'])
@require_connection
@require_permission('write')
def toggle_computer(dn):
    """Activer/désactiver un ordinateur."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('computers.list_computers'))

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('computers.list_computers'))

    try:
        conn.search(dn, '(objectClass=*)', 'BASE', attributes=['userAccountControl'])
        if conn.entries:
            uac = int(conn.entries[0].userAccountControl.value or 4096)
            if uac & 2:
                new_uac = uac & ~2  # Activer
                msg = 'Ordinateur activé.'
            else:
                new_uac = uac | 2  # Désactiver
                msg = 'Ordinateur désactivé.'

            conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
            if conn.result['result'] == 0:
                flash(msg, 'success')
            else:
                flash(f'Erreur: {conn.result["description"]}', 'error')
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
    finally:
        conn.unbind()

    return redirect(url_for('computers.list_computers'))


@computers_bp.route('/<path:dn>/delete', methods=['POST'])
@require_connection
@require_permission('delete')
def delete_computer(dn):
    """Supprimer un ordinateur."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('computers.list_computers'))

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('computers.list_computers'))

    try:
        conn.delete(dn)
        if conn.result['result'] == 0:
            flash('Ordinateur supprimé.', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
    finally:
        conn.unbind()

    return redirect(url_for('computers.list_computers'))
