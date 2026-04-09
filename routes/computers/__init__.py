"""
Blueprint pour la gestion des ordinateurs.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException

from routes.core import (get_ad_connection, decode_ldap_value, is_connected,
                   require_connection, require_permission, config)
from core.security import escape_ldap_filter, validate_csrf_token
from core.audit import log_action, ACTIONS

computers_bp = Blueprint('computers', __name__, url_prefix='/computers')


def extract_ou_path(dn):
    """
    Extraire le chemin OU depuis un DN.
    Ex: CN=PC01,OU=Computers,OU=Paris,DC=company,DC=local → OU=Paris,OU=Computers
    """
    if not dn:
        return '-'
    
    parts = dn.split(',')
    ou_parts = [p for p in parts if p.strip().upper().startswith('OU=')]
    
    if ou_parts:
        # Inverser pour avoir du plus haut niveau au plus bas
        ou_parts.reverse()
        return ','.join(ou_parts)
    
    # Pas d'OU, retourner le premier composant
    return parts[0] if parts else '-'


def _first(value, default=''):
    """Extraire la première valeur d'un attribut paged_search (scalaire ou liste)."""
    if value is None:
        return default
    if isinstance(value, list):
        return value[0] if value else default
    return value if value != '' else default


@computers_bp.route('/')
@require_connection
def list_computers():
    """Liste des ordinateurs Active Directory."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('main.connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')
    ou_filter = request.args.get('ou', '')
    status_filter = request.args.get('status', 'all')   # all / active / disabled
    os_filter = request.args.get('os', '')
    page = request.args.get('page', 1, type=int)
    per_page = config.ITEMS_PER_PAGE

    search_base = ou_filter if ou_filter else base_dn

    if search_query:
        safe_query = escape_ldap_filter(search_query)
        search_filter = f'(&(objectClass=computer)(|(cn=*{safe_query}*)(description=*{safe_query}*)))'
    else:
        search_filter = '(objectClass=computer)'

    try:
        # Recherche paginée pour récupérer tous les ordinateurs (pas de limite 1000)
        attrs = ['cn', 'description', 'distinguishedName', 'operatingSystem',
                 'lastLogon', 'userAccountControl', 'dNSHostName', 'operatingSystemVersion']
        computer_list = []
        for entry in conn.extend.standard.paged_search(
                search_base, search_filter, SUBTREE,
                attributes=attrs, paged_size=500):
            if entry.get('type') != 'searchResEntry':
                continue
            a = entry.get('attributes', {})
            uac_val = a.get('userAccountControl') or 4096
            if isinstance(uac_val, list):
                uac_val = uac_val[0] if uac_val else 4096
            is_disabled = bool(int(uac_val) & 2)
            dn_str = entry.get('dn', '')
            computer_list.append({
                'cn': _first(a.get('cn')),
                'description': _first(a.get('description')),
                'dn': dn_str,
                'os': _first(a.get('operatingSystem')),
                'os_version': _first(a.get('operatingSystemVersion')),
                'dns_name': _first(a.get('dNSHostName')),
                'disabled': is_disabled,
                'ou_path': extract_ou_path(dn_str)
            })

        # Extraire les OS uniques avant filtrage (pour le dropdown)
        all_os = sorted(set(c['os'] for c in computer_list if c['os']))

        # Appliquer les filtres en mémoire
        if status_filter == 'active':
            computer_list = [c for c in computer_list if not c['disabled']]
        elif status_filter == 'disabled':
            computer_list = [c for c in computer_list if c['disabled']]
        if os_filter:
            computer_list = [c for c in computer_list if c['os'] == os_filter]

        # OUs pour le dropdown de filtre et le déplacement
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                    attributes=['name', 'distinguishedName'])
        ou_list = [{'name': decode_ldap_value(e.name), 'dn': decode_ldap_value(e.distinguishedName)}
                   for e in conn.entries]
        conn.unbind()

        # Pagination
        total = len(computer_list)
        total_pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        paginated = computer_list[start:start + per_page]

        return render_template('computers.html', computers=paginated, search=search_query,
                               page=page, total_pages=total_pages, total=total,
                               ous=ou_list, ou_filter=ou_filter,
                               status_filter=status_filter, os_filter=os_filter,
                               all_os=all_os, connected=is_connected())
    except Exception as e:
        try:
            conn.unbind()
        except Exception:
            pass
        flash(f'Erreur: {str(e)}', 'error')
        return render_template('computers.html', computers=[], search=search_query,
                               page=1, total_pages=1, total=0, ous=[],
                               ou_filter='', status_filter='all', os_filter='',
                               all_os=[], connected=is_connected())


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


@computers_bp.route('/<path:dn>/move', methods=['POST'])
@require_connection
@require_permission('write')
def move_computer(dn):
    """Déplacer un ordinateur vers une autre OU."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('computers.list_computers'))

    target_ou = request.form.get('new_ou')
    if not target_ou:
        flash('OU cible requise.', 'error')
        return redirect(url_for('computers.list_computers'))

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('computers.list_computers'))

    try:
        cn = dn.split(',')[0]
        conn.modify_dn(dn, cn, new_superior=target_ou)
        if conn.result['result'] == 0:
            flash('Ordinateur déplacé.', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
    finally:
        conn.unbind()

    return redirect(url_for('computers.list_computers'))
