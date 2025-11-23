"""
Blueprint pour la gestion des groupes.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, MODIFY_ADD, MODIFY_DELETE
from ldap3.core.exceptions import LDAPException

from .core import (get_ad_connection, decode_ldap_value, is_connected,
                   require_connection, require_permission, config)
from security import escape_ldap_filter, validate_csrf_token
from audit import log_action, ACTIONS

groups_bp = Blueprint('groups', __name__, url_prefix='/groups')


@groups_bp.route('/')
@require_connection
def list_groups():
    """Liste des groupes Active Directory."""
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
        search_filter = f'(&(objectClass=group)(|(cn=*{safe_query}*)(description=*{safe_query}*)))'
    else:
        search_filter = '(objectClass=group)'

    try:
        conn.search(base_dn, search_filter, SUBTREE,
                   attributes=['cn', 'description', 'distinguishedName', 'member', 'groupType'])

        group_list = []
        for entry in conn.entries:
            members = entry.member.values if hasattr(entry, 'member') and entry.member else []
            group_list.append({
                'cn': decode_ldap_value(entry.cn),
                'description': decode_ldap_value(entry.description),
                'dn': decode_ldap_value(entry.distinguishedName),
                'member_count': len(members)
            })
        conn.unbind()

        # Pagination
        total = len(group_list)
        total_pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        paginated = group_list[start:start + per_page]

        return render_template('groups.html', groups=paginated, search=search_query,
                             page=page, total_pages=total_pages, total=total,
                             connected=is_connected())
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
        return render_template('groups.html', groups=[], search=search_query,
                             page=1, total_pages=1, total=0, connected=is_connected())


@groups_bp.route('/<path:dn>')
@require_connection
def view_group(dn):
    """Voir les détails d'un groupe."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('groups.list_groups'))

    try:
        conn.search(dn, '(objectClass=*)', 'BASE',
                   attributes=['cn', 'description', 'member', 'managedBy', 'groupType'])

        if not conn.entries:
            flash('Groupe non trouvé.', 'error')
            return redirect(url_for('groups.list_groups'))

        entry = conn.entries[0]
        members = []
        if hasattr(entry, 'member') and entry.member:
            for member_dn in entry.member.values:
                conn.search(str(member_dn), '(objectClass=*)', 'BASE',
                           attributes=['cn', 'sAMAccountName', 'objectClass'])
                if conn.entries:
                    m = conn.entries[0]
                    obj_class = m.objectClass.values if hasattr(m, 'objectClass') else []
                    members.append({
                        'cn': decode_ldap_value(m.cn),
                        'dn': str(member_dn),
                        'type': 'user' if 'user' in obj_class else 'group'
                    })

        group = {
            'cn': decode_ldap_value(entry.cn),
            'description': decode_ldap_value(entry.description),
            'dn': dn,
            'members': members
        }
        conn.unbind()

        return render_template('group_detail.html', group=group, connected=is_connected())
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
        return redirect(url_for('groups.list_groups'))


@groups_bp.route('/<path:dn>/add-member', methods=['POST'])
@require_connection
@require_permission('write')
def add_member(dn):
    """Ajouter un membre à un groupe."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('groups.view_group', dn=dn))

    member_dn = request.form.get('member_dn')
    if not member_dn:
        flash('Membre requis.', 'error')
        return redirect(url_for('groups.view_group', dn=dn))

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('groups.view_group', dn=dn))

    try:
        conn.modify(dn, {'member': [(MODIFY_ADD, [member_dn])]})
        if conn.result['result'] == 0:
            flash('Membre ajouté.', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
    finally:
        conn.unbind()

    return redirect(url_for('groups.view_group', dn=dn))


@groups_bp.route('/<path:dn>/remove-member', methods=['POST'])
@require_connection
@require_permission('write')
def remove_member(dn):
    """Retirer un membre d'un groupe."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('groups.view_group', dn=dn))

    member_dn = request.form.get('member_dn')
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('groups.view_group', dn=dn))

    try:
        conn.modify(dn, {'member': [(MODIFY_DELETE, [member_dn])]})
        if conn.result['result'] == 0:
            flash('Membre retiré.', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
    finally:
        conn.unbind()

    return redirect(url_for('groups.view_group', dn=dn))


@groups_bp.route('/<path:dn>/delete', methods=['POST'])
@require_connection
@require_permission('delete')
def delete_group(dn):
    """Supprimer un groupe."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('groups.list_groups'))

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('groups.list_groups'))

    try:
        conn.delete(dn)
        if conn.result['result'] == 0:
            log_action(ACTIONS.get('DELETE_GROUP', 'delete_group'), session.get('ad_username'),
                      {'dn': dn}, True, request.remote_addr)
            flash('Groupe supprimé.', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
    finally:
        conn.unbind()

    return redirect(url_for('groups.list_groups'))


@groups_bp.route('/create', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def create_group():
    """Créer un nouveau groupe."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('groups.list_groups'))

    base_dn = session.get('ad_base_dn', '')

    # Récupérer les OUs pour le formulaire
    try:
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'distinguishedName'])
        ou_list = [{'name': decode_ldap_value(e.name), 'dn': decode_ldap_value(e.distinguishedName)}
                   for e in conn.entries]
    except:
        ou_list = []

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token CSRF invalide.', 'error')
            return render_template('create_group.html', ous=ou_list, connected=is_connected())

        group_name = request.form.get('group_name', '').strip()
        description = request.form.get('description', '').strip()
        target_ou = request.form.get('target_ou', base_dn)
        group_scope = request.form.get('group_scope', 'global')

        if not group_name:
            flash('Nom du groupe requis.', 'error')
            return render_template('create_group.html', ous=ou_list, connected=is_connected())

        group_dn = f"CN={group_name},{target_ou}"

        # Calcul du groupType selon le scope
        # Global=-2147483646, DomainLocal=-2147483644, Universal=-2147483640
        group_types = {
            'global': -2147483646,
            'domainlocal': -2147483644,
            'universal': -2147483640
        }
        group_type = group_types.get(group_scope, -2147483646)

        attributes = {
            'objectClass': ['top', 'group'],
            'cn': group_name,
            'sAMAccountName': group_name,
            'groupType': group_type
        }
        if description:
            attributes['description'] = description

        try:
            conn.add(group_dn, attributes=attributes)
            if conn.result['result'] == 0:
                log_action(ACTIONS.get('CREATE_GROUP', 'create_group'), session.get('ad_username'),
                          {'dn': group_dn, 'name': group_name}, True, request.remote_addr)
                flash(f'Groupe {group_name} créé.', 'success')
                return redirect(url_for('groups.list_groups'))
            else:
                flash(f'Erreur: {conn.result["description"]}', 'error')
        except Exception as e:
            flash(f'Erreur: {str(e)}', 'error')
        finally:
            conn.unbind()

    return render_template('create_group.html', ous=ou_list, connected=is_connected())
