"""
Blueprint pour la gestion des utilisateurs.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException

from .core import (get_ad_connection, decode_ldap_value, is_connected,
                   require_connection, require_permission, config)
from security import escape_ldap_filter, validate_csrf_token
from audit import log_action, ACTIONS
from backup import backup_object, record_change

users_bp = Blueprint('users', __name__, url_prefix='/users')


@users_bp.route('/')
@require_connection
def list_users():
    """Liste des utilisateurs Active Directory."""
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
        search_filter = f'(&(objectClass=user)(objectCategory=person)(|(cn=*{safe_query}*)(sAMAccountName=*{safe_query}*)(mail=*{safe_query}*)))'
    else:
        search_filter = '(&(objectClass=user)(objectCategory=person))'

    try:
        conn.search(base_dn, search_filter, SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'mail', 'distinguishedName',
                              'displayName', 'userAccountControl', 'department', 'title'])

        user_list = []
        for entry in conn.entries:
            uac = entry.userAccountControl.value if hasattr(entry, 'userAccountControl') and entry.userAccountControl else 512
            is_disabled = bool(int(uac) & 2) if uac else False
            user_list.append({
                'cn': decode_ldap_value(entry.cn),
                'sAMAccountName': decode_ldap_value(entry.sAMAccountName),
                'mail': decode_ldap_value(entry.mail),
                'dn': decode_ldap_value(entry.distinguishedName),
                'displayName': decode_ldap_value(entry.displayName),
                'department': decode_ldap_value(entry.department),
                'title': decode_ldap_value(entry.title),
                'disabled': is_disabled
            })

        # OUs pour déplacement
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'distinguishedName'])
        ou_list = [{'name': decode_ldap_value(e.name), 'dn': decode_ldap_value(e.distinguishedName)}
                   for e in conn.entries]
        conn.unbind()

        # Pagination
        total = len(user_list)
        total_pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        paginated = user_list[start:start + per_page]

        return render_template('users.html', users=paginated, search=search_query,
                             page=page, total_pages=total_pages, total=total,
                             ous=ou_list, connected=is_connected())
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
        return render_template('users.html', users=[], search=search_query,
                             page=1, total_pages=1, total=0, ous=[], connected=is_connected())


@users_bp.route('/<path:dn>/delete', methods=['POST'])
@require_connection
@require_permission('delete')
def delete_user(dn):
    """Supprimer un utilisateur."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('users.list_users'))

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

    try:
        backup_object(conn, dn)
        conn.delete(dn)
        if conn.result['result'] == 0:
            log_action(ACTIONS['DELETE_USER'], session.get('ad_username'),
                      {'dn': dn}, True, request.remote_addr)
            flash('Utilisateur supprimé.', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
    finally:
        conn.unbind()

    return redirect(url_for('users.list_users'))


@users_bp.route('/<path:dn>/move', methods=['POST'])
@require_connection
@require_permission('write')
def move_user(dn):
    """Déplacer un utilisateur vers une autre OU."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('users.list_users'))

    target_ou = request.form.get('target_ou')
    if not target_ou:
        flash('OU cible requise.', 'error')
        return redirect(url_for('users.list_users'))

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

    try:
        cn = dn.split(',')[0]
        conn.modify_dn(dn, cn, new_superior=target_ou)
        if conn.result['result'] == 0:
            log_action(ACTIONS.get('MOVE_USER', 'move_user'), session.get('ad_username'),
                      {'dn': dn, 'target': target_ou}, True, request.remote_addr)
            flash('Utilisateur déplacé.', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
    finally:
        conn.unbind()

    return redirect(url_for('users.list_users'))


@users_bp.route('/create', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def create_user():
    """Créer un nouvel utilisateur."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

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
            return render_template('create_user.html', ous=ou_list, connected=is_connected())

        username = request.form.get('username', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        password = request.form.get('password', '')
        target_ou = request.form.get('target_ou', base_dn)
        email = request.form.get('email', '').strip()

        if not username:
            flash('Nom d\'utilisateur requis.', 'error')
            return render_template('create_user.html', ous=ou_list, connected=is_connected())

        cn = f"{first_name} {last_name}".strip() or username
        user_dn = f"CN={cn},{target_ou}"

        attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'sAMAccountName': username,
            'userPrincipalName': f"{username}@{base_dn.replace('DC=', '').replace(',', '.')}",
            'cn': cn,
            'displayName': cn,
            'givenName': first_name,
            'sn': last_name
        }
        if email:
            attributes['mail'] = email

        try:
            conn.add(user_dn, attributes=attributes)
            if conn.result['result'] == 0:
                # Définir le mot de passe si fourni
                if password:
                    unicode_pwd = f'"{password}"'.encode('utf-16-le')
                    conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})

                # Activer le compte
                conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})

                log_action(ACTIONS.get('CREATE_USER', 'create_user'), session.get('ad_username'),
                          {'dn': user_dn, 'username': username}, True, request.remote_addr)
                flash(f'Utilisateur {username} créé.', 'success')
                return redirect(url_for('users.list_users'))
            else:
                flash(f'Erreur: {conn.result["description"]}', 'error')
        except Exception as e:
            flash(f'Erreur: {str(e)}', 'error')
        finally:
            conn.unbind()

    return render_template('create_user.html', ous=ou_list, connected=is_connected())


@users_bp.route('/import', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def import_users():
    """Importer des utilisateurs depuis un fichier CSV."""
    if request.method == 'POST':
        flash('Fonctionnalité d\'import en cours de développement.', 'info')
        return redirect(url_for('users.list_users'))

    return render_template('import_users.html', connected=is_connected())


@users_bp.route('/export')
@require_connection
def export_users():
    """Exporter les utilisateurs au format CSV."""
    from flask import Response
    import csv
    import io

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

    base_dn = session.get('ad_base_dn', '')

    try:
        conn.search(base_dn, '(&(objectClass=user)(objectCategory=person))', SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'mail', 'displayName', 'department', 'title'])

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Nom', 'Login', 'Email', 'Nom affiché', 'Département', 'Titre'])

        for entry in conn.entries:
            writer.writerow([
                decode_ldap_value(entry.cn),
                decode_ldap_value(entry.sAMAccountName),
                decode_ldap_value(entry.mail),
                decode_ldap_value(entry.displayName),
                decode_ldap_value(entry.department),
                decode_ldap_value(entry.title)
            ])

        conn.unbind()

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=utilisateurs.csv'}
        )
    except Exception as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
        return redirect(url_for('users.list_users'))
