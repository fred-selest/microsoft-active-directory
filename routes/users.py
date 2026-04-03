"""
Blueprint pour la gestion des utilisateurs.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
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

        # OUs et Groupes pour modification rapide
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'distinguishedName'])
        ou_list = [{'name': decode_ldap_value(e.name), 'dn': decode_ldap_value(e.distinguishedName)}
                   for e in conn.entries]
        
        conn.search(base_dn, '(objectClass=group)', SUBTREE,
                   attributes=['name', 'distinguishedName'])
        group_list = [{'name': decode_ldap_value(e.name), 'dn': decode_ldap_value(e.distinguishedName)}
                     for e in conn.entries]
        
        conn.unbind()

        # Pagination
        total = len(user_list)
        total_pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        paginated = user_list[start:start + per_page]

        return render_template('users.html', users=paginated, search=search_query,
                             page=page, total_pages=total_pages, total=total,
                             ous=ou_list, groups=group_list, connected=is_connected())
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

    base_dn = session.get('ad_base_dn', '')

    try:
        conn.search(base_dn, f'(distinguishedName={dn})', SUBTREE, attributes=['*'])
        attributes = {}
        if conn.entries:
            entry = conn.entries[0]
            attributes = {attr: str(entry[attr].value) for attr in entry.entry_attributes}
        backup_object('user', dn, attributes)
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
        must_change_password = request.form.get('must_change_password') == 'on'
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
                    
                    # Forcer le changement de mot de passe à la prochaine connexion
                    if must_change_password:
                        conn.modify(user_dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]})

                # Activer le compte
                conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})

                log_action(ACTIONS.get('CREATE_USER', 'create_user'), session.get('ad_username'),
                          {'dn': user_dn, 'username': username, 'must_change_password': must_change_password}, True, request.remote_addr)
                flash(f'Utilisateur {username} créé.', 'success')
                return redirect(url_for('users.list_users'))
            else:
                flash(f'Erreur: {conn.result["description"]}', 'error')
        except Exception as e:
            flash(f'Erreur: {str(e)}', 'error')
        finally:
            conn.unbind()

    return render_template('create_user.html', ous=ou_list, connected=is_connected())


@users_bp.route('/<path:dn>/edit', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def edit_user(dn):
    """Modifier les attributs d'un utilisateur."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

    base_dn = session.get('ad_base_dn', '')
    user = None

    try:
        conn.search(base_dn, f'(distinguishedName={dn})', SUBTREE,
                   attributes=['cn', 'givenName', 'sn', 'displayName', 'mail',
                               'telephoneNumber', 'department', 'title', 'description',
                               'userAccountControl', 'sAMAccountName', 'distinguishedName'])
        if not conn.entries:
            flash('Utilisateur introuvable.', 'error')
            conn.unbind()
            return redirect(url_for('users.list_users'))
        entry = conn.entries[0]
        uac = entry.userAccountControl.value if hasattr(entry, 'userAccountControl') and entry.userAccountControl else 512
        user = {
            'dn': dn,
            'cn': decode_ldap_value(entry.cn),
            'givenName': decode_ldap_value(entry.givenName),
            'sn': decode_ldap_value(entry.sn),
            'displayName': decode_ldap_value(entry.displayName),
            'mail': decode_ldap_value(entry.mail),
            'telephoneNumber': decode_ldap_value(entry.telephoneNumber),
            'department': decode_ldap_value(entry.department),
            'title': decode_ldap_value(entry.title),
            'description': decode_ldap_value(entry.description),
            'disabled': bool(int(uac) & 2) if uac else False,
        }
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
        conn.unbind()
        return redirect(url_for('users.list_users'))

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token CSRF invalide.', 'error')
            return render_template('user_form.html', action='edit', user=user,
                                   password_requirements={'min_length': 8}, connected=is_connected())

        changes = {}
        for attr in ('givenName', 'sn', 'displayName', 'mail', 'telephoneNumber',
                     'department', 'title', 'description'):
            val = request.form.get(attr, '').strip()
            changes[attr] = [(MODIFY_REPLACE, [val] if val else [])]

        new_password = request.form.get('new_password', '').strip()
        enable_account = request.form.get('enable_account') == 'on'

        try:
            conn.modify(dn, changes)
            if new_password:
                unicode_pwd = f'"{new_password}"'.encode('utf-16-le')
                conn.modify(dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})
            current_uac = int(user['disabled']) * 2 + 512
            new_uac = 512 if enable_account else 514
            conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
            log_action(ACTIONS.get('EDIT_USER', 'edit_user'), session.get('ad_username'),
                      {'dn': dn}, True, request.remote_addr)
            flash('Utilisateur modifié.', 'success')
            conn.unbind()
            return redirect(url_for('users.list_users'))
        except Exception as e:
            flash(f'Erreur: {str(e)}', 'error')
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    return render_template('user_form.html', action='edit', user=user,
                           password_requirements={'min_length': 8}, connected=is_connected())


@users_bp.route('/<path:dn>/reset-password', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def reset_password(dn):
    """Réinitialiser le mot de passe d'un utilisateur."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

    base_dn = session.get('ad_base_dn', '')
    user = None

    try:
        conn.search(base_dn, f'(distinguishedName={dn})', SUBTREE,
                   attributes=['cn', 'displayName', 'sAMAccountName'])
        if not conn.entries:
            flash('Utilisateur introuvable.', 'error')
            conn.unbind()
            return redirect(url_for('users.list_users'))
        entry = conn.entries[0]
        user = {
            'dn': dn,
            'cn': decode_ldap_value(entry.cn),
            'displayName': decode_ldap_value(entry.displayName),
            'sAMAccountName': decode_ldap_value(entry.sAMAccountName),
        }
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
        conn.unbind()
        return redirect(url_for('users.list_users'))

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token CSRF invalide.', 'error')
            return render_template('reset_password.html', user=user,
                                   password_requirements={'min_length': 8,
                                   'require_uppercase': True, 'require_lowercase': True,
                                   'require_digit': True, 'require_special': False},
                                   connected=is_connected())

        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        must_change = request.form.get('must_change') == 'on'

        if new_password != confirm_password:
            flash('Les mots de passe ne correspondent pas.', 'error')
            return render_template('reset_password.html', user=user,
                                   password_requirements={'min_length': 8,
                                   'require_uppercase': True, 'require_lowercase': True,
                                   'require_digit': True, 'require_special': False},
                                   connected=is_connected())

        try:
            unicode_pwd = f'"{new_password}"'.encode('utf-16-le')
            conn.modify(dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})
            if conn.result['result'] == 0:
                if must_change:
                    conn.modify(dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]})
                log_action(ACTIONS.get('RESET_PASSWORD', 'reset_password'), session.get('ad_username'),
                          {'dn': dn}, True, request.remote_addr)
                flash('Mot de passe réinitialisé.', 'success')
                conn.unbind()
                return redirect(url_for('users.list_users'))
            else:
                flash(f'Erreur: {conn.result["description"]}', 'error')
        except Exception as e:
            flash(f'Erreur: {str(e)}', 'error')
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    return render_template('reset_password.html', user=user,
                           password_requirements={'min_length': 8,
                           'require_uppercase': True, 'require_lowercase': True,
                           'require_digit': True, 'require_special': False},
                           connected=is_connected())


@users_bp.route('/<path:dn>/toggle', methods=['POST'])
@require_connection
@require_permission('write')
def toggle_user(dn):
    """Activer ou désactiver un compte utilisateur."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('users.list_users'))

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

    base_dn = session.get('ad_base_dn', '')

    try:
        conn.search(base_dn, f'(distinguishedName={dn})', SUBTREE,
                   attributes=['userAccountControl'])
        if not conn.entries:
            flash('Utilisateur introuvable.', 'error')
            conn.unbind()
            return redirect(url_for('users.list_users'))

        uac = conn.entries[0].userAccountControl.value
        uac = int(uac) if uac else 512
        action = request.form.get('action', '')
        if action == 'enable':
            new_uac = uac & ~2
        else:
            new_uac = uac | 2

        conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
        if conn.result['result'] == 0:
            label = 'activé' if action == 'enable' else 'désactivé'
            log_action(ACTIONS.get('TOGGLE_USER', 'toggle_user'), session.get('ad_username'),
                      {'dn': dn, 'action': action}, True, request.remote_addr)
            flash(f'Utilisateur {label}.', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
    finally:
        conn.unbind()

    return redirect(url_for('users.list_users'))


@users_bp.route('/<path:dn>/duplicate', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def duplicate_user(dn):
    """Dupliquer un utilisateur existant."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

    base_dn = session.get('ad_base_dn', '')

    try:
        conn.search(base_dn, f'(distinguishedName={dn})', SUBTREE,
                   attributes=['cn', 'givenName', 'sn', 'displayName', 'department',
                               'title', 'memberOf'])
        if not conn.entries:
            flash('Utilisateur introuvable.', 'error')
            conn.unbind()
            return redirect(url_for('users.list_users'))
        entry = conn.entries[0]
        member_of = entry.memberOf.values if hasattr(entry, 'memberOf') and entry.memberOf else []
        user = {
            'dn': dn,
            'cn': decode_ldap_value(entry.cn),
            'givenName': decode_ldap_value(entry.givenName),
            'sn': decode_ldap_value(entry.sn),
            'displayName': decode_ldap_value(entry.displayName),
            'department': decode_ldap_value(entry.department),
            'title': decode_ldap_value(entry.title),
            'memberOf': [decode_ldap_value(g) for g in member_of],
        }
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'distinguishedName'])
        ou_list = [{'name': decode_ldap_value(e.name), 'dn': decode_ldap_value(e.distinguishedName)}
                   for e in conn.entries]
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
        conn.unbind()
        return redirect(url_for('users.list_users'))

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token CSRF invalide.', 'error')
            return render_template('duplicate_user.html', user=user, ous=ou_list, connected=is_connected())

        username = request.form.get('sAMAccountName', '').strip()
        password = request.form.get('password', '')
        target_ou = request.form.get('ou', base_dn) or base_dn
        first_name = request.form.get('givenName', '').strip()
        last_name = request.form.get('sn', '').strip()
        display_name = request.form.get('displayName', '').strip()
        department = request.form.get('department', '').strip()
        title = request.form.get('title', '').strip()
        copy_groups = request.form.get('copy_groups') == '1'

        if not username:
            flash("Identifiant requis.", 'error')
            conn.unbind()
            return render_template('duplicate_user.html', user=user, ous=ou_list, connected=is_connected())

        cn = display_name or f"{first_name} {last_name}".strip() or username
        new_dn = f"CN={cn},{target_ou}"
        attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'sAMAccountName': username,
            'cn': cn,
            'displayName': cn,
        }
        if first_name:
            attributes['givenName'] = first_name
        if last_name:
            attributes['sn'] = last_name
        if department:
            attributes['department'] = department
        if title:
            attributes['title'] = title

        try:
            conn.add(new_dn, attributes=attributes)
            if conn.result['result'] == 0:
                if password:
                    unicode_pwd = f'"{password}"'.encode('utf-16-le')
                    conn.modify(new_dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})
                conn.modify(new_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})
                if copy_groups:
                    from ldap3 import MODIFY_ADD
                    for group_dn in user['memberOf']:
                        conn.modify(group_dn, {'member': [(MODIFY_ADD, [new_dn])]})
                log_action(ACTIONS.get('CREATE_USER', 'create_user'), session.get('ad_username'),
                          {'dn': new_dn, 'source': dn}, True, request.remote_addr)
                flash(f'Utilisateur {username} créé.', 'success')
                conn.unbind()
                return redirect(url_for('users.list_users'))
            else:
                flash(f'Erreur: {conn.result["description"]}', 'error')
        except Exception as e:
            flash(f'Erreur: {str(e)}', 'error')
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    return render_template('duplicate_user.html', user=user, ous=ou_list, connected=is_connected())


@users_bp.route('/compare', methods=['GET', 'POST'])
@require_connection
def compare_users():
    """Comparer deux utilisateurs côte à côte."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

    base_dn = session.get('ad_base_dn', '')

    try:
        conn.search(base_dn, '(&(objectClass=user)(objectCategory=person))', SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'distinguishedName'])
        user_list = [{'cn': decode_ldap_value(e.cn),
                      'sAMAccountName': decode_ldap_value(e.sAMAccountName),
                      'dn': decode_ldap_value(e.distinguishedName)}
                     for e in conn.entries]
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
        conn.unbind()
        return redirect(url_for('users.list_users'))

    if request.method == 'GET':
        conn.unbind()
        return render_template('compare_users_form.html', users=user_list, connected=is_connected())

    # POST — compare
    dn1 = request.form.get('user1', '')
    dn2 = request.form.get('user2', '')

    COMPARE_ATTRS = ['cn', 'givenName', 'sn', 'displayName', 'mail', 'telephoneNumber',
                     'department', 'title', 'description', 'userAccountControl',
                     'memberOf', 'manager', 'company', 'physicalDeliveryOfficeName']

    def fetch_user(dn):
        conn.search(base_dn, f'(distinguishedName={dn})', SUBTREE, attributes=COMPARE_ATTRS)
        if not conn.entries:
            return None
        entry = conn.entries[0]
        result = {}
        for attr in COMPARE_ATTRS:
            try:
                val = getattr(entry, attr).value if hasattr(entry, attr) else None
                if isinstance(val, list):
                    result[attr] = [str(v) for v in val]
                else:
                    result[attr] = str(val) if val is not None else ''
            except Exception:
                result[attr] = ''
        result['cn'] = decode_ldap_value(entry.cn)
        return result

    try:
        u1 = fetch_user(dn1)
        u2 = fetch_user(dn2)
        conn.unbind()
        if not u1 or not u2:
            flash('Un ou deux utilisateurs introuvables.', 'error')
            return render_template('compare_users_form.html', users=user_list, connected=is_connected())
        return render_template('compare_users.html', user1=u1, user2=u2,
                               attributes=COMPARE_ATTRS, connected=is_connected())
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
        conn.unbind()
        return render_template('compare_users_form.html', users=user_list, connected=is_connected())


@users_bp.route('/bulk', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def bulk_operations():
    """Opérations en masse sur les utilisateurs."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

    base_dn = session.get('ad_base_dn', '')

    try:
        conn.search(base_dn, '(&(objectClass=user)(objectCategory=person))', SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'distinguishedName', 'userAccountControl'])
        user_list = []
        for e in conn.entries:
            uac = e.userAccountControl.value if hasattr(e, 'userAccountControl') and e.userAccountControl else 512
            user_list.append({
                'cn': decode_ldap_value(e.cn),
                'sAMAccountName': decode_ldap_value(e.sAMAccountName),
                'dn': decode_ldap_value(e.distinguishedName),
                'disabled': bool(int(uac) & 2),
            })
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
        conn.unbind()
        return redirect(url_for('users.list_users'))

    if request.method == 'GET':
        conn.unbind()
        return render_template('bulk_operations.html', users=user_list, connected=is_connected())

    # POST — execute
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        conn.unbind()
        return render_template('bulk_operations.html', users=user_list, connected=is_connected())

    action = request.form.get('action', '')
    selected_dns = request.form.getlist('user_dns')
    new_password = request.form.get('new_password', '')

    if not selected_dns:
        flash('Aucun utilisateur sélectionné.', 'error')
        conn.unbind()
        return render_template('bulk_operations.html', users=user_list, connected=is_connected())

    success_count = 0
    error_count = 0

    try:
        for dn in selected_dns:
            try:
                if action == 'enable':
                    conn.search(base_dn, f'(distinguishedName={dn})', SUBTREE,
                               attributes=['userAccountControl'])
                    if conn.entries:
                        uac = int(conn.entries[0].userAccountControl.value or 512)
                        conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [uac & ~2])]})
                elif action == 'disable':
                    conn.search(base_dn, f'(distinguishedName={dn})', SUBTREE,
                               attributes=['userAccountControl'])
                    if conn.entries:
                        uac = int(conn.entries[0].userAccountControl.value or 512)
                        conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [uac | 2])]})
                elif action == 'reset_password' and new_password:
                    unicode_pwd = f'"{new_password}"'.encode('utf-16-le')
                    conn.modify(dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})
                elif action == 'delete':
                    conn.search(base_dn, f'(distinguishedName={dn})', SUBTREE, attributes=['*'])
                    attributes = {}
                    if conn.entries:
                        entry = conn.entries[0]
                        attributes = {attr: str(entry[attr].value) for attr in entry.entry_attributes}
                    from backup import backup_object
                    backup_object('user', dn, attributes)
                    conn.delete(dn)
                if conn.result['result'] == 0:
                    success_count += 1
                else:
                    error_count += 1
            except Exception:
                error_count += 1
    finally:
        conn.unbind()

    log_action(ACTIONS.get('BULK_ACTION', 'bulk_action'), session.get('ad_username'),
              {'action': action, 'count': success_count}, True, request.remote_addr)
    flash(f'{success_count} utilisateur(s) traité(s), {error_count} erreur(s).', 'success' if not error_count else 'warning')
    return redirect(url_for('users.list_users'))


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


@users_bp.route('/search/advanced')
@require_connection
def advanced_search():
    """Recherche avancée d'utilisateurs (stub)."""
    flash('Recherche avancée disponible dans la version complète.', 'info')
    return redirect(url_for('users.list_users'))


@users_bp.route('/search/global')
@require_connection
def global_search():
    """Recherche globale (stub)."""
    flash('Recherche globale disponible dans la version complète.', 'info')
    return redirect(url_for('users.list_users'))


# === API POUR CHANGEMENTS RAPIDES ===

@users_bp.route('/api/quick-change', methods=['POST'])
@require_connection
@require_permission('write')
def api_quick_change():
    """API pour changement rapide de groupe ou OU."""
    import json
    
    data = request.get_json() if request.is_json else request.form
    dn = data.get('dn')
    change_type = data.get('type')
    new_value = data.get('value')
    
    if not dn or not change_type or not new_value:
        return jsonify({'success': False, 'error': 'Paramètres incomplets'}), 400
    
    conn, error = get_ad_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Connexion échouée'}), 500
    
    try:
        if change_type == 'group':
            # Ajouter l'utilisateur au groupe
            conn.modify(new_value, {
                'member': [(MODIFY_ADD, [dn])]
            })
            
            if conn.result['result'] == 0:
                return jsonify({
                    'success': True,
                    'message': 'Utilisateur ajouté au groupe avec succès'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': conn.result['description']
                }), 500
        
        elif change_type == 'ou':
            # Déplacer l'utilisateur vers la nouvelle OU
            # Note: LDAP ne permet pas de déplacer directement, il faut recréer
            # On retourne juste un message informatif
            return jsonify({
                'success': True,
                'message': f'Pour déplacer vers cette OU, utilisez la fonction Déplacer. OU cible: {new_value}',
                'ou_dn': new_value
            })
        
        else:
            return jsonify({'success': False, 'error': 'Type de changement inconnu'}), 400
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.unbind()


@users_bp.route('/api/bulk-change', methods=['POST'])
@require_connection
@require_permission('write')
def api_bulk_change():
    """API pour changement en masse de groupe ou OU."""
    import json
    
    data = request.get_json() if request.is_json else request.form
    users = data.get('users', [])
    group_dn = data.get('group')
    ou_dn = data.get('ou')
    
    if not users:
        return jsonify({'success': False, 'error': 'Aucun utilisateur spécifié'}), 400
    
    conn, error = get_ad_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Connexion échouée'}), 500
    
    results = {'success': 0, 'failed': 0, 'errors': []}
    
    try:
        # Changement de groupe
        if group_dn:
            for user in users:
                try:
                    conn.modify(group_dn, {
                        'member': [(MODIFY_ADD, [user['dn']])]
                    })
                    if conn.result['result'] == 0:
                        results['success'] += 1
                    else:
                        results['failed'] += 1
                        results['errors'].append(f"{user['name']}: {conn.result['description']}")
                except Exception as e:
                    results['failed'] += 1
                    results['errors'].append(f"{user['name']}: {str(e)}")
        
        # Pour OU, on ne peut pas déplacer en masse directement
        # On retourne juste les DNs pour traitement ultérieur
        if ou_dn:
            return jsonify({
                'success': True,
                'message': f'{results["success"]} utilisateur(s) ajouté(s) au groupe. Pour déplacer vers OU, utilisez la fonction Déplacer avec les DNs.',
                'modified': results['success'],
                'ou_target': ou_dn
            })
        
        return jsonify({
            'success': True,
            'message': f'{results["success"]}/{len(users)} utilisateur(s) modifié(s) avec succès',
            'modified': results['success'],
            'failed': results['failed']
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.unbind()
