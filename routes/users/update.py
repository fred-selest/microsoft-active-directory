# -*- coding: utf-8 -*-
"""
Modification des utilisateurs Active Directory.
"""
from urllib.parse import unquote
from flask import render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE

from . import users_bp
from ..core import (get_ad_connection, decode_ldap_value, is_connected,
                   require_connection, require_permission)
from core.security import escape_ldap_filter, validate_csrf_token
from core.audit import log_action, ACTIONS
from .helpers import get_ous, get_user_attributes
from core.ldap_errors import format_ldap_error, handle_ldap_exception


@users_bp.route('/<path:dn>/edit', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def edit_user(dn):
    """Modifier les informations d'un utilisateur."""
    dn = unquote(dn)  # Décoder le DN si URL-encodé
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

    base_dn = session.get('ad_base_dn', '')
    user = None

    try:
        # Recherche BASE sur le DN direct
        conn.search(dn, '(objectClass=*)', 'BASE',
                   attributes=['cn', 'displayName', 'sAMAccountName', 'mail',
                              'department', 'title', 'telephoneNumber', 'description', 'memberOf'])
        if not conn.entries:
            flash('Utilisateur introuvable.', 'error')
            conn.unbind()
            return redirect(url_for('users.list_users'))

        entry = conn.entries[0]
        # Extraire l'OU actuelle du DN
        ou_parts = [p for p in dn.split(',') if p.strip().upper().startswith('OU=') or p.strip().upper().startswith('CN=')]
        current_ou = ','.join(ou_parts[1:]) if len(ou_parts) > 1 else ''

        # Groupes actuels
        current_groups = []
        if hasattr(entry, 'memberOf') and entry.memberOf:
            for g_dn in entry.memberOf.values:
                g_dn_str = str(g_dn)
                cn_part = g_dn_str.split(',')[0] if ',' in g_dn_str else g_dn_str
                cn_val = cn_part.split('=')[1] if '=' in cn_part else g_dn_str
                current_groups.append({'dn': g_dn_str, 'cn': cn_val})

        user = {
            'dn': dn,
            'cn': str(entry.cn.value) if entry.cn else '',
            'displayName': str(entry.displayName.value) if entry.displayName else '',
            'sAMAccountName': str(entry.sAMAccountName.value) if entry.sAMAccountName else '',
            'mail': str(entry.mail.value) if entry.mail else '',
            'department': str(entry.department.value) if entry.department else '',
            'title': str(entry.title.value) if entry.title else '',
            'telephoneNumber': str(entry.telephoneNumber.value) if entry.telephoneNumber else '',
            'description': str(entry.description.value) if hasattr(entry, 'description') and entry.description else '',
            'current_ou': current_ou,
            'current_groups': current_groups,
        }
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
        conn.unbind()
        return redirect(url_for('users.list_users'))

    if request.method == 'POST':
        action = request.form.get('action', 'update')

        # Charger les OUs si nécessaire (pour le rendu du formulaire en cas d'erreur)
        ou_list = []
        try:
            conn2, _ = get_ad_connection()
            if conn2:
                base_dn2 = session.get('ad_base_dn', '')
                try:
                    conn2.search(base_dn2, '(objectClass=organizationalUnit)', SUBTREE,
                                attributes=['name', 'distinguishedName'])
                    for ou in conn2.entries:
                        ou_list.append({'name': str(ou.name.value) if ou.name else '', 'dn': str(ou.entry_dn)})
                except Exception:
                    pass
                finally:
                    conn2.unbind()
        except Exception:
            pass

        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token CSRF invalide.', 'error')
            return render_template('edit_user.html', user=user, ous=ou_list, connected=is_connected())

        if action == 'move_ou':
            # Déplacement vers une nouvelle OU
            new_ou = request.form.get('target_ou', '').strip()
            if not new_ou:
                flash('OU cible requise.', 'error')
            else:
                try:
                    # Extraire le CN du DN actuel
                    cn_part = dn.split(',')[0]
                    new_dn = f"{cn_part},{new_ou}"
                    conn.modify_dn(dn, cn_part, new_superior=new_ou)
                    if conn.result.get('result') == 0:
                        log_action(ACTIONS.get('MOVE_USER', 'move_user'), session.get('ad_username'),
                                  {'old_dn': dn, 'new_dn': new_dn}, True, request.remote_addr)
                        flash(f'Utilisateur déplacé vers {new_ou}.', 'success')
                        return redirect(url_for('users.edit_user', dn=new_dn))
                    else:
                        flash(f'Erreur: {conn.result.get("description", "inconnue")}', 'error')
                except Exception as e:
                    flash(f'Erreur déplacement: {str(e)}', 'error')

        elif action == 'add_group':
            # Ajouter à un groupe
            group_dn = request.form.get('group_dn', '').strip()
            if group_dn:
                try:
                    conn.modify(group_dn, {'member': [(MODIFY_ADD, [dn])]})
                    if conn.result.get('result') == 0:
                        flash('Utilisateur ajouté au groupe.', 'success')
                    else:
                        flash(f'Erreur: {conn.result.get("description", "inconnue")}', 'error')
                except Exception as e:
                    flash(f'Erreur: {str(e)}', 'error')

        elif action == 'remove_group':
            # Retirer d'un groupe
            group_dn = request.form.get('group_dn', '').strip()
            if group_dn:
                try:
                    conn.modify(group_dn, {'member': [(MODIFY_DELETE, [dn])]})
                    if conn.result.get('result') == 0:
                        flash('Utilisateur retiré du groupe.', 'success')
                    else:
                        flash(f'Erreur: {conn.result.get("description", "inconnue")}', 'error')
                except Exception as e:
                    flash(f'Erreur: {str(e)}', 'error')

        else:
            # Mise à jour des attributs
            updates = {}
            for field in ['displayName', 'mail', 'department', 'title', 'telephoneNumber', 'description']:
                value = request.form.get(field, '').strip()
                if value:
                    updates[field] = value

            try:
                for field, value in updates.items():
                    conn.modify(dn, {field: [(MODIFY_REPLACE, [value])]})

                if conn.result.get('result') == 0:
                    log_action(ACTIONS.get('EDIT_USER', 'edit_user'), session.get('ad_username'),
                              {'dn': dn, 'updates': list(updates.keys())}, True, request.remote_addr)
                    flash('Informations mises à jour.', 'success')
                    return redirect(url_for('users.list_users'))
                else:
                    error_code = conn.result.get('result', 0)
                    error_desc = conn.result.get('description', 'Erreur inconnue')
                    error_msg = conn.result.get('message', '')
                    user_message = format_ldap_error(error_code, error_desc, error_msg, 'edit')
                    flash(user_message, 'error')
            except Exception as e:
                user_message = handle_ldap_exception(e, 'edit')
                flash(user_message, 'error')

        # Rafraîchir les données après modification
        try:
            conn.search(dn, '(objectClass=*)', 'BASE',
                       attributes=['cn', 'displayName', 'sAMAccountName', 'mail',
                                  'department', 'title', 'telephoneNumber', 'description', 'memberOf'])
            if conn.entries:
                entry = conn.entries[0]
                ou_parts = [p for p in dn.split(',') if p.strip().upper().startswith('OU=') or p.strip().upper().startswith('CN=')]
                current_ou = ','.join(ou_parts[1:]) if len(ou_parts) > 1 else ''
                current_groups = []
                if hasattr(entry, 'memberOf') and entry.memberOf:
                    for g_dn in entry.memberOf.values:
                        g_dn_str = str(g_dn)
                        cn_part = g_dn_str.split(',')[0] if ',' in g_dn_str else g_dn_str
                        cn_val = cn_part.split('=')[1] if '=' in cn_part else g_dn_str
                        current_groups.append({'dn': g_dn_str, 'cn': cn_val})
                user = {
                    'dn': dn, 'cn': str(entry.cn.value) if entry.cn else '',
                    'displayName': str(entry.displayName.value) if entry.displayName else '',
                    'sAMAccountName': str(entry.sAMAccountName.value) if entry.sAMAccountName else '',
                    'mail': str(entry.mail.value) if entry.mail else '',
                    'department': str(entry.department.value) if entry.department else '',
                    'title': str(entry.title.value) if entry.title else '',
                    'telephoneNumber': str(entry.telephoneNumber.value) if entry.telephoneNumber else '',
                    'description': str(entry.description.value) if hasattr(entry, 'description') and entry.description else '',
                    'current_ou': current_ou, 'current_groups': current_groups,
                }
        except Exception:
            pass

        conn.unbind()
        return render_template('edit_user.html', user=user, ous=ou_list, connected=is_connected())

    # GET - afficher le formulaire
    ou_list = []
    try:
        ou_list = get_ous(conn, base_dn)
        conn.unbind()
    except:
        conn.unbind()
    return render_template('edit_user.html', user=user, ous=ou_list, connected=is_connected())
