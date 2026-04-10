# -*- coding: utf-8 -*-
"""
Modification des utilisateurs Active Directory.
"""
from urllib.parse import unquote
from flask import render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, MODIFY_REPLACE

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
        conn.search(base_dn, f'(distinguishedName={dn})', SUBTREE,
                   attributes=['cn', 'displayName', 'sAMAccountName', 'mail',
                              'department', 'title', 'telephoneNumber', 'description'])
        if not conn.entries:
            flash('Utilisateur introuvable.', 'error')
            conn.unbind()
            return redirect(url_for('users.list_users'))
            
        entry = conn.entries[0]
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
        }
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
        conn.unbind()
        return redirect(url_for('users.list_users'))

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token CSRF invalide.', 'error')
            return render_template('edit_user.html', user=user, connected=is_connected())

        # Récupérer les nouvelles valeurs
        updates = {}
        for field in ['displayName', 'mail', 'department', 'title', 'telephoneNumber', 'description']:
            value = request.form.get(field, '').strip()
            if value:
                updates[field] = value

        try:
            # Appliquer les modifications
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
                
                # Utiliser le formateur d'erreurs LDAP
                user_message = format_ldap_error(error_code, error_desc, error_msg, 'edit')
                flash(user_message, 'error')
        except Exception as e:
            # Utiliser le gestionnaire d'exceptions LDAP
            user_message = handle_ldap_exception(e, 'edit')
            flash(user_message, 'error')
        finally:
            conn.unbind()

        return render_template('edit_user.html', user=user, connected=is_connected())

    # GET - afficher le formulaire
    try:
        ou_list = get_ous(conn, base_dn)
        conn.unbind()
        return render_template('edit_user.html', user=user, ous=ou_list, connected=is_connected())
    except:
        conn.unbind()
        return render_template('edit_user.html', user=user, connected=is_connected())
