# -*- coding: utf-8 -*-
"""
Suppression et déplacement d'utilisateurs Active Directory.
"""
import logging
from urllib.parse import unquote
from flask import request, redirect, url_for, flash, session
from ldap3 import SUBTREE

from . import users_bp
from ..core import (get_ad_connection, require_connection, require_permission)
from core.security import escape_ldap_filter, validate_csrf_token
from core.audit import log_action, ACTIONS
from core.backup import backup_object
from core.ldap_errors import format_ldap_error, handle_ldap_exception


@users_bp.route('/<path:dn>/delete', methods=['POST'])
@require_connection
@require_permission('delete')
def delete_user(dn):
    """Supprimer un utilisateur."""
    logger = logging.getLogger('users')

    # Décoder le DN si nécessaire (peut être URL-encodé)
    dn = unquote(dn)
    
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('users.list_users'))

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

    try:
        # Recherche avec attributs de base uniquement
        conn.search(session.get('ad_base_dn', ''), f'(distinguishedName={escape_ldap_filter(dn)})', SUBTREE,
                   attributes=['sAMAccountName', 'cn', 'displayName', 'distinguishedName'])
        
        username = 'Unknown'
        attributes = {}
        if conn.entries:
            entry = conn.entries[0]
            username = str(entry.sAMAccountName.value) if entry.sAMAccountName else 'Unknown'
            attributes = {
                'sAMAccountName': username,
                'cn': str(entry.cn.value) if entry.cn else '',
                'displayName': str(entry.displayName.value) if entry.displayName else '',
                'distinguishedName': str(entry.distinguishedName)
            }
            logger.info(f"delete_user: backup attributes = {attributes}")
        
        backup_object('user', dn, attributes)
        
        logger.info(f"delete_user: tentative de suppression de {dn}")
        conn.delete(dn)

        logger.info(f"delete_user: résultat = {conn.result}")

        if conn.result.get('result') == 0:
            log_action(ACTIONS['DELETE_USER'], session.get('ad_username'),
                      {'dn': dn}, True, request.remote_addr)
            flash('Utilisateur supprimé.', 'success')
        else:
            error_code = conn.result.get('result', 0)
            error_desc = conn.result.get('description', 'Erreur inconnue')
            error_msg = conn.result.get('message', '')
            
            # Utiliser le formateur d'erreurs LDAP
            user_message = format_ldap_error(error_code, error_desc, error_msg, 'delete')
            flash(user_message, 'error')

    except Exception as e:
        logger.error(f"delete_user: exception = {str(e)}", exc_info=True)
        # Utiliser le gestionnaire d'exceptions LDAP
        user_message = handle_ldap_exception(e, 'delete')
        flash(user_message, 'error')
    finally:
        conn.unbind()

    return redirect(url_for('users.list_users'))


@users_bp.route('/<path:dn>/move', methods=['POST'])
@require_connection
@require_permission('write')
def move_user(dn):
    """Déplacer un utilisateur vers une autre OU."""
    # Décoder le DN si nécessaire (peut être URL-encodé)
    dn = unquote(dn)

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
        if conn.result.get('result') == 0:
            log_action(ACTIONS.get('MOVE_USER', 'move_user'), session.get('ad_username'),
                      {'dn': dn, 'target': target_ou}, True, request.remote_addr)
            flash('Utilisateur déplacé.', 'success')
        else:
            error_code = conn.result.get('result', 0)
            error_desc = conn.result.get('description', 'Erreur inconnue')
            error_msg = conn.result.get('message', '')
            
            # Utiliser le formateur d'erreurs LDAP
            user_message = format_ldap_error(error_code, error_desc, error_msg, 'move')
            flash(user_message, 'error')
    except Exception as e:
        # Utiliser le gestionnaire d'exceptions LDAP
        user_message = handle_ldap_exception(e, 'move')
        flash(user_message, 'error')
    finally:
        conn.unbind()

    return redirect(url_for('users.list_users'))
