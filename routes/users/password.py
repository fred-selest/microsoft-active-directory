# -*- coding: utf-8 -*-
"""
Gestion des mots de passe utilisateurs.
"""
import logging
from urllib.parse import unquote
from flask import render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, MODIFY_REPLACE

from . import users_bp
from ..core import (get_ad_connection, is_connected, require_connection,
                   require_permission)
from core.security import escape_ldap_filter, validate_csrf_token
from core.audit import log_action, ACTIONS
from .validators import validate_password_strength
from core.ldap_errors import format_ldap_error, handle_ldap_exception


@users_bp.route('/<path:dn>/reset-password', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def reset_password(dn):
    """Réinitialiser le mot de passe d'un utilisateur."""
    logger = logging.getLogger('users')
    dn = unquote(dn)  # Décoder le DN si URL-encodé

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
            'cn': str(entry.cn.value) if entry.cn else '',
            'displayName': str(entry.displayName.value) if entry.displayName else '',
            'sAMAccountName': str(entry.sAMAccountName.value) if entry.sAMAccountName else '',
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
        
        # Valider la force du mot de passe
        pwd_errors = validate_password_strength(new_password)
        if pwd_errors:
            for error in pwd_errors:
                flash(error, 'error')
            return render_template('reset_password.html', user=user,
                                   password_requirements={'min_length': 8,
                                   'require_uppercase': True, 'require_lowercase': True,
                                   'require_digit': True, 'require_special': False},
                                   connected=is_connected())

        try:
            unicode_pwd = f'"{new_password}"'.encode('utf-16-le')
            conn.modify(dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})
            if conn.result.get('result') == 0:
                if must_change:
                    conn.modify(dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]})
                log_action(ACTIONS.get('RESET_PASSWORD', 'reset_password'), session.get('ad_username'),
                          {'dn': dn}, True, request.remote_addr)
                flash(f'Mot de passe réinitialisé pour {user["sAMAccountName"]}.', 'success')
                return redirect(url_for('users.list_users'))
            else:
                logger.error(f"reset_password: erreur = {conn.result}")
                error_code = conn.result.get('result', -1)
                error_desc = conn.result.get('description', '')
                error_msg = conn.result.get('message', '')
                
                # Utiliser le formateur d'erreurs LDAP
                user_message = format_ldap_error(error_code, error_desc, error_msg, 'reset_password')
                flash(user_message, 'error')
        except Exception as e:
            logger.error(f"reset_password: exception = {str(e)}", exc_info=True)
            # Utiliser le gestionnaire d'exceptions LDAP
            user_message = handle_ldap_exception(e, 'reset_password')
            flash(user_message, 'error')
        finally:
            conn.unbind()

        return render_template('reset_password.html', user=user,
                               password_requirements={'min_length': 8,
                               'require_uppercase': True, 'require_lowercase': True,
                               'require_digit': True, 'require_special': False},
                               connected=is_connected())

    return render_template('reset_password.html', user=user,
                           password_requirements={'min_length': 8,
                           'require_uppercase': True, 'require_lowercase': True,
                           'require_digit': True, 'require_special': False},
                           connected=is_connected())


@users_bp.route('/<path:dn>/toggle', methods=['POST'])
@require_connection
@require_permission('write')
def toggle_user_status(dn):
    """Activer ou désactiver un compte utilisateur."""
    logger = logging.getLogger('users')
    dn = unquote(dn)  # Décoder le DN si URL-encodé

    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('users.list_users'))

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

    base_dn = session.get('ad_base_dn', '')
    action = request.form.get('action', '')

    logger.info(f"toggle_user_status: DN = {dn}, action = {action}")

    try:
        search_filter = f'(distinguishedName={escape_ldap_filter(dn)})'
        conn.search(base_dn, search_filter, SUBTREE,
                   attributes=['userAccountControl', 'distinguishedName', 'sAMAccountName', 'pwdLastSet'])

        if not conn.entries:
            logger.error(f"toggle_user_status: Utilisateur introuvable: {dn}")
            flash(f'Utilisateur introuvable: {dn}', 'error')
            conn.unbind()
            return redirect(url_for('users.list_users'))

        entry = conn.entries[0]
        uac = entry.userAccountControl.value
        uac = int(uac) if uac else 512

        actual_dn = str(entry.distinguishedName)
        username = str(entry.sAMAccountName.value) if entry.sAMAccountName else 'inconnu'
        
        # Vérifier si le compte a un mot de passe défini
        pwd_last_set = entry.pwdLastSet.value if hasattr(entry, 'pwdLastSet') and entry.pwdLastSet else None

        logger.info(f"toggle_user_status: actual_dn = {actual_dn}, username = {username}, uac = {uac}, pwdLastSet = {pwd_last_set}")

        if action == 'enable':
            # PRÉVENTION: Vérifier si le compte a un mot de passe valide avant activation
            if pwd_last_set == 0 or pwd_last_set is None:
                # Compte sans mot de passe valide - proposer de le réinitialiser
                logger.warning(f"toggle_user_status: Compte {username} sans mot de passe valide")
                from flask import url_for
                flash(
                    f'<strong>Compte sans mot de passe valide</strong><br>'
                    f'Le compte {username} ne peut pas être activé sans mot de passe conforme.<br><br>'
                    f'<strong>Options :</strong><br>'
                    f'1. <a href="{url_for("users.reset_password", dn=actual_dn)}">Réinitialiser le mot de passe</a><br>'
                    f'2. Activer quand même (risqué)',
                    'warning'
                )
            
            new_uac = uac & ~2  # Activer (enlever ACCOUNTDISABLE)
            label = 'activé'
        else:
            new_uac = uac | 2   # Désactiver (ajouter ACCOUNTDISABLE)
            label = 'désactivé'

        logger.info(f"toggle_user_status: new_uac = {new_uac}")

        conn.modify(actual_dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})

        logger.info(f"toggle_user_status: résultat = {conn.result}")

        if conn.result.get('result') == 0:
            log_action(ACTIONS.get('TOGGLE_USER', 'toggle_user'), session.get('ad_username'),
                      {'dn': actual_dn, 'username': username, 'action': action}, True, request.remote_addr)
            flash(f'Compte {label}.', 'success')
        else:
            # Gérer les erreurs spécifiques avec le gestionnaire LDAP
            error_code = conn.result.get('result', 0)
            error_desc = conn.result.get('description', 'Erreur inconnue')
            error_msg = conn.result.get('message', '')
            
            from core.ldap_errors import format_ldap_error
            user_message = format_ldap_error(error_code, error_desc, error_msg, 'toggle')
            
            # Ajouter une suggestion spécifique pour l'activation
            if action == 'enable' and (error_code == 53 or 'unwilling' in str(error_desc).lower()):
                from flask import url_for
                user_message += (
                    f'<br><br><strong>Solution rapide :</strong><br>'
                    f'<a href="{url_for("users.reset_password", dn=actual_dn)}" class="btn btn-sm btn-primary">Réinitialiser le mot de passe</a>'
                )
            
            flash(user_message, 'error')
            
    except Exception as e:
        logger.error(f"toggle_user_status: exception = {str(e)}", exc_info=True)
        from core.ldap_errors import handle_ldap_exception
        user_message = handle_ldap_exception(e, 'toggle')
        flash(user_message, 'error')
    finally:
        conn.unbind()

    return redirect(url_for('users.list_users'))
