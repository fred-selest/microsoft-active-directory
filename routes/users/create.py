# -*- coding: utf-8 -*-
"""
Création d'utilisateurs Active Directory.
"""
from flask import render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, MODIFY_ADD, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException
import logging

from . import users_bp
from ..core import (get_ad_connection, is_connected, require_connection,
                   require_permission)
from core.security import escape_ldap_filter, validate_csrf_token
from core.audit import log_action, ACTIONS
from .validators import UserCreateRequest

logger = logging.getLogger(__name__)


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
    use_ssl = session.get('ad_use_ssl', False)

    # Récupérer les OUs pour le formulaire
    try:
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'distinguishedName'])
        ou_list = [
            {'name': str(e.name.value) if e.name else '', 'dn': str(e.distinguishedName.value)}
            for e in conn.entries
        ]
        ou_list.sort(key=lambda x: x['name'])
    except Exception as ex:
        logger.error(f"Erreur récupération OUs: {ex}")
        ou_list = []

    # OU par défaut = CN=Users du domaine
    default_ou = f"CN=Users,{base_dn}" if base_dn else ''

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token CSRF invalide.', 'error')
            return render_template('create_user.html',
                                   ous=ou_list, default_ou=default_ou,
                                   use_ssl=use_ssl, connected=is_connected())

        # Récupérer les valeurs du formulaire
        target_ou = request.form.get('target_ou', '').strip()

        # Appliquer l'OU par défaut AVANT la validation
        if not target_ou:
            target_ou = default_ou

        user_req = UserCreateRequest(
            username=request.form.get('username', '').strip(),
            first_name=request.form.get('first_name', '').strip(),
            last_name=request.form.get('last_name', '').strip(),
            password=request.form.get('password', ''),
            email=request.form.get('email', '').strip(),
            ou=target_ou,
            department=request.form.get('department', '').strip(),
            title=request.form.get('title', '').strip()
        )

        must_change_password = request.form.get('must_change_password') == 'on'

        # Valider les données
        errors = user_req.validate()
        if errors:
            for err in errors:
                flash(err, 'error')
            return render_template('create_user.html',
                                   ous=ou_list, default_ou=default_ou,
                                   use_ssl=use_ssl, connected=is_connected())

        # Construire le DN
        cn = f"{user_req.first_name} {user_req.last_name}".strip() or user_req.username
        user_dn = f"CN={cn},{user_req.ou}"

        # Préparer les attributs
        domain = base_dn.replace('DC=', '').replace(',', '.') if base_dn else 'local'
        attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'sAMAccountName': user_req.username,
            'userPrincipalName': f"{user_req.username}@{domain}",
            'cn': cn,
            'displayName': cn,
            'givenName': user_req.first_name,
            'sn': user_req.last_name,
        }
        if user_req.email:
            attributes['mail'] = user_req.email
        if user_req.department:
            attributes['department'] = user_req.department
        if user_req.title:
            attributes['title'] = user_req.title

        try:
            logger.info(f"Création utilisateur {user_req.username} dans {user_req.ou}")
            success = conn.add(user_dn, attributes=attributes)
            logger.info(f"Résultat création: success={success}, result={conn.result}")

            if success and conn.result.get('result') == 0:
                # Définir le mot de passe (requiert LDAPS/STARTTLS)
                unicode_pwd = f'"{user_req.password}"'.encode('utf-16-le')
                pwd_success = conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})
                logger.info(f"Définition mot de passe: success={pwd_success}, result={conn.result}")

                if pwd_success and conn.result.get('result') == 0:
                    # Activer le compte (userAccountControl=512 = compte normal activé)
                    conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})

                    if must_change_password:
                        conn.modify(user_dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]})

                    log_action(ACTIONS.get('CREATE_USER', 'create_user'),
                               session.get('ad_username'),
                               {'dn': user_dn, 'username': user_req.username},
                               True, request.remote_addr)

                    flash(f'Utilisateur {user_req.username} créé avec succès.', 'success')
                    conn.unbind()
                    return redirect(url_for('users.list_users'))
                else:
                    # Échec mot de passe → supprimer l'entrée incomplète
                    error_desc = conn.result.get('description', '')
                    error_msg  = conn.result.get('message', '')
                    logger.warning(f"Échec mot de passe {user_req.username}: {error_desc} {error_msg}")
                    conn.delete(user_dn)

                    if not use_ssl:
                        flash('⚠️ Connexion sécurisée (LDAPS/STARTTLS) requise pour définir le mot de passe. '
                              'Déconnectez-vous et reconnectez via le port 636 (LDAPS).', 'warning')
                    else:
                        flash(f'Erreur lors de la définition du mot de passe : {error_desc}. {error_msg}', 'error')
            else:
                error_desc = conn.result.get('description', 'Erreur inconnue')
                error_msg  = conn.result.get('message', '')
                flash(f'Erreur création utilisateur : {error_desc}. {error_msg}', 'error')

        except LDAPException as ex:
            logger.error(f"Erreur LDAP création: {ex}")
            flash(f'Erreur LDAP : {str(ex)}', 'error')
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

        return render_template('create_user.html',
                               ous=ou_list, default_ou=default_ou,
                               use_ssl=use_ssl, connected=is_connected())

    # GET
    conn.unbind()
    return render_template('create_user.html',
                           ous=ou_list, default_ou=default_ou,
                           use_ssl=use_ssl, connected=is_connected())
