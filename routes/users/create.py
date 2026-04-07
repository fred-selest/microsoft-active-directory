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
from security import escape_ldap_filter, validate_csrf_token
from audit import log_action, ACTIONS
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
    
    # Vérifier si connexion SSL est disponible
    if not use_ssl:
        logger.warning("Connexion non sécurisée (pas de LDAPS) - password modification may fail")

    # Récupérer les OUs pour le formulaire
    try:
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'distinguishedName'])
        ou_list = [
            {'name': str(e.name.value) if e.name else '', 'dn': str(e.distinguishedName)}
            for e in conn.entries
        ]
        # Trier par nom
        ou_list.sort(key=lambda x: x['name'])
    except Exception as e:
        logger.error(f"Erreur récupération OUs: {e}")
        ou_list = []

    default_ou = base_dn  # OU par défaut = racine du domaine

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token CSRF invalide.', 'error')
            return render_template('create_user.html', ous=ou_list, default_ou=default_ou, use_ssl=use_ssl, connected=is_connected())

        # Créer l'objet de requête
        user_req = UserCreateRequest(
            username=request.form.get('username', '').strip(),
            first_name=request.form.get('first_name', '').strip(),
            last_name=request.form.get('last_name', '').strip(),
            password=request.form.get('password', ''),
            email=request.form.get('email', '').strip(),
            ou=request.form.get('target_ou', '').strip(),
            department=request.form.get('department', '').strip(),
            title=request.form.get('title', '').strip()
        )

        must_change_password = request.form.get('must_change_password') == 'on'

        # Valider les données
        errors = user_req.validate()
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('create_user.html', ous=ou_list, default_ou=default_ou, use_ssl=use_ssl, connected=is_connected())

        # Si aucune OU spécifiée, utiliser le base_dn (racine du domaine)
        if not user_req.ou:
            user_req.ou = base_dn or ''
            if not user_req.ou:
                flash('Impossible de déterminer l\'OU de destination. Vérifiez la connexion AD.', 'error')
                return render_template('create_user.html', ous=ou_list, default_ou=default_ou, use_ssl=use_ssl, connected=is_connected())

        # Construire le DN
        cn = f"{user_req.first_name} {user_req.last_name}".strip() or user_req.username
        user_dn = f"CN={cn},{user_req.ou}"

        # Préparer les attributs
        attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'sAMAccountName': user_req.username,
            'userPrincipalName': f"{user_req.username}@{base_dn.replace('DC=', '').replace(',', '.')}",
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
            # Créer l'utilisateur
            add_success = conn.add(user_dn, attributes=attributes)
            logger.info(f"Création utilisateur {user_req.username}: success={add_success}, result={conn.result}")

            if not add_success:
                error_desc = conn.result.get('description', 'Erreur inconnue')
                error_msg = conn.result.get('message', '')
                flash(f'Erreur création: {error_desc}', 'error')
                return render_template('create_user.html', ous=ou_list, default_ou=default_ou, use_ssl=use_ssl, connected=is_connected())

            # Définir le mot de passe (nécessite LDAPS/SSL)
            if user_req.password:
                unicode_pwd = f'"{user_req.password}"'.encode('utf-16-le')
                pwd_success = conn.modify(user_dn, {'unicodePwd': [(MODIFY_ADD, [unicode_pwd])]})
                logger.info(f"Définition mot de passe: success={pwd_success}, result={conn.result}")

                if not pwd_success:
                    # Échec définition mot de passe
                    error_desc = conn.result.get('description', '')
                    error_msg = conn.result.get('message', '')
                    
                    # Supprimer l'utilisateur créé
                    conn.delete(user_dn)
                    logger.warning(f"Utilisateur {user_dn} supprimé suite à échec password")
                    
                    # Message d'erreur détaillé
                    if 'unwillingToPerform' in str(error_desc) or 'WILL_NOT_PERFORM' in str(error_msg):
                        flash('⚠️ Mot de passe non défini: Connexion sécurisée (LDAPS) requise. '
                              'Déconnectez-vous et reconnectez avec SSL (port 636) pour définir le mot de passe.', 'error')
                    elif 'constraintViolation' in str(error_desc):
                        flash('⚠️ Mot de passe non défini: Le mot de passe ne respecte pas la politique AD. '
                              'Complexité requise: 8+ caractères, majuscule, minuscule, chiffre, caractère spécial.', 'error')
                    else:
                        flash(f'⚠️ Mot de passe non défini: {error_desc} - {error_msg[:100]}', 'error')
                    
                    return render_template('create_user.html', ous=ou_list, default_ou=default_ou, use_ssl=use_ssl, connected=is_connected())

            # Activer le compte (userAccountControl = 512 = NORMAL_ACCOUNT)
            uac_success = conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})
            logger.info(f"Activation compte: success={uac_success}")

            # Option: doit changer le mot de passe
            if must_change_password and user_req.password:
                conn.modify(user_dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]})

            log_action(ACTIONS.get('CREATE_USER', 'create_user'),
                      session.get('ad_username'),
                      {'dn': user_dn, 'username': user_req.username},
                      True, request.remote_addr)

            flash(f'✅ Utilisateur {user_req.username} créé avec succès.', 'success')
            return redirect(url_for('users.list_users'))

        except LDAPException as e:
            logger.error(f"Exception LDAP création: {str(e)}")
            flash(f'Erreur LDAP: {str(e)}', 'error')
        except Exception as e:
            logger.error(f"Exception création: {str(e)}")
            flash(f'Erreur: {str(e)}', 'error')
        finally:
            conn.unbind()

        return render_template('create_user.html', ous=ou_list, default_ou=default_ou, use_ssl=use_ssl, connected=is_connected())

    return render_template('create_user.html', ous=ou_list, default_ou=default_ou, use_ssl=use_ssl, connected=is_connected())