# -*- coding: utf-8 -*-
"""
Création d'utilisateurs Active Directory.
"""
from flask import render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, MODIFY_ADD
from ldap3.core.exceptions import LDAPException

from . import users_bp
from ..core import (get_ad_connection, is_connected, require_connection,
                   require_permission)
from security import escape_ldap_filter, validate_csrf_token
from audit import log_action, ACTIONS
from .validators import UserCreateRequest


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
        ou_list = [
            {'name': str(e.name.value) if e.name else '', 'dn': str(e.distinguishedName)}
            for e in conn.entries
        ]
    except:
        ou_list = []

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token CSRF invalide.', 'error')
            return render_template('create_user.html', ous=ou_list, connected=is_connected())

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
            return render_template('create_user.html', ous=ou_list, connected=is_connected())

        # Si aucune OU spécifiée, utiliser le base_dn
        if not user_req.ou:
            user_req.ou = base_dn or ''
            if not user_req.ou:
                flash('OU de destination requise.', 'error')
                return render_template('create_user.html', ous=ou_list, connected=is_connected())

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
            conn.add(user_dn, attributes=attributes)
            
            if conn.result.get('result') == 0:
                # Définir le mot de passe
                unicode_pwd = f'"{user_req.password}"'.encode('utf-16-le')
                conn.modify(user_dn, {'unicodePwd': [(MODIFY_ADD, [unicode_pwd])]})
                
                if conn.result.get('result') == 0:
                    if must_change_password:
                        conn.modify(user_dn, {'pwdLastSet': [(MODIFY_ADD, [0])]})
                    
                    log_action(ACTIONS.get('CREATE_USER', 'create_user'),
                              session.get('ad_username'),
                              {'dn': user_dn, 'username': user_req.username},
                              True, request.remote_addr)
                    
                    flash(f'Utilisateur {user_req.username} créé avec succès.', 'success')
                    return redirect(url_for('users.list_users'))
                else:
                    # Échec définition mot de passe - supprimer l'utilisateur
                    conn.delete(user_dn)
                    flash(f'Erreur mot de passe: {conn.result.get("description")}', 'error')
            else:
                flash(f'Erreur création: {conn.result.get("description")}', 'error')
                
        except LDAPException as e:
            flash(f'Erreur LDAP: {str(e)}', 'error')
        finally:
            conn.unbind()

        return render_template('create_user.html', ous=ou_list, connected=is_connected())

    return render_template('create_user.html', ous=ou_list, connected=is_connected())
