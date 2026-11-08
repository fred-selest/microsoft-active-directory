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


def _mail_fields(entry):
    """Adresse pro, alias, UPN et adresse personnelle d'une entrée."""
    def values(attr):
        return [str(v) for v in getattr(entry, attr).values] if attr in entry else []
    proxies = values('proxyAddresses')
    upn = values('userPrincipalName')
    return {
        'userPrincipalName': upn[0] if upn else '',
        'aliases': [p[5:] for p in proxies if p.lower().startswith('smtp:') and not p.startswith('SMTP:')],
        'proxyAddresses': proxies,
        'personal_email': (values('otherMailbox') or [''])[0],
    }


def merge_proxy_addresses(current, new_primary, keep_old_as_alias=True):
    """
    proxyAddresses après changement d'adresse principale.

    L'ancienne adresse principale (SMTP:) devient un alias (smtp:) pour que
    les messages qui lui sont adressés continuent d'arriver, ou disparaît.
    Les autres entrées (alias, X500:, SIP:…) sont conservées.
    """
    result = []
    for value in current:
        if value.lower() == f'smtp:{new_primary}'.lower():
            continue
        if value.startswith('SMTP:'):
            if keep_old_as_alias:
                result.append('smtp:' + value[5:])
            continue
        result.append(value)
    return [f'SMTP:{new_primary}'] + result


def _update_mail(conn, dn, user):
    """Adresse pro (mail, proxyAddresses, UPN au choix) et adresse personnelle."""
    from core.onboarding import address_owner, get_upn_suffixes, valid_email
    base_dn = session.get('ad_base_dn', '')
    pro = request.form.get('pro_email', '').strip().lower()
    personal = request.form.get('personal_email', '').strip()
    set_upn = request.form.get('set_upn') == 'on'
    keep_alias = request.form.get('keep_alias') == 'on'

    errors = []
    if pro and not valid_email(pro):
        errors.append('Adresse professionnelle invalide.')
    if personal and not valid_email(personal):
        errors.append('Adresse personnelle invalide.')
    if pro and personal and pro == personal.lower():
        errors.append('L\'adresse personnelle doit être différente de l\'adresse professionnelle.')
    if pro and not errors:
        owner = address_owner(conn, base_dn, pro, exclude_dn=dn)
        if owner:
            errors.append(f'L\'adresse {pro} est déjà utilisée par {owner}.')
        suffixes = get_upn_suffixes(conn, base_dn)
        if set_upn and suffixes and pro.split('@', 1)[1] not in suffixes:
            errors.append(f'Le domaine {pro.split("@", 1)[1]} n\'est pas un suffixe UPN de la forêt.')
    if set_upn and not pro:
        errors.append('Indiquez l\'adresse professionnelle à utiliser comme identifiant.')
    for err in errors:
        flash(err, 'error')
    if errors:
        return

    changes = {'otherMailbox': [(MODIFY_REPLACE, [personal] if personal else [])]}
    if pro:
        changes['mail'] = [(MODIFY_REPLACE, [pro])]
        changes['proxyAddresses'] = [(MODIFY_REPLACE, merge_proxy_addresses(
            user.get('proxyAddresses', []), pro, keep_alias))]
        if set_upn:
            changes['userPrincipalName'] = [(MODIFY_REPLACE, [pro])]
    elif user.get('mail'):
        changes['mail'] = [(MODIFY_REPLACE, [])]
    conn.modify(dn, changes)
    ok = conn.result.get('result') == 0
    log_action('edit_user_mail', session.get('ad_username'),
               {'dn': dn, 'mail': pro, 'upn': set_upn, 'personal': bool(personal)}, ok, request.remote_addr)
    if ok:
        flash('Adresses mises à jour ; Microsoft 365 les reprendra à la prochaine synchronisation.', 'success')
        for key, value in (('mail', pro), ('personal_email', personal)):
            user[key] = value
        if set_upn:
            user['userPrincipalName'] = pro
    else:
        flash(format_ldap_error(conn.result.get('result', 0), conn.result.get('description', ''),
                                conn.result.get('message', ''), 'edit'), 'error')


@users_bp.route('/<path:dn>/edit', methods=['GET', 'POST'])
@require_connection
@require_permission('users:update')
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
                              'department', 'title', 'telephoneNumber', 'description', 'memberOf',
                              'homeDirectory', 'homeDrive',
                              'userPrincipalName', 'proxyAddresses', 'otherMailbox'])
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
            'homeDirectory': str(entry.homeDirectory.value) if 'homeDirectory' in entry and entry.homeDirectory.value else '',
            'homeDrive': str(entry.homeDrive.value) if 'homeDrive' in entry and entry.homeDrive.value else '',
            **_mail_fields(entry),
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

        elif action == 'update_mail':
            _update_mail(conn, dn, user)

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
            # « mail » n'est plus modifié ici : seul, il désalignait proxyAddresses
            # (adresse reprise par Microsoft 365). Voir l'action update_mail.
            for field in ['displayName', 'department', 'title', 'telephoneNumber', 'description']:
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
                                  'department', 'title', 'telephoneNumber', 'description', 'memberOf',
                              'homeDirectory', 'homeDrive',
                              'userPrincipalName', 'proxyAddresses', 'otherMailbox'])
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
                    'homeDirectory': str(entry.homeDirectory.value) if 'homeDirectory' in entry and entry.homeDirectory.value else '',
                    'homeDrive': str(entry.homeDrive.value) if 'homeDrive' in entry and entry.homeDrive.value else '',
                    **_mail_fields(entry),
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
    except Exception:
        conn.unbind()
    return render_template('edit_user.html', user=user, ous=ou_list, connected=is_connected())
