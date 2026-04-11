# -*- coding: utf-8 -*-
"""
Liste et recherche des utilisateurs Active Directory.
"""
from flask import render_template, request, session, redirect, url_for, flash
from ldap3 import SUBTREE
from ldap3.core.exceptions import LDAPException
from datetime import datetime

from . import users_bp
from ..core import (get_ad_connection, decode_ldap_value, is_connected,
                   require_connection, config)
from core.security import escape_ldap_filter


# Comptes système à exclure (Windows — noms EN et FR)
SYSTEM_ACCOUNTS = [
    'krbtgt', 'Guest', 'Invité', 'Administrator', 'Administrateur',
    'DefaultAccount', 'WDAGUtilityAccount',
]


@users_bp.route('/')
@require_connection
def list_users():
    """Liste des utilisateurs Active Directory."""
    conn, error = get_ad_connection()
    if not conn:
        return redirect(url_for('main.connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')
    ou_filter = request.args.get('ou', '')
    status_filter = request.args.get('status', 'all')  # all, active, disabled
    page = request.args.get('page', 1, type=int)
    per_page = config.ITEMS_PER_PAGE

    # Construire le filtre de recherche
    # Exclure les comptes système
    system_filter = ''.join(f'(!(cn={escape_ldap_filter(acc)}))' for acc in SYSTEM_ACCOUNTS)

    if search_query:
        safe_query = escape_ldap_filter(search_query)
        search_filter = (
            f'(&(objectClass=user)(objectCategory=person)'
            f'(|(cn=*{safe_query}*)(sAMAccountName=*{safe_query}*)(mail=*{safe_query}*))'
            f'{system_filter})'
        )
    else:
        search_filter = f'(&(objectClass=user)(objectCategory=person){system_filter})'

    # Si un OU spécifique est demandé, restreindre la recherche à cette OU
    search_base = base_dn
    if ou_filter:
        search_base = ou_filter

    try:
        conn.search(search_base, search_filter, SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'mail', 'distinguishedName',
                              'displayName', 'userAccountControl', 'department', 'title',
                              'lastLogonTimestamp', 'lastLogon', 'whenCreated', 'pwdLastSet'],
                   size_limit=10000)

        user_list = []
        now = datetime.now()
        for entry in conn.entries:
            entry_dn = str(entry.entry_dn).lower()
            # Exclure les utilisateurs système du conteneur Builtin et Users
            if 'cn=builtin' in entry_dn:
                continue
            uac_val = entry.userAccountControl.value if hasattr(entry, 'userAccountControl') and entry.userAccountControl else 512
            try:
                uac = int(uac_val)
            except (ValueError, TypeError):
                uac = 512
            is_disabled = bool(uac & 2)

            # Filtre par statut
            if status_filter == 'active' and is_disabled:
                continue
            if status_filter == 'disabled' and not is_disabled:
                continue

            # Dernière connexion — lastLogonTimestamp (répliqué entre DC)
            last_logon = None
            if hasattr(entry, 'lastLogonTimestamp') and entry.lastLogonTimestamp and entry.lastLogonTimestamp.value:
                llt_val = entry.lastLogonTimestamp.value
                try:
                    if isinstance(llt_val, datetime):
                        last_logon = llt_val
                        if last_logon.tzinfo:
                            last_logon = last_logon.replace(tzinfo=None)
                    elif isinstance(llt_val, str):
                        last_logon = datetime.strptime(llt_val.rstrip('Z'), '%Y%m%d%H%M%S')
                    else:
                        logon_val = int(str(llt_val))
                        if logon_val > 0:
                            last_logon = datetime.fromtimestamp(logon_val / 10000000 - 11644473600)
                except (ValueError, TypeError, OSError):
                    pass

            # Fallback : lastLogon (local au DC, non répliqué mais toujours disponible)
            if not last_logon and hasattr(entry, 'lastLogon') and entry.lastLogon and entry.lastLogon.value:
                ll_val = entry.lastLogon.value
                try:
                    if isinstance(ll_val, datetime):
                        last_logon = ll_val
                        if last_logon.tzinfo:
                            last_logon = last_logon.replace(tzinfo=None)
                    else:
                        logon_val = int(str(ll_val))
                        if logon_val > 0:
                            last_logon = datetime.fromtimestamp(logon_val / 10000000 - 11644473600)
                except (ValueError, TypeError, OSError):
                    pass

            # Date de création
            created = None
            if hasattr(entry, 'whenCreated') and entry.whenCreated and entry.whenCreated.value:
                try:
                    created = datetime.strptime(str(entry.whenCreated.value), '%Y%m%d%H%M%S.0Z')
                except (ValueError, TypeError):
                    try:
                        created = datetime.fromisoformat(str(entry.whenCreated.value).replace('Z', '+00:00'))
                    except (ValueError, TypeError):
                        pass

            # Dernier changement de mot de passe
            pwd_last_set = None
            if hasattr(entry, 'pwdLastSet') and entry.pwdLastSet and entry.pwdLastSet.value:
                try:
                    pwd_val = int(str(entry.pwdLastSet.value))
                    if pwd_val > 0:
                        pwd_last_set = datetime.fromtimestamp(pwd_val / 10000000 - 11644473600)
                except (ValueError, TypeError, OSError):
                    pass

            user_list.append({
                'cn': str(entry.cn.value) if entry.cn else '',
                'sAMAccountName': str(entry.sAMAccountName.value) if entry.sAMAccountName else '',
                'mail': str(entry.mail.value) if entry.mail else '',
                'dn': str(entry.entry_dn),
                'displayName': str(entry.displayName.value) if entry.displayName else '',
                'department': str(entry.department.value) if entry.department else '',
                'title': str(entry.title.value) if entry.title else '',
                'disabled': is_disabled,
                'lastLogon': last_logon,
                'whenCreated': created,
                'pwdLastSet': pwd_last_set,
            })

        # Trier par nom d'affichage
        user_list.sort(key=lambda u: (u.get('displayName') or u['cn']).lower())

        # Récupérer les OUs pour affichage
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'distinguishedName'])
        ou_list = [
            {'name': str(e.name.value) if e.name else '', 'dn': str(e.entry_dn)}
            for e in conn.entries
        ]
        ou_list.sort(key=lambda o: o['name'].lower())

        conn.unbind()

        # Pagination
        total = len(user_list)
        total_pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        paginated = user_list[start:start + per_page]

        return render_template('users.html', users=paginated, search=search_query,
                             page=page, total_pages=total_pages, total=total,
                             ous=ou_list, ou_filter=ou_filter,
                             status_filter=status_filter, connected=is_connected(),
                             column_chooser_enabled=_is_column_chooser_enabled())

    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur LDAP: {str(e)}', 'error')
        return render_template('users.html', users=[], search=search_query,
                             page=1, total_pages=1, total=0, ous=[],
                             status_filter=status_filter, connected=is_connected(),
                             column_chooser_enabled=_is_column_chooser_enabled())


def _is_column_chooser_enabled():
    """Verifier si le selecteur de colonnes est active."""
    try:
        from core.settings_manager import load_settings
        settings = load_settings()
        return settings.get('features', {}).get('users_column_chooser', True)
    except Exception:
        return True
