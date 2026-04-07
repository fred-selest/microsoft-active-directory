# -*- coding: utf-8 -*-
"""
Liste et recherche des utilisateurs Active Directory.
"""
from flask import render_template, request, session, redirect, url_for, flash
from ldap3 import SUBTREE
from ldap3.core.exceptions import LDAPException

from . import users_bp
from ..core import (get_ad_connection, decode_ldap_value, is_connected,
                   require_connection, config)
from core.security import escape_ldap_filter


@users_bp.route('/')
@require_connection
def list_users():
    """Liste des utilisateurs Active Directory."""
    conn, error = get_ad_connection()
    if not conn:
        return redirect(url_for('main.connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = config.ITEMS_PER_PAGE

    if search_query:
        safe_query = escape_ldap_filter(search_query)
        search_filter = (
            f'(&(objectClass=user)(objectCategory=person)'
            f'(|(cn=*{safe_query}*)(sAMAccountName=*{safe_query}*)(mail=*{safe_query}*)))'
        )
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
                'cn': str(entry.cn.value) if entry.cn else '',
                'sAMAccountName': str(entry.sAMAccountName.value) if entry.sAMAccountName else '',
                'mail': str(entry.mail.value) if entry.mail else '',
                'dn': str(entry.distinguishedName),
                'displayName': str(entry.displayName.value) if entry.displayName else '',
                'department': str(entry.department.value) if entry.department else '',
                'title': str(entry.title.value) if entry.title else '',
                'disabled': is_disabled
            })

        # Récupérer les OUs pour affichage
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'distinguishedName'])
        ou_list = [
            {'name': str(e.name.value) if e.name else '', 'dn': str(e.distinguishedName)}
            for e in conn.entries
        ]

        conn.unbind()

        # Pagination
        total = len(user_list)
        total_pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        paginated = user_list[start:start + per_page]

        return render_template('users.html', users=paginated, search=search_query,
                             page=page, total_pages=total_pages, total=total,
                             ous=ou_list, connected=is_connected())
                             
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur LDAP: {str(e)}', 'error')
        return render_template('users.html', users=[], search=search_query,
                             page=1, total_pages=1, total=0, ous=[], connected=is_connected())
