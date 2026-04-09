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
    ou_filter = request.args.get('ou', '')
    status_filter = request.args.get('status', 'all')  # all / active / disabled
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

    search_base = ou_filter if ou_filter else base_dn

    try:
        # Recherche paginée pour récupérer tous les utilisateurs (pas de limite 1000)
        attrs = ['cn', 'sAMAccountName', 'mail', 'distinguishedName',
                 'displayName', 'userAccountControl', 'department', 'title']
        user_list = []
        for entry in conn.extend.standard.paged_search(
                search_base, search_filter, SUBTREE,
                attributes=attrs, paged_size=500):
            if entry.get('type') != 'searchResEntry':
                continue
            a = entry.get('attributes', {})
            uac_val = a.get('userAccountControl') or 512
            if isinstance(uac_val, list):
                uac_val = uac_val[0] if uac_val else 512
            is_disabled = bool(int(uac_val) & 2)

            def _s(val):
                if isinstance(val, list):
                    return val[0] if val else ''
                return val or ''

            user_list.append({
                'cn': _s(a.get('cn')),
                'sAMAccountName': _s(a.get('sAMAccountName')),
                'mail': _s(a.get('mail')),
                'dn': entry.get('dn', ''),
                'displayName': _s(a.get('displayName')),
                'department': _s(a.get('department')),
                'title': _s(a.get('title')),
                'disabled': is_disabled
            })

        # Filtre statut en mémoire
        if status_filter == 'active':
            user_list = [u for u in user_list if not u['disabled']]
        elif status_filter == 'disabled':
            user_list = [u for u in user_list if u['disabled']]

        # OUs pour le dropdown
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
                               ous=ou_list, ou_filter=ou_filter,
                               status_filter=status_filter, connected=is_connected())

    except Exception as e:
        try:
            conn.unbind()
        except Exception:
            pass
        flash(f'Erreur LDAP: {str(e)}', 'error')
        return render_template('users.html', users=[], search=search_query,
                               page=1, total_pages=1, total=0, ous=[],
                               ou_filter='', status_filter='all', connected=is_connected())
