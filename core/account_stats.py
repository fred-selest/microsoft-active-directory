"""
Statistiques de comptes partagées par le centre des alertes et le tableau
de bord.

Toutes les recherches passent par paged_search : une recherche simple est
tronquée par AD à 1000 objets (MaxPageSize), ce qui faussait les compteurs
des domaines plus grands.
"""
from datetime import timedelta

from core.ad_dates import (ad_datetime, get_account_policy, is_locked_out,
                           last_logon, password_expiry, utcnow)

INACTIVE_DAYS = 90
PASSWORD_WARNING_DAYS = 14
ACCOUNT_WARNING_DAYS = 30

UF_ACCOUNTDISABLE = 0x2

# Comptes intégrés jamais utilisés pour se connecter : les compter comme
# inactifs n'apprend rien.
_BUILTIN_ACCOUNTS = {'krbtgt', 'guest', 'invité', 'defaultaccount', 'wdagutilityaccount'}

_PERSON_FILTER = '(&(objectClass=user)(objectCategory=person))'
_USER_ATTRS = ['cn', 'sAMAccountName', 'userAccountControl', 'lastLogon',
               'lastLogonTimestamp', 'pwdLastSet', 'accountExpires',
               'lockoutTime', 'whenCreated', 'primaryGroupID']


def _int(attr, default=0):
    value = getattr(attr, 'value', attr)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _rid(sid):
    """RID (dernier composant) d'un SID 'S-1-5-21-…-512', ou None."""
    sid = getattr(sid, 'value', sid)
    if isinstance(sid, bytes) and len(sid) >= 12:
        return int.from_bytes(sid[-4:], 'little')
    try:
        return int(str(sid).rsplit('-', 1)[1])
    except (IndexError, ValueError):
        return None


def _is_builtin_sid(sid):
    sid = getattr(sid, 'value', sid)
    if isinstance(sid, bytes):
        # S-1-5-32-… : autorité 5, une seule sous-autorité valant 32
        return len(sid) >= 12 and sid[1] == 2 and sid[8:12] == (32).to_bytes(4, 'little')
    return str(sid).startswith('S-1-5-32-')


def load_users(conn, base_dn):
    from routes.core import paged_search
    return paged_search(conn, base_dn, _PERSON_FILTER, attributes=_USER_ATTRS)


def load_groups(conn, base_dn):
    from routes.core import paged_search
    return paged_search(conn, base_dn, '(objectClass=group)',
                        attributes=['cn', 'member', 'objectSid', 'isCriticalSystemObject'])


def count_empty_groups(groups, users):
    """
    Groupes sans aucun membre.

    Ne compte pas les groupes intégrés (BUILTIN, RID < 1000, objets système
    critiques) ni les groupes utilisés comme groupe principal : l'attribut
    member n'inclut jamais les membres via primaryGroupID (« Utilisateurs du
    domaine » paraît vide alors qu'il contient tout le monde).
    """
    primary_rids = {_int(getattr(u, 'primaryGroupID', None), None) for u in users}
    count = 0
    for group in groups:
        member = getattr(group, 'member', None)
        if member is not None and member.values:
            continue
        sid = getattr(group, 'objectSid', None)
        rid = _rid(sid)
        if _is_builtin_sid(sid) or (rid is not None and (rid < 1000 or rid in primary_rids)):
            continue
        critical = getattr(getattr(group, 'isCriticalSystemObject', None), 'value', None)
        if critical is True or str(critical).upper() == 'TRUE':
            continue
        count += 1
    return count


def compute_account_alerts(conn, base_dn):
    """
    Compteurs du centre des alertes.

    Returns:
        dict: compteurs (clés attendues par alerts.html) et
        'privileged_accounts'.
    """
    now = utcnow()
    policy = get_account_policy(conn, base_dn)
    users = load_users(conn, base_dn)
    groups = load_groups(conn, base_dn)

    data = {
        'expiring_accounts': 0, 'password_expiring': 0, 'inactive_accounts': 0,
        'locked_accounts': 0, 'disabled_accounts': 0, 'empty_groups': 0,
        'privileged_accounts': 0, 'max_pwd_age_days': None,
    }
    if policy['max_pwd_age']:
        data['max_pwd_age_days'] = policy['max_pwd_age'].days

    inactive_limit = now - timedelta(days=INACTIVE_DAYS)
    pwd_limit = now + timedelta(days=PASSWORD_WARNING_DAYS)
    account_limit = now + timedelta(days=ACCOUNT_WARNING_DAYS)

    for user in users:
        uac = _int(getattr(user, 'userAccountControl', None))
        sam = str(getattr(getattr(user, 'sAMAccountName', None), 'value', '') or '').lower()
        disabled = bool(uac & UF_ACCOUNTDISABLE)

        if is_locked_out(getattr(user, 'lockoutTime', None), policy['lockout_duration'], now):
            data['locked_accounts'] += 1
        if disabled:
            data['disabled_accounts'] += 1
            continue  # les comptes désactivés ne peuvent ni expirer ni servir

        expires = ad_datetime(getattr(user, 'accountExpires', None))
        if expires and now <= expires <= account_limit:
            data['expiring_accounts'] += 1

        pwd_expires = password_expiry(getattr(user, 'pwdLastSet', None),
                                      policy['max_pwd_age'], uac)
        if pwd_expires and now <= pwd_expires <= pwd_limit:
            data['password_expiring'] += 1

        if sam in _BUILTIN_ACCOUNTS:
            continue
        seen = last_logon(user)
        if seen:
            if seen < inactive_limit:
                data['inactive_accounts'] += 1
        else:
            # Jamais connecté : inactif seulement s'il existe depuis assez
            # longtemps (un compte créé hier n'est pas « inactif »).
            created = ad_datetime(getattr(user, 'whenCreated', None))
            if created and created < inactive_limit:
                data['inactive_accounts'] += 1

    data['empty_groups'] = count_empty_groups(groups, users)
    data['privileged_accounts'] = count_privileged_accounts(conn, base_dn, groups)
    return data


def count_privileged_accounts(conn, base_dn, groups):
    """
    Comptes actifs membres (y compris par imbrication) de « Admins du
    domaine » (RID 512) ou « Administrateurs de l'entreprise » (RID 519).

    Les groupes sont trouvés par leur SID et non par leur nom : sur un AD
    francophone ils s'appellent « Admins du domaine », et rien n'oblige à
    les laisser dans CN=Users.
    """
    from ldap3.utils.conv import escape_filter_chars
    from routes.core import paged_search

    admin_dns = [g.entry_dn for g in groups
                 if not _is_builtin_sid(getattr(g, 'objectSid', None))
                 and _rid(getattr(g, 'objectSid', None)) in (512, 519)]
    if not admin_dns:
        return 0
    # 1.2.840.113556.1.4.1941 = LDAP_MATCHING_RULE_IN_CHAIN (appartenance imbriquée)
    clauses = ''.join(f'(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(dn)})'
                      for dn in admin_dns)
    search_filter = (f'(&{_PERSON_FILTER}(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
                     f'(|{clauses}))')
    try:
        return len(paged_search(conn, base_dn, search_filter, attributes=['cn']))
    except Exception:
        return 0
