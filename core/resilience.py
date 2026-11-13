"""
Résistance au rançongiciel : ce qu'un attaquant (ou un poste infecté)
trouverait sur ce domaine, et ce qui permettrait de s'en relever.

Trois volets, en lecture seule :
- annuaire (LDAP) : qui peut devenir administrateur du domaine, et par
  quel chemin (appartenance directe, groupes imbriqués), comptes
  d'administration fragiles, délégations dangereuses, corbeille AD ;
- partages (droits NTFS lus par core/folders.py) : dossiers où tout le
  monde peut écrire — un seul poste infecté suffit à tout chiffrer ;
- sauvegardes (scripts/resilience.ps1, sur le serveur de l'application) :
  Sauvegarde Windows Server, clichés instantanés, logiciels tiers détectés.

Chaque constat a une gravité, une explication et une marche à suivre.
Non couvert : les droits délégués par ACL sur les objets de l'annuaire
(« qui peut réinitialiser le mot de passe d'un administrateur »).
"""
import json
import logging
import os
import subprocess
from datetime import datetime, timedelta, timezone

logger = logging.getLogger('resilience')

PS_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'scripts', 'resilience.ps1')
PS_TIMEOUT = 120

# userAccountControl
UF_DISABLED = 0x2
UF_PASSWD_NOTREQD = 0x20
UF_REVERSIBLE = 0x80
UF_DONT_EXPIRE = 0x10000
UF_TRUSTED_FOR_DELEGATION = 0x80000
UF_SERVER_TRUST = 0x2000               # contrôleur de domaine
UF_PARTIAL_SECRETS = 0x4000000         # contrôleur de domaine en lecture seule
UF_NOT_DELEGATED = 0x100000
UF_DONT_REQ_PREAUTH = 0x400000

# Groupes qui donnent la main sur le domaine. (RID ou SID complet, libellé, niveau)
DOMAIN_RIDS = {512: ('Admins du domaine', 'critical'), 518: ('Administrateurs du schéma', 'critical'),
               519: ('Administrateurs de l\'entreprise', 'critical')}
BUILTIN_SIDS = {'S-1-5-32-544': ('Administrateurs', 'critical'),
                'S-1-5-32-548': ('Opérateurs de compte', 'high'),
                'S-1-5-32-549': ('Opérateurs de serveur', 'high'),
                'S-1-5-32-550': ('Opérateurs d\'impression', 'high'),
                'S-1-5-32-551': ('Opérateurs de sauvegarde', 'high')}
NAMED_GROUPS = {'dnsadmins': ('DnsAdmins', 'high')}
RID_PROTECTED_USERS = 525
RID_KRBTGT = 502

# Entités « tout le monde » dans les droits d'un dossier : SID → (libellé, gravité en écriture)
BROAD_SIDS = {'S-1-1-0': ('Tout le monde', 'critical'), 'S-1-5-7': ('Anonyme', 'critical'),
              'S-1-5-11': ('Utilisateurs authentifiés', 'high'), 'S-1-5-32-545': ('Utilisateurs', 'high')}
BROAD_RIDS = {513: ('Utilisateurs du domaine', 'high'), 515: ('Ordinateurs du domaine', 'high'),
              514: ('Invités du domaine', 'critical')}
WRITE_LEVELS = ('Contrôle total', 'Modification', 'Écriture')

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'info': 3}
SEVERITY_COST = {'critical': 25, 'high': 12, 'medium': 5, 'info': 0}

ADMIN_PWD_MAX_DAYS = 365
ADMIN_INACTIVE_DAYS = 90
KRBTGT_MAX_DAYS = 180
MAX_ADMINS = 5
BACKUP_WARN_HOURS = 48
BACKUP_BAD_DAYS = 7


class ResilienceError(Exception):
    """Erreur présentable à l'utilisateur."""


def _finding(key, severity, title, why, fix, items=None, count=None):
    items = items or []
    return {'key': key, 'severity': severity, 'title': title, 'why': why, 'fix': fix,
            'items': items[:200], 'count': len(items) if count is None else count}


def score(findings):
    """Note sur 100 : chaque constat retire des points selon sa gravité."""
    return max(0, 100 - sum(SEVERITY_COST[f['severity']] for f in findings))


def sort_findings(findings):
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f['severity']], f['title']))


# --- Annuaire -----------------------------------------------------------------

def _val(entry, attr, default=None):
    if attr not in entry:
        return default
    value = getattr(entry, attr).value
    if isinstance(value, list):
        value = value[0] if value else default
    return default if value is None else value


def _values(entry, attr):
    return [str(v) for v in getattr(entry, attr).values] if attr in entry else []


def _int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def read_directory(conn, base_dn):
    """Groupes, comptes et ordinateurs utiles à l'analyse (trois lectures paginées)."""
    from routes.core import paged_search
    from core import folders as fs
    from core.ad_dates import ad_datetime, last_logon
    groups, users, computers = {}, {}, []
    for e in paged_search(conn, base_dn, '(objectClass=group)',
                          attributes=['cn', 'sAMAccountName', 'member', 'objectSid']):
        groups[e.entry_dn.lower()] = {'dn': e.entry_dn, 'name': str(_val(e, 'cn') or _val(e, 'sAMAccountName') or ''),
                                      'sid': fs.sid_to_str(getattr(e, 'objectSid', None)) if 'objectSid' in e else '',
                                      'members': [m.lower() for m in _values(e, 'member')]}
    for e in paged_search(conn, base_dn, '(&(objectClass=user)(objectCategory=person))',
                          attributes=['sAMAccountName', 'displayName', 'userAccountControl', 'pwdLastSet',
                                      'lastLogonTimestamp', 'lastLogon', 'servicePrincipalName', 'adminCount',
                                      'primaryGroupID', 'objectSid', 'memberOf']):
        sam = str(_val(e, 'sAMAccountName') or '')
        users[e.entry_dn.lower()] = {
            'dn': e.entry_dn, 'sam': sam, 'name': str(_val(e, 'displayName') or sam),
            'uac': _int(_val(e, 'userAccountControl'), 512),
            'pwd_last_set': ad_datetime(getattr(e, 'pwdLastSet', None)),
            'last_logon': last_logon(e), 'spn': _values(e, 'servicePrincipalName'),
            'admin_count': _int(_val(e, 'adminCount')) == 1,
            'primary_group': _int(_val(e, 'primaryGroupID')),
            'sid': fs.sid_to_str(getattr(e, 'objectSid', None)) if 'objectSid' in e else '',
            'member_of': [g.lower() for g in _values(e, 'memberOf')]}
    for e in paged_search(conn, base_dn, '(objectClass=computer)',
                          attributes=['cn', 'userAccountControl', 'primaryGroupID']):
        computers.append({'dn': e.entry_dn, 'name': str(_val(e, 'cn') or ''),
                          'uac': _int(_val(e, 'userAccountControl'), 4096),
                          'primary_group': _int(_val(e, 'primaryGroupID'))})
    return {'groups': groups, 'users': users, 'computers': computers,
            'recycle_bin': recycle_bin_enabled(conn, base_dn)}


def recycle_bin_enabled(conn, base_dn):
    """True / False, ou None si l'information n'est pas lisible."""
    from ldap3 import BASE
    try:
        config = None
        info = getattr(conn.server, 'info', None)
        if info is not None and getattr(info, 'other', None):
            config = (info.other.get('configurationNamingContext') or [None])[0]
        config = config or 'CN=Configuration,' + ','.join(
            p for p in base_dn.split(',') if p.strip().upper().startswith('DC='))
        conn.search('CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,'
                    f'CN=Services,{config}', '(objectClass=*)', BASE, attributes=['msDS-EnabledFeatureScope'])
        if not conn.entries:
            return None
        return bool(_values(conn.entries[0], 'msDS-EnabledFeatureScope'))
    except Exception as e:
        logger.info('État de la corbeille AD illisible : %s', e)
        return None


def _domain_sid(data):
    for user in data['users'].values():
        if user['sid'].startswith('S-1-5-21-') and user['sid'].count('-') == 7:
            return user['sid'].rsplit('-', 1)[0]
    for group in data['groups'].values():
        if group['sid'].startswith('S-1-5-21-') and group['sid'].count('-') == 7:
            return group['sid'].rsplit('-', 1)[0]
    return ''


def privileged_groups(data):
    """Groupes d'administration présents : [{dn, name, label, tier, rid}]."""
    domain = _domain_sid(data)
    found = []
    for group in data['groups'].values():
        sid, rid = group['sid'], None
        spec = BUILTIN_SIDS.get(sid)
        if not spec and domain and sid.startswith(domain + '-'):
            rid = _int(sid.rsplit('-', 1)[1])
            spec = DOMAIN_RIDS.get(rid)
        if not spec:
            spec = NAMED_GROUPS.get(group['name'].lower())
        if spec:
            found.append({'dn': group['dn'], 'name': group['name'], 'label': spec[0], 'tier': spec[1], 'rid': rid})
    return found


def privileged_accounts(data):
    """
    Comptes ayant un chemin vers un groupe d'administration.

    Returns:
        dict {dn minuscule: {'user': …, 'paths': [{'group', 'tier', 'via': [noms de groupes]}]}}
        Le chemin retenu pour chaque groupe est le plus court.
    """
    accounts = {}
    targets = privileged_groups(data)
    # Admins du domaine dans Administrateurs : imbrication d'origine, pas un chemin caché.
    builtin = {t['dn'].lower() for t in targets}
    for target in targets:
        seen = {target['dn'].lower(): ([], False)}     # groupe → (chemin, passe par un groupe ordinaire)
        queue = [target['dn'].lower()]
        while queue:
            current = queue.pop(0)
            via, hidden = seen[current]
            for member in data['groups'].get(current, {}).get('members', []):
                if member in data['groups']:
                    if member not in seen:
                        seen[member] = (via + [data['groups'][member]['name']], hidden or member not in builtin)
                        queue.append(member)
                elif member in data['users']:
                    entry = accounts.setdefault(member, {'user': data['users'][member], 'paths': []})
                    if not any(p['group'] == target['label'] for p in entry['paths']):
                        entry['paths'].append({'group': target['label'], 'tier': target['tier'], 'via': via,
                                               'nested': hidden})
        if target['rid']:
            # Groupe principal : cette appartenance n'apparaît pas dans « member ».
            for dn, user in data['users'].items():
                if user['primary_group'] == target['rid']:
                    entry = accounts.setdefault(dn, {'user': user, 'paths': []})
                    if not any(p['group'] == target['label'] for p in entry['paths']):
                        entry['paths'].append({'group': target['label'], 'tier': target['tier'], 'via': [],
                                               'nested': False})
    return accounts


def _path_text(path):
    return ' → '.join(path['via'] + [path['group']]) if path['via'] else path['group']


def _item(user, detail=''):
    return {'name': user['name'], 'sam': user['sam'], 'dn': user['dn'], 'detail': detail}


def analyse_directory(data, now=None):
    """
    Constats tirés de l'annuaire.

    Returns:
        dict: findings, admins (tableau des comptes d'administration avec
        leur chemin), counts.
    """
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    domain = _domain_sid(data)
    accounts = privileged_accounts(data)
    protected = set()
    for group in data['groups'].values():
        if domain and group['sid'] == f'{domain}-{RID_PROTECTED_USERS}':
            protected = set(group['members'])
    findings = []

    def enabled(user):
        return not user['uac'] & UF_DISABLED

    def critical(entry):
        return any(p['tier'] == 'critical' for p in entry['paths'])

    def is_krbtgt(user):
        return user['sid'].endswith(f'-{RID_KRBTGT}') or user['sam'].lower() == 'krbtgt'

    active = [a for a in accounts.values() if enabled(a['user']) and not is_krbtgt(a['user'])]
    full_admins = [a for a in active if critical(a)]

    if len(full_admins) > MAX_ADMINS:
        findings.append(_finding(
            'too_many_admins', 'medium', f'{len(full_admins)} comptes ont tous les droits sur le domaine',
            'Chaque compte d\'administration est une porte d\'entrée : il suffit d\'en compromettre un seul '
            'pour chiffrer tout le domaine.',
            f'Visez {MAX_ADMINS} comptes au plus. Retirez les comptes du quotidien et donnez des droits '
            'délégués (rôles de cette application) à la place.',
            [_item(a['user'], ' ; '.join(_path_text(p) for p in a['paths'])) for a in full_admins]))

    nested = [a for a in active if any(p['nested'] for p in a['paths'])]
    if nested:
        findings.append(_finding(
            'nested_admins', 'medium', 'Droits d\'administration obtenus par un groupe imbriqué',
            'Ces comptes n\'apparaissent pas dans la liste des membres du groupe d\'administration : ils y '
            'entrent par un autre groupe. Ajouter quelqu\'un à ce groupe intermédiaire en fait un administrateur '
            'sans que personne ne le voie.',
            'Retirez le groupe intermédiaire du groupe d\'administration et ajoutez directement les comptes '
            'qui en ont réellement besoin.',
            [_item(a['user'], ' ; '.join(_path_text(p) for p in a['paths'] if p['nested'])) for a in nested]))

    operators = [a for a in active if not critical(a)]
    if operators:
        findings.append(_finding(
            'operators', 'high', 'Membres des groupes d\'opérateurs',
            'Les opérateurs de sauvegarde peuvent copier la base de l\'annuaire, les opérateurs de serveur et '
            'de compte peuvent prendre la main sur un contrôleur de domaine ou sur d\'autres comptes : ce sont '
            'des administrateurs qui ne disent pas leur nom.',
            'Videz ces groupes : Microsoft recommande de ne pas les utiliser.',
            [_item(a['user'], ' ; '.join(_path_text(p) for p in a['paths'])) for a in operators]))

    roastable = [a for a in active if a['user']['spn']]
    if roastable:
        findings.append(_finding(
            'admin_spn', 'critical', 'Comptes d\'administration utilisés comme comptes de service',
            'Un compte qui porte un nom de service (SPN) peut être attaqué hors ligne par n\'importe quel '
            'utilisateur du domaine (« Kerberoasting ») : son mot de passe finit par tomber s\'il n\'est pas très long.',
            'Créez un compte de service dédié sans droits d\'administration (idéalement un compte de service '
            'géré, gMSA) et retirez le SPN du compte d\'administration.',
            [_item(a['user'], a['user']['spn'][0]) for a in roastable]))

    no_preauth = [u for u in data['users'].values() if enabled(u) and u['uac'] & UF_DONT_REQ_PREAUTH]
    if no_preauth:
        privileged = any(u['dn'].lower() in accounts for u in no_preauth)
        findings.append(_finding(
            'no_preauth', 'critical' if privileged else 'high', 'Comptes sans pré-authentification Kerberos',
            'Leur mot de passe peut être attaqué hors ligne par quelqu\'un qui n\'a même pas de compte sur le '
            'domaine (« AS-REP roasting »).',
            'Décochez « La pré-authentification Kerberos n\'est pas nécessaire » dans l\'onglet Compte.',
            [_item(u, 'compte d\'administration' if u['dn'].lower() in accounts else '') for u in no_preauth]))

    delegation = [{'name': c['name'], 'sam': c['name'], 'dn': '', 'detail': 'ordinateur'}
                  for c in data['computers']
                  if c['uac'] & UF_TRUSTED_FOR_DELEGATION and c['primary_group'] not in (516, 521)
                  and not c['uac'] & (UF_SERVER_TRUST | UF_PARTIAL_SECRETS)   # normal sur un contrôleur de domaine
                  and not c['uac'] & UF_DISABLED]
    delegation += [_item(u, 'compte') for u in data['users'].values()
                   if enabled(u) and u['uac'] & UF_TRUSTED_FOR_DELEGATION]
    if delegation:
        findings.append(_finding(
            'unconstrained_delegation', 'critical', 'Délégation Kerberos sans contrainte',
            'Ces machines ou comptes reçoivent le ticket complet de toute personne qui s\'y connecte, '
            'administrateurs compris : en prendre le contrôle revient à prendre le domaine.',
            'Passez en délégation contrainte, ou supprimez la délégation si elle ne sert plus.', delegation))

    stale = []
    for a in active:
        user, notes = a['user'], []
        if user['uac'] & UF_DONT_EXPIRE:
            notes.append('mot de passe sans expiration')
        if user['pwd_last_set'] and now - user['pwd_last_set'] > timedelta(days=ADMIN_PWD_MAX_DAYS):
            notes.append(f'mot de passe de {(now - user["pwd_last_set"]).days // 365} an(s)')
        if notes and critical(a):
            stale.append(_item(user, ', '.join(notes)))
    if stale:
        findings.append(_finding(
            'admin_old_password', 'medium', 'Mots de passe d\'administration anciens ou sans expiration',
            'Un mot de passe d\'administration qui ne change jamais reste valable des années après une fuite.',
            'Changez ces mots de passe et laissez-les expirer (ou utilisez des phrases longues renouvelées '
            'chaque année).', stale))

    inactive = [_item(a['user'], 'jamais connecté' if not a['user']['last_logon'] else
                      f'dernière connexion le {a["user"]["last_logon"].strftime("%d/%m/%Y")}')
                for a in active
                if not a['user']['last_logon'] or now - a['user']['last_logon'] > timedelta(days=ADMIN_INACTIVE_DAYS)]
    if inactive:
        findings.append(_finding(
            'admin_inactive', 'high', 'Comptes d\'administration inutilisés',
            f'Ces comptes actifs ne se sont pas connectés depuis plus de {ADMIN_INACTIVE_DAYS} jours : personne '
            'ne remarquerait qu\'un attaquant s\'en sert.',
            'Désactivez-les ou retirez-les des groupes d\'administration.', inactive))

    disabled = [_item(a['user'], ' ; '.join(_path_text(p) for p in a['paths']))
                for a in accounts.values() if not enabled(a['user']) and not is_krbtgt(a['user'])]
    if disabled:
        findings.append(_finding(
            'admin_disabled', 'medium', 'Comptes désactivés encore membres d\'un groupe d\'administration',
            'Réactiver un de ces comptes suffit à retrouver tous les droits.',
            'Retirez-les des groupes d\'administration (le bouton « Départ » le fait).', disabled))

    exposed = [_item(a['user']) for a in full_admins
               if not a['user']['uac'] & UF_NOT_DELEGATED and a['user']['dn'].lower() not in protected]
    if exposed:
        findings.append(_finding(
            'admin_delegable', 'medium', 'Comptes d\'administration non protégés contre la délégation',
            'Sans cette protection, un serveur compromis peut réutiliser l\'identité d\'un administrateur qui s\'y connecte.',
            'Cochez « Le compte est sensible et ne peut pas être délégué », ou ajoutez ces comptes au groupe '
            '« Protected Users ».', exposed))

    for user in data['users'].values():
        if is_krbtgt(user) and user['pwd_last_set'] and now - user['pwd_last_set'] > timedelta(days=KRBTGT_MAX_DAYS):
            findings.append(_finding(
                'krbtgt', 'high', f'Mot de passe du compte krbtgt inchangé depuis {(now - user["pwd_last_set"]).days} jours',
                'Ce compte signe tous les tickets Kerberos. Un attaquant qui a eu accès au domaine une seule fois '
                'peut fabriquer ses propres tickets d\'administrateur (« golden ticket ») tant que ce mot de passe '
                'n\'a pas changé deux fois.',
                f'Renouvelez-le deux fois, à au moins dix heures d\'intervalle, puis tous les {KRBTGT_MAX_DAYS} jours '
                '(script Microsoft New-KrbtgtKeys.ps1).', [], count=1))

    no_password = [_item(u) for u in data['users'].values() if enabled(u) and u['uac'] & UF_PASSWD_NOTREQD]
    if no_password:
        findings.append(_finding(
            'passwd_notreqd', 'high', 'Comptes autorisés à avoir un mot de passe vide',
            'L\'indicateur « mot de passe non requis » permet à ces comptes d\'échapper à la stratégie de mots de passe.',
            'Retirez l\'indicateur : Set-ADUser <compte> -PasswordNotRequired $false, puis imposez un mot de passe.',
            no_password))

    reversible = [_item(u) for u in data['users'].values() if enabled(u) and u['uac'] & UF_REVERSIBLE]
    if reversible:
        findings.append(_finding(
            'reversible', 'medium', 'Mots de passe enregistrés avec un chiffrement réversible',
            'Ces mots de passe sont récupérables en clair par quiconque obtient une copie de l\'annuaire.',
            'Décochez « Enregistrer le mot de passe en utilisant un chiffrement réversible » et changez le mot de passe.',
            reversible))

    orphans = [_item(u) for dn, u in data['users'].items()
               if u['admin_count'] and dn not in accounts and not is_krbtgt(u) and enabled(u)]
    if orphans:
        findings.append(_finding(
            'admin_count', 'info', 'Anciens comptes d\'administration',
            'Ces comptes ne sont plus dans un groupe d\'administration mais gardent la protection AdminSDHolder : '
            'leurs droits ne suivent plus ceux de leur unité d\'organisation (délégations inopérantes).',
            'Remettez adminCount à 0 et réactivez l\'héritage des droits sur ces comptes.', orphans))

    if data.get('recycle_bin') is False:
        findings.append(_finding(
            'recycle_bin', 'medium', 'La corbeille Active Directory n\'est pas activée',
            'Sans elle, un compte ou un groupe supprimé (par erreur ou par malveillance) ne se restaure qu\'à '
            'partir d\'une sauvegarde de l\'annuaire.',
            'Activez-la une fois pour toutes : Enable-ADOptionalFeature "Recycle Bin Feature" '
            '-Scope ForestOrConfigurationSet -Target <domaine>.', [], count=1))

    admins = []
    for a in sorted(accounts.values(), key=lambda a: (not critical(a), a['user']['name'].lower())):
        user = a['user']
        if is_krbtgt(user):
            continue
        admins.append({'name': user['name'], 'sam': user['sam'], 'dn': user['dn'], 'enabled': enabled(user),
                       'critical': critical(a), 'paths': [_path_text(p) for p in a['paths']],
                       'nested': any(p['nested'] for p in a['paths']),
                       'last_logon': user['last_logon'].strftime('%d/%m/%Y') if user['last_logon'] else '',
                       'pwd_age_days': (now - user['pwd_last_set']).days if user['pwd_last_set'] else None})
    return {'findings': sort_findings(findings), 'admins': admins,
            'counts': {'admins': len(full_admins), 'operators': len(operators),
                       'users': len(data['users']), 'groups': len(data['groups'])},
            'recycle_bin': data.get('recycle_bin')}


# --- Partages -----------------------------------------------------------------

def _broad(sid):
    if sid in BROAD_SIDS:
        return BROAD_SIDS[sid]
    if sid.startswith('S-1-5-21-') and sid.count('-') == 7:
        return BROAD_RIDS.get(_int(sid.rsplit('-', 1)[1]))
    return None


def analyse_shares(trees, errors=()):
    """
    Dossiers où une entité « tout le monde » peut écrire.

    trees : résultats de core.folders.rights_overview pour chaque partage géré.
    """
    by_severity = {'critical': [], 'high': []}
    readable = []
    scanned = 0
    for tree in trees:
        scanned += len(tree['folders'])
        for folder in tree['folders']:
            for ace in folder['aces']:
                spec = _broad(ace['sid'])
                # Un droit hérité est déjà signalé sur le dossier qui le porte.
                if not spec or ace['deny'] or (ace['inherited'] and folder['level'] > 0):
                    continue
                row = {'name': folder['path'], 'sam': '', 'dn': '', 'path': folder['path'],
                       'detail': f'{spec[0]} : {ace["level"]}'}
                if ace['level'] in WRITE_LEVELS:
                    by_severity[spec[1]].append(row)
                elif ace['sid'] in ('S-1-1-0', 'S-1-5-7'):
                    readable.append(row)
    findings = []
    if by_severity['critical']:
        findings.append(_finding(
            'share_everyone_write', 'critical', 'Dossiers modifiables par tout le monde',
            'N\'importe quel poste, même extérieur au domaine ou invité, peut chiffrer ou supprimer ces fichiers.',
            'Remplacez « Tout le monde » par un groupe précis (méthode AGDLP de la page Répertoires).',
            by_severity['critical']))
    if by_severity['high']:
        findings.append(_finding(
            'share_all_users_write', 'high', 'Dossiers modifiables par tous les utilisateurs du domaine',
            'Un seul poste infecté suffit à chiffrer ces dossiers : le rançongiciel agit avec les droits de '
            'l\'utilisateur connecté.',
            'Limitez l\'écriture aux groupes qui en ont besoin et laissez les autres en lecture.',
            by_severity['high']))
    if readable:
        findings.append(_finding(
            'share_everyone_read', 'medium', 'Dossiers lisibles par tout le monde',
            'Avant de chiffrer, les attaquants copient les données pour menacer de les publier.',
            'Réservez la lecture aux groupes concernés.', readable))
    return {'findings': sort_findings(findings), 'scanned': scanned, 'shares': [t['path'] for t in trees],
            'errors': list(errors)[:20],
            'truncated': any(t.get('truncated') for t in trees)}


def scan_shares(credentials):
    """Lit les droits de chaque partage géré, puis les analyse (long : à lancer en arrière-plan)."""
    from core import folders as fs
    settings = fs.get_folder_settings()
    trees, errors = [], []
    for root in settings['roots']:
        try:
            trees.append(fs.rights_overview({'path': root, 'depth': settings['scan_depth'],
                                             'credentials': credentials}))
        except fs.FolderError as e:
            errors.append(f'{root} : {e}')
    return analyse_shares(trees, errors)


# --- Sauvegardes ----------------------------------------------------------------

def run_ps():
    """État des sauvegardes du serveur de l'application (scripts/resilience.ps1)."""
    if os.name != 'nt':
        raise ResilienceError('L\'état des sauvegardes se lit sur un serveur Windows.')
    try:
        proc = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', PS_SCRIPT_PATH],
            input='{}', capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=PS_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ResilienceError('La lecture de l\'état des sauvegardes a dépassé le délai imparti.')
    except OSError as e:
        raise ResilienceError(f'PowerShell introuvable : {e}')
    lines = [ln for ln in (proc.stdout or '').strip().splitlines() if ln.strip().startswith('{')]
    try:
        result = json.loads(lines[-1].lstrip('﻿')) if lines else None
    except ValueError:
        result = None
    if not isinstance(result, dict) or not result.get('ok'):
        logger.error('État des sauvegardes illisible (code %s) : %s', proc.returncode,
                     (proc.stderr or proc.stdout or '')[:500])
        raise ResilienceError(str((result or {}).get('error') or 'Réponse illisible du serveur.')[:300])
    return result


def _when(text):
    try:
        return datetime.fromisoformat(str(text).replace('Z', '+00:00')).astimezone(timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def _age(moment, now):
    hours = (now - moment).total_seconds() / 3600
    return f'il y a {int(hours)} h' if hours < 48 else f'il y a {int(hours // 24)} jours'


def analyse_backups(raw, now=None):
    """Constats sur les sauvegardes et les clichés instantanés du serveur."""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    findings = []
    wsb = raw.get('wsb') or {}
    others = [str(s) for s in raw.get('other_software') or []]
    last = _when(wsb.get('last_success'))
    other_note = (' Un autre logiciel de sauvegarde est installé (' + ', '.join(others[:3]) +
                  ') : vérifiez son dernier rapport.') if others else ''

    if not wsb.get('installed'):
        findings.append(_finding(
            'wsb_missing', 'medium' if others else 'critical',
            'Sauvegarde Windows Server n\'est pas installée sur ce serveur',
            'Sans sauvegarde de l\'état du système, l\'annuaire ne peut pas être reconstruit après un chiffrement.'
            + other_note,
            'Installez la fonctionnalité (Install-WindowsFeature Windows-Server-Backup) et planifiez une sauvegarde '
            'quotidienne de l\'état du système vers un support que les postes ne peuvent pas atteindre.', [], count=1))
    elif not last:
        findings.append(_finding(
            'wsb_never', 'medium' if others else 'critical', 'Aucune sauvegarde Windows réussie sur ce serveur',
            'La fonctionnalité est installée mais aucune sauvegarde n\'a abouti.' + other_note,
            'Planifiez une sauvegarde quotidienne de l\'état du système (wbadmin enable backup).', [], count=1))
    elif now - last > timedelta(days=BACKUP_BAD_DAYS):
        findings.append(_finding(
            'wsb_old', 'medium' if others else 'critical', f'Dernière sauvegarde Windows réussie {_age(last, now)}',
            'Tout ce qui a changé depuis serait perdu.' + other_note,
            'Consultez le journal de Sauvegarde Windows Server : support plein, débranché ou tâche désactivée.',
            [], count=1))
    elif now - last > timedelta(hours=BACKUP_WARN_HOURS):
        findings.append(_finding(
            'wsb_late', 'medium', f'Dernière sauvegarde Windows réussie {_age(last, now)}',
            'La sauvegarde quotidienne n\'a pas tourné ou a échoué.' + other_note,
            'Consultez le journal de Sauvegarde Windows Server.', [], count=1))
    if wsb.get('installed') and last and _int(wsb.get('last_result')) != 0:
        findings.append(_finding(
            'wsb_failed', 'high', 'La dernière tentative de sauvegarde Windows a échoué',
            f'Code d\'erreur {wsb.get("last_result")}. La dernière réussite date de {_age(last, now)}.',
            'Consultez le journal de Sauvegarde Windows Server.', [], count=1))

    volumes, unprotected, stale = [], [], []
    for v in raw.get('volumes') or []:
        newest = _when(v.get('newest'))
        row = {'letter': str(v.get('letter') or ''), 'label': str(v.get('label') or ''),
               'size': _int(v.get('size')), 'free': _int(v.get('free')), 'copies': _int(v.get('copies')),
               'newest': newest.strftime('%d/%m/%Y %H:%M') if newest else '',
               'oldest': (_when(v.get('oldest')) or now).strftime('%d/%m/%Y') if v.get('oldest') else ''}
        volumes.append(row)
        item = {'name': f'{row["letter"]} {row["label"]}'.strip(), 'sam': '', 'dn': '', 'detail': ''}
        if not row['copies']:
            unprotected.append(item)
        elif newest and now - newest > timedelta(hours=BACKUP_WARN_HOURS):
            stale.append(dict(item, detail=f'dernier cliché {_age(newest, now)}'))
    if unprotected:
        findings.append(_finding(
            'vss_none', 'medium', 'Volumes sans cliché instantané',
            'Les clichés instantanés (« Versions précédentes ») permettent de récupérer un fichier écrasé en '
            'quelques secondes. Ils ne remplacent pas une sauvegarde : un rançongiciel avec des droits '
            'd\'administrateur les efface.',
            'Activez les clichés instantanés sur les volumes de données (Propriétés du volume › Clichés instantanés), '
            'deux fois par jour.', unprotected))
    if stale:
        findings.append(_finding(
            'vss_old', 'medium', 'Clichés instantanés anciens',
            'La planification des clichés ne tourne plus sur ces volumes.',
            'Vérifiez les tâches planifiées « ShadowCopyVolume… » et l\'espace réservé aux clichés.', stale))

    return {'findings': sort_findings(findings), 'computer': str(raw.get('computer') or ''),
            'wsb': {'installed': bool(wsb.get('installed')),
                    'last_success': last.strftime('%d/%m/%Y %H:%M') if last else '',
                    'next': (_when(wsb.get('next')) or now).strftime('%d/%m/%Y %H:%M') if wsb.get('next') else '',
                    'versions': _int(wsb.get('versions')), 'target': str(wsb.get('target') or '')},
            'volumes': volumes, 'other_software': others, 'notes': [str(n) for n in raw.get('notes') or []][:10]}


def scan_server(credentials):
    """Partages puis sauvegardes : l'analyse longue, lancée en arrière-plan."""
    result = {'shares': None, 'backups': None, 'errors': []}
    try:
        result['shares'] = scan_shares(credentials)
    except Exception as e:
        logger.warning('Analyse des partages impossible : %s', e)
        result['errors'].append(f'Partages : {e}')
    try:
        result['backups'] = analyse_backups(run_ps())
    except Exception as e:
        logger.warning('État des sauvegardes illisible : %s', e)
        result['errors'].append(f'Sauvegardes : {e}')
    return result
