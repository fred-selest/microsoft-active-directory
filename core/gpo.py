"""
Stratégies de groupe (GPO) : lecture, rattachements et gestion des liens.

Tout se lit dans l'annuaire :
- les GPO sont des objets groupPolicyContainer sous CN=Policies,CN=System ;
- un lien est une entrée de l'attribut gPLink d'une OU (ou de la racine du
  domaine) : « [LDAP://cn={GUID},cn=policies,…;options] », options bit 0 =
  lien désactivé, bit 1 = appliqué (« enforced ») ; la DERNIÈRE entrée de
  la chaîne a la priorité la plus haute (ordre de lien 1) ;
- gPOptions = 1 sur une OU bloque l'héritage ;
- le filtrage de sécurité est le droit étendu « Appliquer la stratégie de
  groupe » dans le descripteur de sécurité de la GPO.

Ce qui n'est PAS évalué, et signalé dans l'interface : les GPO liées aux
sites, les filtres WMI et le mode de bouclage (loopback).
"""
import re
import uuid

APPLY_GROUP_POLICY = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
ADS_RIGHT_DS_CONTROL_ACCESS = 0x100
GENERIC_ALL = 0x10000000
INHERIT_ONLY_ACE = 0x08

LINK_DISABLED = 1
LINK_ENFORCED = 2

GPO_STATUS = {
    0: 'Activée',
    1: 'Paramètres utilisateur désactivés',
    2: 'Paramètres ordinateur désactivés',
    3: 'Désactivée',
}

_LINK_RE = re.compile(r'\[LDAP://([^;\]]+);(\d+)\]', re.I)
_GUID_RE = re.compile(r'^\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}?$')
_GUID_IN_DN = re.compile(r'cn=(\{[0-9A-Fa-f-]{36}\})', re.I)

WELL_KNOWN = {
    'S-1-1-0': 'Tout le monde',
    'S-1-5-11': 'Utilisateurs authentifiés',
    'S-1-5-9': 'Contrôleurs de domaine d\'entreprise',
    'S-1-5-18': 'Système',
    'S-1-3-0': 'Créateur propriétaire',
}


class GpoError(Exception):
    """Erreur présentable à l'utilisateur."""


def norm_guid(value):
    """'{GUID}' en majuscules, ou GpoError."""
    match = _GUID_RE.match((value or '').strip())
    if not match:
        raise GpoError('Identifiant de stratégie invalide.')
    return '{' + match.group(1).upper() + '}'


# --- Descripteur de sécurité -------------------------------------------------

def _sid(data):
    count = data[1]
    authority = int.from_bytes(data[2:8], 'big')
    subs = [int.from_bytes(data[8 + 4 * i:12 + 4 * i], 'little') for i in range(count)]
    return 'S-%d-%d' % (data[0], authority) + ''.join('-%d' % s for s in subs), 8 + 4 * count


def parse_apply_rights(sd):
    """
    SID autorisés et refusés pour « Appliquer la stratégie de groupe ».

    Args:
        sd: descripteur de sécurité binaire (nTSecurityDescriptor, DACL).

    Returns:
        (allow, deny) : ensembles de SID. (None, None) si illisible.
    """
    try:
        if not sd or len(sd) < 20:
            return None, None
        dacl_offset = int.from_bytes(sd[16:20], 'little')
        if not dacl_offset:
            return None, None
        count = int.from_bytes(sd[dacl_offset + 4:dacl_offset + 6], 'little')
        pos = dacl_offset + 8
        allow, deny = set(), set()
        for _ in range(count):
            ace_type, ace_flags = sd[pos], sd[pos + 1]
            size = int.from_bytes(sd[pos + 2:pos + 4], 'little')
            body = sd[pos + 4:pos + size]
            pos += size
            if ace_type not in (0, 1, 5, 6) or ace_flags & INHERIT_ONLY_ACE:
                continue
            mask = int.from_bytes(body[0:4], 'little')
            offset, object_type = 4, None
            if ace_type in (5, 6):
                flags = int.from_bytes(body[4:8], 'little')
                offset = 8
                if flags & 1:
                    object_type = str(uuid.UUID(bytes_le=bytes(body[offset:offset + 16])))
                    offset += 16
                if flags & 2:
                    offset += 16
            sid, _ = _sid(body[offset:])
            # Droit étendu : accordé nommément, ou par « tous les droits
            # étendus » (aucun type d'objet) ou le contrôle total générique.
            grants = ((mask & ADS_RIGHT_DS_CONTROL_ACCESS and object_type in (None, APPLY_GROUP_POLICY))
                      or mask & GENERIC_ALL)
            if grants:
                (allow if ace_type in (0, 5) else deny).add(sid)
        return allow, deny
    except (IndexError, ValueError):
        return None, None


# --- Lecture -----------------------------------------------------------------

def parse_gplink(value):
    """[(dn_gpo, guid, options)] dans l'ordre de la chaîne (priorité croissante)."""
    links = []
    for dn, options in _LINK_RE.findall(value or ''):
        match = _GUID_IN_DN.search(dn)
        if match:
            links.append((dn, match.group(1).upper(), int(options)))
    return links


def format_gplink(links):
    return ''.join(f'[LDAP://{dn};{options}]' for dn, _, options in links)


def _value(entry, attr, default=None):
    if attr in entry:
        value = getattr(entry, attr).value
        return default if value in (None, [], '') else value
    return default


def _policies_dn(base_dn):
    return f'CN=Policies,CN=System,{base_dn}'


def load_gpos(conn, base_dn):
    """Toutes les GPO du domaine, {guid: gpo}."""
    from ldap3 import SUBTREE
    from ldap3.protocol.microsoft import security_descriptor_control
    conn.search(_policies_dn(base_dn), '(objectClass=groupPolicyContainer)', SUBTREE,
                attributes=['cn', 'displayName', 'flags', 'versionNumber', 'whenChanged', 'whenCreated',
                            'gPCWQLFilter', 'nTSecurityDescriptor'],
                controls=security_descriptor_control(sdflags=0x04))
    gpos = {}
    for entry in conn.entries:
        try:
            guid = norm_guid(str(_value(entry, 'cn', '')))
        except GpoError:
            continue
        flags = int(_value(entry, 'flags', 0) or 0) & 3
        version = int(_value(entry, 'versionNumber', 0) or 0)
        sd = _value(entry, 'nTSecurityDescriptor')
        allow, deny = parse_apply_rights(sd if isinstance(sd, (bytes, bytearray)) else None)
        wmi = str(_value(entry, 'gPCWQLFilter', '') or '')
        gpos[guid] = {
            'guid': guid, 'dn': entry.entry_dn,
            'name': str(_value(entry, 'displayName', guid)),
            'flags': flags, 'status': GPO_STATUS[flags],
            'user_enabled': not flags & 1, 'computer_enabled': not flags & 2,
            'user_version': version >> 16, 'computer_version': version & 0xFFFF,
            'changed': _value(entry, 'whenChanged'), 'created': _value(entry, 'whenCreated'),
            'wmi_filter': wmi.split(';')[1] if wmi.count(';') >= 2 else wmi,
            'apply_sids': sorted(allow) if allow is not None else None,
            'deny_sids': sorted(deny) if deny is not None else [],
            'links': [],
        }
    return gpos


def load_containers(conn, base_dn):
    """
    Racine du domaine et OU portant des liens ou bloquant l'héritage,
    {dn_minuscule: {dn, name, links, block}}.
    """
    from routes.core import paged_search
    entries = paged_search(conn, base_dn,
                           '(&(|(objectClass=organizationalUnit)(objectClass=domainDNS))'
                           '(|(gPLink=*)(gPOptions=*)))',
                           attributes=['name', 'gPLink', 'gPOptions'])
    containers = {}
    for entry in entries:
        containers[entry.entry_dn.lower()] = {
            'dn': entry.entry_dn,
            'name': str(_value(entry, 'name', entry.entry_dn)),
            'raw': str(_value(entry, 'gPLink', '') or ''),
            'links': parse_gplink(str(_value(entry, 'gPLink', '') or '')),
            'block': int(_value(entry, 'gPOptions', 0) or 0) & 1 == 1,
        }
    return containers


def resolve_names(conn, base_dn, sids):
    """{sid: nom lisible} pour des SID du domaine ou bien connus."""
    from ldap3 import SUBTREE
    from ldap3.utils.conv import escape_filter_chars
    names = {s: WELL_KNOWN[s] for s in sids if s in WELL_KNOWN}
    unknown = [s for s in sids if s not in names]
    for start in range(0, len(unknown), 50):
        chunk = unknown[start:start + 50]
        clauses = ''.join(f'(objectSid={escape_filter_chars(s)})' for s in chunk)
        conn.search(base_dn, f'(|{clauses})', SUBTREE, attributes=['objectSid', 'sAMAccountName', 'cn'])
        for entry in conn.entries:
            from core.folders import sid_to_str
            sid = sid_to_str(getattr(entry, 'objectSid', None))
            names[sid] = str(_value(entry, 'sAMAccountName') or _value(entry, 'cn') or sid)
    for sid in sids:
        names.setdefault(sid, sid)
    return names


def load_all(conn, base_dn):
    """
    GPO, conteneurs et constats.

    Returns:
        dict: gpos (liste triée), by_guid, containers (liste, haut en bas),
        orphan_links (liens vers une GPO disparue).
    """
    gpos = load_gpos(conn, base_dn)
    containers = load_containers(conn, base_dn)
    orphan_links = []
    for container in containers.values():
        total = len(container['links'])
        for index, (dn, guid, options) in enumerate(container['links']):
            link = {'target_dn': container['dn'], 'target_name': container['name'],
                    'enforced': bool(options & LINK_ENFORCED), 'disabled': bool(options & LINK_DISABLED),
                    'order': total - index, 'guid': guid}
            if guid in gpos:
                gpos[guid]['links'].append(link)
            else:
                orphan_links.append(link)

    sids = {s for g in gpos.values() for s in (g['apply_sids'] or []) + g['deny_sids']}
    names = resolve_names(conn, base_dn, sorted(sids)) if sids else {}
    for gpo in gpos.values():
        gpo['filtering'] = [{'sid': s, 'name': names.get(s, s)} for s in (gpo['apply_sids'] or [])]
        gpo['denied'] = [{'sid': s, 'name': names.get(s, s)} for s in gpo['deny_sids']]
        gpo['links'].sort(key=lambda l: (len(l['target_dn']), l['target_dn'].lower()))
        gpo['issues'] = _issues(gpo)

    ordered = sorted(containers.values(), key=lambda c: (len(c['dn']), c['dn'].lower()))
    for container in ordered:
        container['gpos'] = [
            {'guid': guid, 'name': gpos[guid]['name'] if guid in gpos else f'GPO supprimée {guid}',
             'missing': guid not in gpos, 'enforced': bool(options & LINK_ENFORCED),
             'disabled': bool(options & LINK_DISABLED), 'order': len(container['links']) - i}
            for i, (dn, guid, options) in enumerate(container['links'])][::-1]
    return {'gpos': sorted(gpos.values(), key=lambda g: g['name'].lower()), 'by_guid': gpos,
            'containers': ordered, 'by_dn': containers, 'orphan_links': orphan_links}


def _issues(gpo):
    issues = []
    active = [l for l in gpo['links'] if not l['disabled']]
    if not gpo['links']:
        issues.append(('unlinked', 'Liée nulle part : elle ne s\'applique à personne.'))
    elif not active:
        issues.append(('links_disabled', 'Tous ses liens sont désactivés.'))
    if gpo['flags'] == 3:
        issues.append(('disabled', 'Stratégie entièrement désactivée.'))
    if gpo['user_version'] == 0 and gpo['computer_version'] == 0:
        issues.append(('empty', 'Jamais modifiée : elle ne contient aucun paramètre.'))
    if gpo['apply_sids'] is not None and not gpo['apply_sids']:
        issues.append(('no_filtering', 'Aucun compte ni groupe n\'a le droit de l\'appliquer.'))
    return issues


# --- Qui reçoit quoi ---------------------------------------------------------

def _chain(containers, dn, include_self):
    """Conteneurs au-dessus de dn (et dn lui-même si include_self), du haut vers le bas."""
    low = dn.lower()
    chain = [c for key, c in containers.items()
             if low.endswith(',' + key) or (include_self and low == key)]
    return sorted(chain, key=lambda c: len(c['dn']))


def applied_order(containers, dn, include_self=False):
    """
    Liens applicables à un objet, dans l'ordre d'application (le dernier
    l'emporte), avec ceux qui sont écartés et pourquoi.

    Returns:
        (appliqués, écartés) : listes de dict {guid, source_dn, source_name,
        enforced, reason}.
    """
    normal, enforced, excluded = [], [], []
    for container in _chain(containers, dn, include_self):
        if container['block'] and normal:
            for link in normal:
                excluded.append(dict(link, reason=f'Héritage bloqué par {container["name"]}'))
            normal = []
        level_enforced = []
        for _, guid, options in container['links']:
            link = {'guid': guid, 'source_dn': container['dn'], 'source_name': container['name'],
                    'enforced': bool(options & LINK_ENFORCED), 'reason': None}
            if options & LINK_DISABLED:
                excluded.append(dict(link, reason='Lien désactivé'))
            elif options & LINK_ENFORCED:
                level_enforced.append(link)
            else:
                normal.append(link)
        # Un lien « appliqué » d'un niveau supérieur l'emporte sur ceux des
        # niveaux inférieurs : il est traité après eux.
        enforced = level_enforced + enforced
    return normal + enforced, excluded


def applied_gpos(conn, base_dn, dn, data=None):
    """
    Stratégies reçues par un utilisateur, un ordinateur ou une OU.

    Returns:
        dict: target {dn, name, kind}, applied (priorité décroissante :
        la première l'emporte), excluded, notes.
    """
    from ldap3 import BASE
    from core import folders as fs
    data = data or load_all(conn, base_dn)
    if not dn.lower().endswith(base_dn.lower()):
        raise GpoError('Objet hors du domaine.')
    conn.search(dn, '(objectClass=*)', BASE, attributes=['objectClass', 'name', 'sAMAccountName'])
    if not conn.entries:
        raise GpoError('Objet introuvable.')
    entry = conn.entries[0]
    classes = [str(c).lower() for c in entry.objectClass.values]
    if 'computer' in classes:
        kind = 'computer'
    elif 'user' in classes:
        kind = 'user'
    elif 'organizationalunit' in classes or 'domaindns' in classes or 'domain' in classes:
        kind = 'ou'
    else:
        raise GpoError('Les stratégies s\'appliquent aux utilisateurs, aux ordinateurs et aux OU.')
    name = str(_value(entry, 'sAMAccountName') or _value(entry, 'name') or dn)

    sids = None
    if kind != 'ou':
        try:
            sids = fs.resolve_principal(conn, base_dn, dn)['sids']
        except fs.FolderError as e:
            raise GpoError(str(e))

    links, excluded = applied_order(data['by_dn'], dn, include_self=(kind == 'ou'))
    applied, seen = [], set()
    for link in reversed(links):                      # la plus prioritaire d'abord
        gpo = data['by_guid'].get(link['guid'])
        row = dict(link, name=gpo['name'] if gpo else f'GPO supprimée {link["guid"]}',
                   wmi_filter=gpo['wmi_filter'] if gpo else '', via=None)
        if not gpo:
            excluded.append(dict(row, reason='La stratégie n\'existe plus (lien orphelin)'))
            continue
        if link['guid'] in seen:
            continue                                   # liée plusieurs fois : le lien le plus fort compte
        part_on = {'user': gpo['user_enabled'], 'computer': gpo['computer_enabled'],
                   'ou': gpo['flags'] != 3}[kind]
        if not part_on:
            excluded.append(dict(row, reason={'user': 'Paramètres utilisateur désactivés',
                                              'computer': 'Paramètres ordinateur désactivés',
                                              'ou': 'Stratégie désactivée'}[kind]))
            continue
        if sids is not None and gpo['apply_sids'] is not None:
            denied = [s for s in gpo['deny_sids'] if s in sids]
            allowed = [s for s in gpo['apply_sids'] if s in sids]
            if denied:
                excluded.append(dict(row, reason=f'Filtrage de sécurité : refus pour {sids[denied[0]]}'))
                continue
            if not allowed:
                excluded.append(dict(row, reason='Filtrage de sécurité : ni le compte ni ses groupes '
                                                 'n\'ont le droit d\'appliquer cette stratégie'))
                continue
            row['via'] = sids[allowed[0]]
        seen.add(link['guid'])
        applied.append(row)

    for row in excluded:
        if not row.get('name'):
            known = data['by_guid'].get(row['guid'])
            row['name'] = known['name'] if known else f'GPO supprimée {row["guid"]}'

    notes = ['Les stratégies liées aux sites Active Directory ne sont pas prises en compte.']
    if any(r['wmi_filter'] for r in applied):
        notes.append('Les filtres WMI ne sont pas évalués : une stratégie qui en porte un peut ne pas '
                     's\'appliquer selon le poste.')
    if kind == 'user':
        notes.append('Seuls les paramètres « utilisateur » suivent le compte ; en mode de bouclage '
                     '(loopback), ceux de l\'ordinateur utilisé peuvent les remplacer.')
    return {'target': {'dn': dn, 'name': name, 'kind': kind}, 'applied': applied,
            'excluded': excluded, 'notes': notes}


def gpo_scope(conn, base_dn, gpo, data, limit=2000):
    """
    Utilisateurs et ordinateurs qui reçoivent une GPO : situés sous un lien
    actif, non coupés par un blocage d'héritage, et autorisés par le
    filtrage de sécurité.

    Returns:
        dict: users, computers (listes {name, dn}), truncated.
    """
    from ldap3.utils.conv import escape_filter_chars
    from routes.core import paged_search

    if gpo['apply_sids'] is None:
        principal_filter = ''                           # filtrage illisible : portée par les liens seuls
    else:
        everyone = {'S-1-1-0', 'S-1-5-11'} & set(gpo['apply_sids'])
        clauses = []
        if not everyone:
            for sid in gpo['apply_sids']:
                conn.search(base_dn, f'(objectSid={escape_filter_chars(sid)})',
                            attributes=['objectClass'])
                if not conn.entries:
                    continue
                entry = conn.entries[0]
                classes = [str(c).lower() for c in entry.objectClass.values]
                if 'group' in classes:
                    clauses.append(f'(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(entry.entry_dn)})')
                    clauses.append(f'(primaryGroupID={int(sid.rsplit("-", 1)[1])})')
                else:
                    clauses.append(f'(objectSid={escape_filter_chars(sid)})')
            if not clauses:
                return {'users': [], 'computers': [], 'truncated': False}
        principal_filter = '' if everyone else '(|' + ''.join(clauses) + ')'
    deny = ''.join(f'(!(objectSid={escape_filter_chars(s)}))' for s in gpo['deny_sids'])

    blocked = [c['dn'].lower() for c in data['containers'] if c['block']]
    found = {'user': {}, 'computer': {}}
    for link in gpo['links']:
        if link['disabled']:
            continue
        target = link['target_dn'].lower()
        cut = [] if link['enforced'] else [b for b in blocked if b != target and b.endswith(',' + target)]
        for kind, part_on, category in (('user', gpo['user_enabled'], '(objectCategory=person)(objectClass=user)'),
                                        ('computer', gpo['computer_enabled'], '(objectCategory=computer)')):
            if not part_on:
                continue
            entries = paged_search(conn, link['target_dn'], f'(&{category}{principal_filter}{deny})',
                                   attributes=['sAMAccountName', 'cn'])
            for entry in entries:
                low = entry.entry_dn.lower()
                if any(low.endswith(',' + b) for b in cut):
                    continue
                found[kind][low] = {'dn': entry.entry_dn,
                                    'name': str(_value(entry, 'sAMAccountName') or _value(entry, 'cn'))}
    users = sorted(found['user'].values(), key=lambda x: x['name'].lower())
    computers = sorted(found['computer'].values(), key=lambda x: x['name'].lower())
    return {'users': users[:limit], 'computers': computers[:limit],
            'users_count': len(users), 'computers_count': len(computers),
            'truncated': len(users) > limit or len(computers) > limit}


def gpos_for_group(data, sid):
    """GPO dont le filtrage de sécurité nomme ce groupe (ou ce compte)."""
    return [g for g in data['gpos'] if g['apply_sids'] and sid in g['apply_sids']]


# --- Écritures ---------------------------------------------------------------

def _container(conn, base_dn, target_dn):
    """Entrée d'une OU ou de la racine du domaine (gPLink, gPOptions)."""
    from ldap3 import BASE
    if not target_dn or not target_dn.lower().endswith(base_dn.lower()):
        raise GpoError('Cible hors du domaine.')
    conn.search(target_dn, '(|(objectClass=organizationalUnit)(objectClass=domainDNS))', BASE,
                attributes=['gPLink', 'gPOptions', 'name'])
    if not conn.entries:
        raise GpoError('La cible doit être une unité d\'organisation ou la racine du domaine.')
    return conn.entries[0]


def _check(conn, action):
    if conn.result.get('result') != 0:
        raise GpoError(f'{action} impossible : '
                       f'{conn.result.get("message") or conn.result.get("description") or "erreur LDAP"}')


def _write_links(conn, target_dn, links):
    from ldap3 import MODIFY_REPLACE
    value = format_gplink(links)
    conn.modify(target_dn, {'gPLink': [(MODIFY_REPLACE, [value] if value else [])]})
    _check(conn, 'Modification des liens')


def change_link(conn, base_dn, guid, target_dn, action):
    """
    action : add, remove, enable, disable, enforce, unenforce, up, down.

    Un nouveau lien est ajouté en priorité la plus haute (ordre 1).
    """
    guid = norm_guid(guid)
    gpos = load_gpos(conn, base_dn)
    entry = _container(conn, base_dn, target_dn)
    links = parse_gplink(str(_value(entry, 'gPLink', '') or ''))
    index = next((i for i, (_, g, _o) in enumerate(links) if g == guid), None)

    if action == 'add':
        if guid not in gpos:
            raise GpoError('Stratégie introuvable.')
        if index is not None:
            raise GpoError('Cette stratégie est déjà liée à cette cible.')
        links.append((f'cn={guid},cn=policies,cn=system,{base_dn}', guid, 0))
    else:
        if index is None:
            raise GpoError('Ce lien n\'existe pas (ou plus).')
        dn, _, options = links[index]
        if action == 'remove':
            links.pop(index)
        elif action in ('enable', 'disable', 'enforce', 'unenforce'):
            bit = LINK_DISABLED if action in ('enable', 'disable') else LINK_ENFORCED
            options = options | bit if action in ('disable', 'enforce') else options & ~bit
            links[index] = (dn, guid, options)
        elif action in ('up', 'down'):                 # up = priorité plus haute = vers la fin
            other = index + 1 if action == 'up' else index - 1
            if 0 <= other < len(links):
                links[index], links[other] = links[other], links[index]
        else:
            raise GpoError('Action inconnue.')
    _write_links(conn, entry.entry_dn, links)
    return entry.entry_dn


def set_status(conn, base_dn, guid, flags):
    """État d'une GPO : 0 activée, 1 sans paramètres utilisateur, 2 sans ordinateur, 3 désactivée."""
    from ldap3 import MODIFY_REPLACE
    guid = norm_guid(guid)
    try:
        flags = int(flags)
    except (TypeError, ValueError):
        raise GpoError('État invalide.')
    if flags not in GPO_STATUS:
        raise GpoError('État invalide.')
    gpos = load_gpos(conn, base_dn)
    if guid not in gpos:
        raise GpoError('Stratégie introuvable.')
    conn.modify(gpos[guid]['dn'], {'flags': [(MODIFY_REPLACE, [flags])]})
    _check(conn, 'Changement d\'état')
    return gpos[guid]['name']


def set_block_inheritance(conn, base_dn, target_dn, block):
    from ldap3 import MODIFY_REPLACE
    entry = _container(conn, base_dn, target_dn)
    conn.modify(entry.entry_dn, {'gPOptions': [(MODIFY_REPLACE, [1 if block else 0])]})
    _check(conn, 'Blocage de l\'héritage')
    return entry.entry_dn


# --- Sauvegarde et restauration (PowerShell, module GroupPolicy) ------------

import json  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
from datetime import datetime  # noqa: E402

PS_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'scripts', 'gpo.ps1')
BACKUP_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'data', 'gpo_backups')
_BACKUP_NAME = re.compile(r'^\d{8}-\d{6}$')
MAX_BACKUPS = 30


def _run_ps(request, timeout=600):
    """Exécute scripts/gpo.ps1 (paramètres en JSON sur l'entrée standard)."""
    from core import folders as fs
    if os.name != 'nt':
        raise GpoError('La sauvegarde des stratégies nécessite que l\'application tourne sous Windows.')
    user, password = fs._credentials()
    request = dict(request, user=user, password=password)
    try:
        proc = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
             '-File', PS_SCRIPT_PATH],
            input=json.dumps(request), capture_output=True, text=True, encoding='utf-8',
            errors='replace', timeout=timeout)
    except subprocess.TimeoutExpired:
        raise GpoError('L\'opération a dépassé le délai imparti.')
    except OSError as e:
        raise GpoError(f'PowerShell introuvable : {e}')
    out = (proc.stdout or '').strip().lstrip('\ufeff')
    try:
        result = json.loads(out[out.find('{'):]) if '{' in out else None
    except ValueError:
        result = None
    if not isinstance(result, dict):
        raise GpoError((proc.stderr or out or 'Réponse PowerShell illisible.')[:300])
    if not result.get('ok'):
        raise GpoError(str(result.get('error') or 'Erreur inconnue.')[:300])
    return result


def _domain(base_dn):
    return '.'.join(p.split('=', 1)[1] for p in base_dn.split(',') if p.strip().upper().startswith('DC='))


def list_backups():
    """Sauvegardes présentes, la plus récente d'abord."""
    backups = []
    if not os.path.isdir(BACKUP_ROOT):
        return backups
    for name in sorted(os.listdir(BACKUP_ROOT), reverse=True):
        manifest = os.path.join(BACKUP_ROOT, name, 'manifest.json')
        if _BACKUP_NAME.match(name) and os.path.isfile(manifest):
            try:
                with open(manifest, encoding='utf-8') as f:
                    data = json.load(f)
            except (OSError, ValueError):
                continue
            backups.append({'name': name, 'date': datetime.strptime(name, '%Y%m%d-%H%M%S'),
                            'by': data.get('by', ''), 'gpos': data.get('gpos', [])})
    return backups


def backup_all(base_dn, by):
    """Sauvegarde toutes les GPO (Backup-GPO -All) dans data/gpo_backups/<date>."""
    name = datetime.now().strftime('%Y%m%d-%H%M%S')
    path = os.path.join(BACKUP_ROOT, name)
    os.makedirs(path, exist_ok=True)
    result = _run_ps({'op': 'backup', 'path': path, 'domain': _domain(base_dn)})
    gpos = [{'id': norm_guid(str(g.get('id'))), 'guid': norm_guid(str(g.get('guid'))),
             'name': str(g.get('name') or '')} for g in result.get('gpos') or []]
    with open(os.path.join(path, 'manifest.json'), 'w', encoding='utf-8') as f:
        json.dump({'by': by, 'gpos': gpos}, f, ensure_ascii=False, indent=2)
    _prune()
    return {'name': name, 'count': len(gpos)}


def _prune():
    import shutil
    names = sorted(n for n in os.listdir(BACKUP_ROOT) if _BACKUP_NAME.match(n))
    for old in names[:-MAX_BACKUPS]:
        shutil.rmtree(os.path.join(BACKUP_ROOT, old), ignore_errors=True)


def restore(base_dn, backup_name, guid):
    """Restaure une GPO depuis une sauvegarde (Restore-GPO) : ses paramètres reviennent à cet état."""
    if not _BACKUP_NAME.match(backup_name or ''):
        raise GpoError('Sauvegarde inconnue.')
    guid = norm_guid(guid)
    backup = next((b for b in list_backups() if b['name'] == backup_name), None)
    item = next((g for g in (backup or {}).get('gpos', []) if g['guid'] == guid), None)
    if not item:
        raise GpoError('Cette stratégie ne figure pas dans cette sauvegarde.')
    _run_ps({'op': 'restore', 'path': os.path.join(BACKUP_ROOT, backup_name),
             'backup_id': item['id'].strip('{}'), 'domain': _domain(base_dn)})
    return item['name']
