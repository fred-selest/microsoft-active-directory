"""
Boîte noire du domaine : photos de l'état de l'annuaire, comparaison et
retour en arrière.

Une photo enregistre ce qui compte pour la sécurité et l'organisation :
comptes, groupes et leurs membres, ordinateurs, unités d'organisation,
stratégies de groupe et leurs liens, droits des partages gérés. Les
attributs qui bougent tout seuls (dernière connexion…) n'y figurent pas,
pour que la comparaison de deux photos ne montre que de vrais changements.

Les objets sont suivis par leur objectGUID : un compte déplacé ou renommé
reste le même objet, et n'apparaît pas comme « supprimé puis créé ».

Les photos sont dans data/snapshots/ (compressées, 90 conservées). Elles
contiennent la liste des comptes et des droits : même sensibilité que le
journal d'audit, aucun mot de passe.
"""
import gzip
import hashlib
import json
import logging
import os
import re
import threading
from datetime import datetime

logger = logging.getLogger('domain_history')

SNAP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'snapshots')
MAX_SNAPSHOTS = 90
_NAME_RE = re.compile(r'^\d{8}-\d{6}$')
_LOCK = threading.Lock()

UF_DISABLED = 0x2
UF_DONT_EXPIRE = 0x10000

# Groupes dont un changement de membres est toujours critique (RID du
# domaine et groupes intégrés).
PRIVILEGED_RIDS = {512: 'Admins du domaine', 518: 'Administrateurs du schéma',
                   519: 'Administrateurs de l\'entreprise', 520: 'Propriétaires créateurs de la stratégie de groupe'}
PRIVILEGED_BUILTIN = {'S-1-5-32-544': 'Administrateurs', 'S-1-5-32-548': 'Opérateurs de compte',
                      'S-1-5-32-549': 'Opérateurs de serveur', 'S-1-5-32-550': 'Opérateurs d\'impression',
                      'S-1-5-32-551': 'Opérateurs de sauvegarde'}
BROAD_SIDS = {'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545'}

SECTIONS = {'users': 'Utilisateurs', 'groups': 'Groupes', 'computers': 'Ordinateurs',
            'ous': 'Unités d\'organisation', 'gpos': 'Stratégies de groupe', 'shares': 'Partages'}


class HistoryError(Exception):
    """Erreur présentable à l'utilisateur."""


# --- Collecte ----------------------------------------------------------------

def _val(entry, attr, default=None):
    if attr in entry:
        value = getattr(entry, attr).value
        return default if value in (None, [], '') else value
    return default


def _guid(entry):
    return str(_val(entry, 'objectGUID', entry.entry_dn)).strip('{}').lower()


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def collect(conn, base_dn, share_credentials=None):
    """État du domaine (dict sérialisable). Les sections illisibles sont notées."""
    from core import folders as fs
    from core import gpo as gp
    from routes.core import paged_search

    data = {'base_dn': base_dn, 'notes': [], 'users': {}, 'groups': {}, 'computers': {}, 'ous': {},
            'gpos': {}, 'shares': {}}

    for e in paged_search(conn, base_dn, '(&(objectClass=user)(objectCategory=person))',
                          attributes=['objectGUID', 'sAMAccountName', 'displayName', 'userPrincipalName',
                                      'mail', 'userAccountControl', 'adminCount']):
        uac = _int(_val(e, 'userAccountControl', 0))
        data['users'][_guid(e)] = {
            'dn': e.entry_dn, 'name': str(_val(e, 'sAMAccountName', '')),
            'display': str(_val(e, 'displayName', '') or ''), 'upn': str(_val(e, 'userPrincipalName', '') or ''),
            'mail': str(_val(e, 'mail', '') or ''), 'enabled': not uac & UF_DISABLED,
            'pwd_never_expires': bool(uac & UF_DONT_EXPIRE), 'admin': _int(_val(e, 'adminCount', 0)) == 1}

    for e in paged_search(conn, base_dn, '(objectClass=group)',
                          attributes=['objectGUID', 'sAMAccountName', 'member', 'objectSid', 'adminCount']):
        sid = fs.sid_to_str(getattr(e, 'objectSid', None)) if 'objectSid' in e else ''
        rid = _int(sid.rsplit('-', 1)[-1]) if sid else 0
        privileged = (sid in PRIVILEGED_BUILTIN or (sid.startswith('S-1-5-21-') and rid in PRIVILEGED_RIDS)
                      or _int(_val(e, 'adminCount', 0)) == 1)
        members = [str(m) for m in e.member.values] if 'member' in e else []
        data['groups'][_guid(e)] = {'dn': e.entry_dn, 'name': str(_val(e, 'sAMAccountName', '')),
                                    'privileged': bool(privileged), 'members': sorted(members, key=str.lower)}

    for e in paged_search(conn, base_dn, '(objectCategory=computer)',
                          attributes=['objectGUID', 'cn', 'operatingSystem', 'userAccountControl']):
        data['computers'][_guid(e)] = {
            'dn': e.entry_dn, 'name': str(_val(e, 'cn', '')), 'os': str(_val(e, 'operatingSystem', '') or ''),
            'enabled': not _int(_val(e, 'userAccountControl', 0)) & UF_DISABLED}

    for e in paged_search(conn, base_dn, '(|(objectClass=organizationalUnit)(objectClass=domainDNS))',
                          attributes=['objectGUID', 'name', 'gPLink', 'gPOptions']):
        data['ous'][_guid(e)] = {'dn': e.entry_dn, 'name': str(_val(e, 'name', '')),
                                 'gplink': str(_val(e, 'gPLink', '') or '').strip(),
                                 'block': _int(_val(e, 'gPOptions', 0)) & 1 == 1}

    try:
        gpos = gp.load_all(conn, base_dn)['gpos']
        for g in gpos:
            data['gpos'][g['guid']] = {
                'dn': g['dn'], 'name': g['name'], 'flags': g['flags'],
                'user_version': g['user_version'], 'computer_version': g['computer_version'],
                'filtering': sorted(f['name'] for f in g['filtering']),
                'denied': sorted(f['name'] for f in g['denied'])}
    except Exception as e:
        data['notes'].append(f'Stratégies de groupe illisibles : {e}')

    if share_credentials:
        settings = fs.get_folder_settings()
        for root in settings['roots']:
            try:
                tree = fs.rights_overview({'path': root, 'depth': settings['scan_depth'],
                                           'credentials': share_credentials})
                for folder in tree['folders']:
                    data['shares'][folder['path']] = {
                        'protected': folder['protected'],
                        'aces': sorted(f"{a['sid']}|{a['name']}|{a['type']}|{a['level']}|{a['applies']}"
                                       for a in folder['aces'] if not a['inherited'] or folder['level'] == 0)}
                if tree['truncated']:
                    data['notes'].append(f'{root} : analyse des droits interrompue à la limite de dossiers.')
            except fs.FolderError as e:
                data['notes'].append(f'Droits de {root} illisibles : {e}')
    return data


# --- Stockage ----------------------------------------------------------------

def _path(name, suffix='.json.gz'):
    if not _NAME_RE.match(name or ''):
        raise HistoryError('Photo inconnue.')
    return os.path.join(SNAP_DIR, name + suffix)


def list_snapshots():
    """Photos existantes, la plus récente d'abord (métadonnées seulement)."""
    if not os.path.isdir(SNAP_DIR):
        return []
    snaps = []
    for fname in sorted(os.listdir(SNAP_DIR), reverse=True):
        if not fname.endswith('.meta.json') or not _NAME_RE.match(fname[:15]):
            continue
        try:
            with open(os.path.join(SNAP_DIR, fname), encoding='utf-8') as f:
                meta = json.load(f)
        except (OSError, ValueError):
            continue
        meta['name'] = fname[:15]
        meta['date'] = datetime.strptime(fname[:15], '%Y%m%d-%H%M%S')
        snaps.append(meta)
    return snaps


def load(name):
    try:
        with gzip.open(_path(name), 'rt', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        raise HistoryError('Photo illisible.')


def save(data, by, events=None):
    os.makedirs(SNAP_DIR, exist_ok=True)
    name = datetime.now().strftime('%Y%m%d-%H%M%S')
    with gzip.open(_path(name), 'wt', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, separators=(',', ':'))
    events = events or []
    meta = {'by': by, 'counts': {s: len(data.get(s, {})) for s in SECTIONS},
            'changes': {sev: sum(1 for e in events if e['severity'] == sev)
                        for sev in ('critical', 'warning', 'info')},
            'notes': data.get('notes', [])}
    with open(_path(name, '.meta.json'), 'w', encoding='utf-8') as f:
        json.dump(meta, f, ensure_ascii=False)
    names = sorted(n[:15] for n in os.listdir(SNAP_DIR) if n.endswith('.meta.json'))
    for old in names[:-MAX_SNAPSHOTS]:
        for suffix in ('.json.gz', '.meta.json'):
            try:
                os.remove(os.path.join(SNAP_DIR, old + suffix))
            except OSError:
                pass
    return name


def take_snapshot(conn, base_dn, by, share_credentials=None):
    """
    Prend une photo et la compare à la précédente.

    Returns:
        (nom, événements). Une seule photo à la fois.
    """
    if not _LOCK.acquire(blocking=False):
        raise HistoryError('Une photo est déjà en cours.')
    try:
        data = collect(conn, base_dn, share_credentials)
        previous = list_snapshots()
        events = diff(load(previous[0]['name']), data) if previous else []
        return save(data, by, events), events
    finally:
        _LOCK.release()


# --- Comparaison -------------------------------------------------------------

def _event(severity, section, title, detail='', revert=None, key=''):
    ident = hashlib.sha1(f'{section}|{key}|{title}|{detail}'.encode('utf-8')).hexdigest()[:12]
    return {'id': ident, 'severity': severity, 'section': section, 'title': title, 'detail': detail,
            'revert': revert}


def _index(data):
    """{dn minuscule: (guid, nom)} de tous les objets d'une photo."""
    index = {}
    for section in ('users', 'groups', 'computers'):
        for guid, obj in data.get(section, {}).items():
            index[obj['dn'].lower()] = (guid, obj['name'])
    return index


def _members(group, index):
    """{clé stable: (dn, nom)} des membres : GUID quand l'objet est connu."""
    out = {}
    for dn in group['members']:
        guid, name = index.get(dn.lower(), (None, dn.split(',')[0].split('=', 1)[-1]))
        out[guid or dn.lower()] = (dn, name)
    return out


def _parent(dn):
    return dn.split(',', 1)[1] if ',' in dn else ''


def diff(old, new):
    """Événements séparant deux photos, les plus graves d'abord."""
    events = []
    old_index, new_index = _index(old), _index(new)

    # Utilisateurs
    for guid, user in new['users'].items():
        before = old['users'].get(guid)
        if before is None:
            events.append(_event('critical' if user['admin'] else 'info', 'users',
                                 f'Compte créé : {user["name"]}', user['dn'], key=guid))
            continue
        if before['enabled'] != user['enabled']:
            events.append(_event('warning' if user['enabled'] else 'info', 'users',
                                 f'Compte {"réactivé" if user["enabled"] else "désactivé"} : {user["name"]}',
                                 user['dn'], key=guid,
                                 revert={'op': 'set_enabled', 'dn': user['dn'], 'enabled': before['enabled']}))
        if user['admin'] and not before['admin']:
            events.append(_event('critical', 'users', f'Compte devenu privilégié : {user["name"]}',
                                 'Il est entré dans un groupe d\'administration protégé.', key=guid))
        if user['pwd_never_expires'] and not before['pwd_never_expires']:
            events.append(_event('warning', 'users', f'Mot de passe sans expiration : {user["name"]}',
                                 user['dn'], key=guid))
        if before['dn'].lower() != user['dn'].lower():
            moved = _parent(before['dn']).lower() != _parent(user['dn']).lower()
            events.append(_event('info', 'users', f'Compte {"déplacé" if moved else "renommé"} : {user["name"]}',
                                 f'{before["dn"]} → {user["dn"]}', key=guid))
        for field, label in (('upn', 'Identifiant de connexion'), ('mail', 'Adresse e-mail')):
            if before.get(field, '') != user.get(field, ''):
                events.append(_event('info', 'users', f'{label} modifié : {user["name"]}',
                                     f'{before.get(field) or "—"} → {user.get(field) or "—"}', key=guid))
    for guid, user in old['users'].items():
        if guid not in new['users']:
            events.append(_event('warning' if user['admin'] else 'info', 'users',
                                 f'Compte supprimé : {user["name"]}', user['dn'], key=guid))

    # Groupes et membres
    for guid, group in new['groups'].items():
        before = old['groups'].get(guid)
        severity = 'critical' if group['privileged'] else 'info'
        if before is None:
            events.append(_event('info', 'groups', f'Groupe créé : {group["name"]}', group['dn'], key=guid))
            added, removed = _members(group, new_index), {}
        else:
            now, then = _members(group, new_index), _members(before, old_index)
            added = {k: v for k, v in now.items() if k not in then}
            removed = {k: v for k, v in then.items() if k not in now}
        for key, (dn, name) in added.items():
            events.append(_event(severity, 'groups', f'{name} ajouté à {group["name"]}', dn, key=guid + key,
                                 revert={'op': 'remove_member', 'group': group['dn'], 'member': dn}))
        for key, (dn, name) in removed.items():
            # Remise possible si le membre existe toujours (sous son DN actuel) ;
            # un objet supprimé se restaure d'abord depuis la corbeille AD.
            known = key in {g for g, _ in old_index.values()}
            target = new_dn(new, key) if known else dn
            events.append(_event('warning' if group['privileged'] else 'info', 'groups',
                                 f'{name} retiré de {group["name"]}', dn, key=guid + key,
                                 revert={'op': 'add_member', 'group': group['dn'], 'member': target}
                                 if target else None))
    for guid, group in old['groups'].items():
        if guid not in new['groups']:
            events.append(_event('critical' if group['privileged'] else 'warning', 'groups',
                                 f'Groupe supprimé : {group["name"]}',
                                 f'{len(group["members"])} membre(s) — {group["dn"]}', key=guid))

    # Ordinateurs
    for guid, pc in new['computers'].items():
        if guid not in old['computers']:
            events.append(_event('info', 'computers', f'Ordinateur ajouté : {pc["name"]}', pc['os'], key=guid))
    for guid, pc in old['computers'].items():
        if guid not in new['computers']:
            events.append(_event('info', 'computers', f'Ordinateur supprimé : {pc["name"]}', pc['dn'], key=guid))

    # Unités d'organisation : liens de stratégies et héritage
    for guid, ou in new['ous'].items():
        before = old['ous'].get(guid)
        if before is None:
            events.append(_event('info', 'ous', f'Unité d\'organisation créée : {ou["name"]}', ou['dn'], key=guid))
            continue
        if before['gplink'] != ou['gplink']:
            events.append(_event('warning', 'ous', f'Stratégies liées modifiées sur {ou["name"]}',
                                 _links_text(before['gplink'], ou['gplink'], old, new), key=guid,
                                 revert={'op': 'set_gplink', 'dn': ou['dn'], 'value': before['gplink']}))
        if before['block'] != ou['block']:
            events.append(_event('warning', 'ous',
                                 f'Héritage des stratégies {"bloqué" if ou["block"] else "rétabli"} sur {ou["name"]}',
                                 ou['dn'], key=guid,
                                 revert={'op': 'set_block', 'dn': ou['dn'], 'block': before['block']}))
    for guid, ou in old['ous'].items():
        if guid not in new['ous']:
            events.append(_event('warning', 'ous', f'Unité d\'organisation supprimée : {ou["name"]}',
                                 ou['dn'], key=guid))

    # Stratégies de groupe
    for guid, gpo in new['gpos'].items():
        before = old['gpos'].get(guid)
        if before is None:
            events.append(_event('warning', 'gpos', f'Stratégie créée : {gpo["name"]}', guid, key=guid))
            continue
        if (before['user_version'], before['computer_version']) != (gpo['user_version'], gpo['computer_version']):
            events.append(_event('warning', 'gpos', f'Paramètres modifiés : {gpo["name"]}',
                                 'Restaurable depuis une sauvegarde des stratégies.', key=guid,
                                 revert={'op': 'gpo_restore', 'guid': guid}))
        if before['flags'] != gpo['flags']:
            events.append(_event('warning', 'gpos', f'État changé : {gpo["name"]}', '', key=guid,
                                 revert={'op': 'set_gpo_flags', 'guid': guid, 'flags': before['flags']}))
        if before['filtering'] != gpo['filtering'] or before['denied'] != gpo['denied']:
            events.append(_event('warning', 'gpos', f'Filtrage de sécurité modifié : {gpo["name"]}',
                                 f'{", ".join(before["filtering"]) or "personne"} → '
                                 f'{", ".join(gpo["filtering"]) or "personne"}', key=guid))
    for guid, gpo in old['gpos'].items():
        if guid not in new['gpos']:
            events.append(_event('critical', 'gpos', f'Stratégie supprimée : {gpo["name"]}',
                                 'Restaurable depuis une sauvegarde des stratégies.', key=guid))

    # Droits des partages (seulement si les deux photos les contiennent)
    if old.get('shares') and new.get('shares'):
        for path, folder in new['shares'].items():
            before = old['shares'].get(path)
            if before is None:
                continue                      # nouveau dossier aux droits propres : signalé par ses droits
            added = [a for a in folder['aces'] if a not in before['aces']]
            removed = [a for a in before['aces'] if a not in folder['aces']]
            for ace in added:
                sid, name, kind, level, _ = ace.split('|', 4)
                broad = sid in BROAD_SIDS and kind == 'Autoriser' and level in ('Modification', 'Contrôle total')
                events.append(_event('critical' if broad else 'warning', 'shares',
                                     f'Droit ajouté sur {path}',
                                     f'{name} : {"refus " if kind == "Refuser" else ""}{level}'
                                     + (' — ouvert à tous les comptes' if broad else ''),
                                     key=path + ace, revert={'op': 'folder', 'path': path}))
            for ace in removed:
                _, name, kind, level, _ = ace.split('|', 4)
                events.append(_event('warning', 'shares', f'Droit retiré sur {path}', f'{name} : {level}',
                                     key=path + ace, revert={'op': 'folder', 'path': path}))
            if before['protected'] != folder['protected']:
                events.append(_event('warning', 'shares',
                                     f'Héritage {"coupé" if folder["protected"] else "rétabli"} sur {path}', '',
                                     key=path, revert={'op': 'folder', 'path': path}))

    order = {'critical': 0, 'warning': 1, 'info': 2}
    events.sort(key=lambda e: (order[e['severity']], e['section'], e['title'].lower()))
    return events


def new_dn(data, key):
    """DN actuel d'un objet connu par son GUID dans une photo."""
    for section in ('users', 'groups', 'computers'):
        if key in data.get(section, {}):
            return data[section][key]['dn']
    return None


def _links_text(before, after, old, new):
    from core.gpo import parse_gplink

    def names(raw, data):
        return [data['gpos'].get(g, {}).get('name', g) for _, g, _ in parse_gplink(raw)]
    then, now = names(before, old), names(after, new)
    added = [n for n in now if n not in then]
    removed = [n for n in then if n not in now]
    parts = []
    if added:
        parts.append('liée : ' + ', '.join(added))
    if removed:
        parts.append('déliée : ' + ', '.join(removed))
    return ' ; '.join(parts) or 'ordre ou options des liens modifiés'


# --- Retour en arrière -------------------------------------------------------

REVERT_LABELS = {'remove_member': 'Retirer du groupe', 'add_member': 'Remettre dans le groupe',
                 'set_enabled': 'Rétablir l\'état du compte', 'set_gplink': 'Rétablir les liens',
                 'set_block': 'Rétablir l\'héritage', 'set_gpo_flags': 'Rétablir l\'état',
                 'gpo_restore': 'Voir les sauvegardes', 'folder': 'Ouvrir le dossier'}
# Opérations exécutées par l'application ; les autres renvoient vers la page
# qui permet de corriger (restauration de GPO, droits d'un dossier).
DIRECT_REVERTS = {'remove_member', 'add_member', 'set_enabled', 'set_gplink', 'set_block', 'set_gpo_flags'}


def revert(conn, base_dn, old_name, new_name, event_id):
    """
    Annule un changement constaté entre deux photos.

    L'opération est recalculée côté serveur à partir des photos : le
    navigateur ne fournit que l'identifiant de l'événement.
    """
    from ldap3 import BASE, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
    from core import gpo as gp
    events = diff(load(old_name), load(new_name))
    event = next((e for e in events if e['id'] == event_id), None)
    if not event or not event['revert'] or event['revert']['op'] not in DIRECT_REVERTS:
        raise HistoryError('Ce changement ne peut pas être annulé automatiquement.')
    spec = event['revert']
    op = spec['op']
    for key in ('dn', 'group', 'member'):
        if key in spec and not spec[key].lower().endswith(base_dn.lower()):
            raise HistoryError('Objet hors du domaine.')

    if op in ('remove_member', 'add_member'):
        conn.modify(spec['group'], {'member': [(MODIFY_DELETE if op == 'remove_member' else MODIFY_ADD,
                                                 [spec['member']])]})
    elif op == 'set_enabled':
        conn.search(spec['dn'], '(objectClass=user)', BASE, attributes=['userAccountControl'])
        if not conn.entries:
            raise HistoryError('Compte introuvable.')
        uac = _int(conn.entries[0].userAccountControl.value)
        uac = uac & ~UF_DISABLED if spec['enabled'] else uac | UF_DISABLED
        conn.modify(spec['dn'], {'userAccountControl': [(MODIFY_REPLACE, [uac])]})
    elif op == 'set_gplink':
        conn.modify(spec['dn'], {'gPLink': [(MODIFY_REPLACE, [spec['value']] if spec['value'] else [])]})
    elif op == 'set_block':
        conn.modify(spec['dn'], {'gPOptions': [(MODIFY_REPLACE, [1 if spec['block'] else 0])]})
    elif op == 'set_gpo_flags':
        try:
            gp.set_status(conn, base_dn, spec['guid'], spec['flags'])
        except gp.GpoError as e:
            raise HistoryError(str(e))
        return event
    if conn.result.get('result') != 0:
        raise HistoryError('Annulation impossible : '
                           f'{conn.result.get("message") or conn.result.get("description") or "erreur LDAP"}')
    return event


# --- Alerte ------------------------------------------------------------------

def notify(events, name):
    """Envoie par e-mail le résumé des changements critiques. Renvoie True si envoyé."""
    from core.mailer import MailError, default_recipient, is_configured, send_mail
    critical = [e for e in events if e['severity'] == 'critical']
    if not critical or not is_configured() or not default_recipient():
        return False
    lines = [f'- {e["title"]}' + (f' ({e["detail"]})' if e['detail'] else '') for e in critical[:40]]
    warnings = sum(1 for e in events if e['severity'] == 'warning')
    text = (f'{len(critical)} changement(s) critique(s) détecté(s) dans le domaine '
            f'(photo du {datetime.strptime(name, "%Y%m%d-%H%M%S").strftime("%d/%m/%Y %H:%M")}) :\n\n'
            + '\n'.join(lines) + f'\n\n{warnings} autre(s) changement(s) à vérifier.\n'
            'Détail et annulation : menu Administration › Journal du domaine.\n')
    try:
        send_mail(default_recipient(), f'[AD] {len(critical)} changement(s) critique(s) dans le domaine', text)
        return True
    except MailError as e:
        logger.warning('Alerte de changements non envoyée : %s', e)
        return False
