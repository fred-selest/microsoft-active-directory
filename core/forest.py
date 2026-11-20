"""
Forêt Active Directory vue depuis le domaine actif : domaines de la forêt,
approbations (trusts), contrôleurs de domaine, rôles FSMO, catalogues
globaux, niveaux fonctionnels. Lecture seule, en LDAP.

Quelques constats accompagnent ces informations (filtrage SID désactivé
sur une approbation externe, contrôleur de domaine en fin de support, un
seul contrôleur…) avec la même forme que core/resilience.py.
"""
import logging
from datetime import datetime, timezone

logger = logging.getLogger('forest')

# msDS-Behavior-Version / domainFunctionality / forestFunctionality
LEVELS = {0: 'Windows 2000', 1: 'Windows Server 2003 (intermédiaire)', 2: 'Windows Server 2003',
          3: 'Windows Server 2008', 4: 'Windows Server 2008 R2', 5: 'Windows Server 2012',
          6: 'Windows Server 2012 R2', 7: 'Windows Server 2016', 10: 'Windows Server 2025'}

# trustDirection
DIRECTIONS = {0: 'Désactivée', 1: 'Entrante', 2: 'Sortante', 3: 'Bidirectionnelle'}
DIRECTION_HELP = {1: 'les comptes de ce domaine peuvent accéder à l\'autre domaine',
                  2: 'les comptes de l\'autre domaine peuvent accéder à ce domaine',
                  3: 'chaque domaine peut accéder aux ressources de l\'autre'}
# trustType
TYPES = {1: 'Windows NT (ancien)', 2: 'Active Directory', 3: 'Kerberos (MIT)', 4: 'DCE'}
# trustAttributes
TA_NON_TRANSITIVE = 0x1
TA_UPLEVEL_ONLY = 0x2
TA_QUARANTINED = 0x4            # filtrage SID actif
TA_FOREST_TRANSITIVE = 0x8
TA_CROSS_ORGANIZATION = 0x10    # authentification sélective
TA_WITHIN_FOREST = 0x20
TA_TREAT_AS_EXTERNAL = 0x40
TA_RC4 = 0x80
TA_PIM = 0x400

# Rôles FSMO : (objet relatif, libellé, portée)
FSMO = [('{config}CN=Schema,', 'Maître de schéma', 'forêt'),
        ('{config}CN=Partitions,', 'Maître d\'attribution des noms de domaine', 'forêt'),
        ('{base}', 'Émulateur PDC', 'domaine'),
        ('{base}CN=RID Manager$,CN=System,', 'Maître RID', 'domaine'),
        ('{base}CN=Infrastructure,', 'Maître d\'infrastructure', 'domaine')]

UF_DISABLED = 0x2
UF_SERVER_TRUST = 0x2000
UF_PARTIAL_SECRETS = 0x4000000
DC_SILENT_DAYS = 30
OLD_OS = ('2003', '2008', '2012')


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


def _rdn(dn, index=0):
    parts = [p for p in str(dn or '').split(',') if p]
    return parts[index].split('=', 1)[-1] if len(parts) > index else ''


def _root_dse(conn):
    info = getattr(conn.server, 'info', None)
    other = getattr(info, 'other', None) or {}

    def first(name):
        value = other.get(name)
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        return str(value) if value not in (None, '') else ''
    return {'config': first('configurationNamingContext'), 'root': first('rootDomainNamingContext'),
            'default': first('defaultNamingContext'), 'schema': first('schemaNamingContext'),
            'domain_level': first('domainFunctionality'), 'forest_level': first('forestFunctionality'),
            'dc_level': first('domainControllerFunctionality'), 'dns_host': first('dnsHostName')}


def _level(value):
    if value in (None, ''):
        return {'value': None, 'label': 'Inconnu'}
    value = _int(value, -1)
    return {'value': value, 'label': LEVELS.get(value, f'Niveau {value}')}


def _config(base_dn, dse):
    return dse['config'] or 'CN=Configuration,' + ','.join(
        p for p in base_dn.split(',') if p.strip().upper().startswith('DC='))


def read(conn, base_dn):
    """Tout ce que la page Domaines affiche, lu depuis le domaine actif."""
    from ldap3 import BASE, LEVEL
    from routes.core import paged_search
    from core.ad_dates import ad_datetime, last_logon
    dse = _root_dse(conn)
    config = _config(base_dn, dse)
    notes = []

    # Domaines de la forêt (objets crossRef de type domaine : systemFlags & 2)
    domains = []
    try:
        conn.search(f'CN=Partitions,{config}', '(objectClass=crossRef)', LEVEL,
                    attributes=['nETBIOSName', 'dnsRoot', 'nCName', 'systemFlags'])
        for e in conn.entries:
            if not _int(_val(e, 'systemFlags')) & 2:
                continue
            nc = str(_val(e, 'nCName') or '')
            domains.append({'netbios': str(_val(e, 'nETBIOSName') or ''), 'dns': str(_val(e, 'dnsRoot') or '').lower(),
                            'base_dn': nc, 'root': bool(dse['root']) and nc.lower() == dse['root'].lower(),
                            'current': nc.lower() == base_dn.lower()})
    except Exception as e:
        notes.append(f'Domaines de la forêt illisibles : {e}')
    domains.sort(key=lambda d: (not d['root'], d['dns']))

    # Approbations
    trusts = []
    try:
        conn.search(f'CN=System,{base_dn}', '(objectClass=trustedDomain)', LEVEL,
                    attributes=['trustPartner', 'flatName', 'trustDirection', 'trustType', 'trustAttributes',
                                'whenCreated', 'whenChanged'])
        for e in conn.entries:
            attrs = _int(_val(e, 'trustAttributes'))
            direction, kind = _int(_val(e, 'trustDirection')), _int(_val(e, 'trustType'))
            if attrs & TA_WITHIN_FOREST:
                category = 'Dans la forêt (parent-enfant ou arborescence)'
            elif attrs & TA_FOREST_TRANSITIVE:
                category = 'Approbation de forêt'
            elif kind == 3:
                category = 'Domaine Kerberos (MIT)'
            else:
                category = 'Approbation externe'
            created = ad_datetime(getattr(e, 'whenCreated', None))
            changed = ad_datetime(getattr(e, 'whenChanged', None))
            trusts.append({'partner': str(_val(e, 'trustPartner') or ''), 'netbios': str(_val(e, 'flatName') or ''),
                           'direction': DIRECTIONS.get(direction, str(direction)), 'direction_value': direction,
                           'direction_help': DIRECTION_HELP.get(direction, ''),
                           'type': TYPES.get(kind, str(kind)), 'type_value': kind, 'category': category,
                           'attributes': attrs, 'transitive': not attrs & TA_NON_TRANSITIVE,
                           'sid_filtering': bool(attrs & TA_QUARANTINED) or bool(attrs & TA_FOREST_TRANSITIVE
                                                                                 and not attrs & TA_TREAT_AS_EXTERNAL),
                           'selective': bool(attrs & TA_CROSS_ORGANIZATION), 'within_forest': bool(attrs & TA_WITHIN_FOREST),
                           'rc4': bool(attrs & TA_RC4),
                           'created': created.strftime('%d/%m/%Y') if created else '',
                           'changed': changed.strftime('%d/%m/%Y') if changed else ''})
    except Exception as e:
        notes.append(f'Approbations illisibles : {e}')
    trusts.sort(key=lambda t: t['partner'].lower())

    # Serveurs des sites : site et catalogue global de chaque contrôleur
    sites, gc = {}, set()
    try:
        for e in paged_search(conn, f'CN=Sites,{config}', '(objectClass=nTDSDSA)', attributes=['options']):
            server = _rdn(e.entry_dn, 1).lower()
            sites[server] = _rdn(e.entry_dn, 3)
            if _int(_val(e, 'options')) & 1:
                gc.add(server)
    except Exception as e:
        notes.append(f'Sites illisibles : {e}')

    # Rôles FSMO
    roles = []
    for template, label, scope in FSMO:
        dn = (template.replace('{config}', '').replace('{base}', '') +
              (config if '{config}' in template else base_dn))
        try:
            conn.search(dn, '(objectClass=*)', BASE, attributes=['fSMORoleOwner'])
            owner = str(_val(conn.entries[0], 'fSMORoleOwner') or '') if conn.entries else ''
        except Exception:
            owner = ''
        roles.append({'role': label, 'scope': scope, 'server': _rdn(owner, 1) if owner else 'Inconnu'})

    # Contrôleurs de domaine du domaine actif
    dcs = []
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        for e in paged_search(conn, base_dn, '(objectClass=computer)',
                              attributes=['cn', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion',
                                          'userAccountControl', 'primaryGroupID', 'lastLogonTimestamp', 'lastLogon']):
            uac, primary = _int(_val(e, 'userAccountControl')), _int(_val(e, 'primaryGroupID'))
            if not (uac & (UF_SERVER_TRUST | UF_PARTIAL_SECRETS) or primary in (516, 521)):
                continue
            name = str(_val(e, 'cn') or '')
            seen = last_logon(e)
            dcs.append({'name': name, 'dns': str(_val(e, 'dNSHostName') or ''), 'os': str(_val(e, 'operatingSystem') or ''),
                        'version': str(_val(e, 'operatingSystemVersion') or ''),
                        'rodc': bool(uac & UF_PARTIAL_SECRETS) or primary == 521, 'disabled': bool(uac & UF_DISABLED),
                        'site': sites.get(name.lower(), ''), 'gc': name.lower() in gc,
                        'last_seen': seen.strftime('%d/%m/%Y') if seen else '',
                        'silent_days': (now - seen).days if seen else None,
                        'roles': [r['role'] for r in roles if r['server'].lower() == name.lower()],
                        'current': bool(dse['dns_host'])
                        and dse['dns_host'].lower() == str(_val(e, 'dNSHostName') or '').lower()})
    except Exception as e:
        notes.append(f'Contrôleurs de domaine illisibles : {e}')
    dcs.sort(key=lambda d: d['name'].lower())

    current = next((d for d in domains if d['current']), None)
    return {'base_dn': base_dn, 'dns': (current or {}).get('dns') or _dns(base_dn),
            'netbios': (current or {}).get('netbios', ''),
            'forest_root': _dns(dse['root']) if dse['root'] else '', 'connected_to': dse['dns_host'],
            'domain_level': _level(dse['domain_level']), 'forest_level': _level(dse['forest_level']),
            'domains': domains, 'trusts': trusts, 'dcs': dcs, 'roles': roles,
            'sites': sorted(set(s for s in sites.values() if s)), 'notes': notes}


def _dns(base_dn):
    return '.'.join(p.strip().split('=', 1)[1] for p in str(base_dn or '').split(',')
                    if p.strip().upper().startswith('DC=')).lower()


def _finding(key, severity, title, why, fix, items=None, count=None):
    items = items or []
    return {'key': key, 'severity': severity, 'title': title, 'why': why, 'fix': fix,
            'items': items, 'count': len(items) if count is None else count}


def findings(data):
    """Constats sur l'architecture : approbations, contrôleurs, niveaux fonctionnels."""
    out = []
    external = [t for t in data['trusts'] if not t['within_forest']]
    no_filter = [t for t in external if not t['sid_filtering'] and t['direction_value'] in (2, 3)]
    if no_filter:
        out.append(_finding(
            'trust_sid_filtering', 'high', 'Filtrage SID désactivé sur une approbation',
            'Un administrateur de l\'autre domaine peut se fabriquer des droits sur ce domaine (historique de SID '
            'falsifié) : la compromission de l\'autre domaine devient celle de celui-ci.',
            'Réactivez la quarantaine : netdom trust <ce domaine> /domain:<autre domaine> /quarantine:yes.',
            [{'name': t['partner'], 'detail': f'{t["category"]}, {t["direction"].lower()}'} for t in no_filter]))
    wide = [t for t in external if t['direction_value'] in (2, 3) and not t['selective']]
    if wide:
        out.append(_finding(
            'trust_not_selective', 'medium', 'Approbations sans authentification sélective',
            'Tous les comptes de l\'autre domaine sont considérés comme « Utilisateurs authentifiés » ici : ils '
            'accèdent à tout ce qui est ouvert à ce groupe (partages, applications).',
            'Si seuls quelques comptes doivent accéder à ce domaine, passez l\'approbation en authentification '
            'sélective et accordez « Autorisé à s\'authentifier » sur les serveurs concernés.',
            [{'name': t['partner'], 'detail': t['direction'].lower()} for t in wide]))
    rc4 = [t for t in data['trusts'] if t['rc4']]
    if rc4:
        out.append(_finding(
            'trust_rc4', 'medium', 'Approbations chiffrées en RC4',
            'RC4 est un chiffrement obsolète : les tickets échangés avec l\'autre domaine sont plus faciles à casser.',
            'Activez AES sur l\'approbation (onglet Général, « L\'autre domaine prend en charge le chiffrement '
            'AES Kerberos »).',
            [{'name': t['partner'], 'detail': ''} for t in rc4]))
    old = [d for d in data['dcs'] if any(v in d['os'] for v in OLD_OS) and not d['disabled']]
    if old:
        out.append(_finding(
            'dc_old_os', 'high', 'Contrôleurs de domaine en fin de support',
            'Ces systèmes ne reçoivent plus de correctifs de sécurité : une faille connue suffit à prendre le domaine.',
            'Installez un nouveau contrôleur sous Windows Server 2019 ou plus récent, transférez les rôles FSMO, '
            'puis rétrogradez l\'ancien (dcpromo / Uninstall-ADDSDomainController).',
            [{'name': d['name'], 'detail': d['os']} for d in old]))
    silent = [d for d in data['dcs'] if d['silent_days'] is not None and d['silent_days'] > DC_SILENT_DAYS
              and not d['disabled']]
    if silent:
        out.append(_finding(
            'dc_silent', 'high', 'Contrôleurs de domaine silencieux',
            f'Ces contrôleurs ne se sont pas manifestés depuis plus de {DC_SILENT_DAYS} jours : arrêtés, isolés du '
            'réseau, ou supprimés sans nettoyage. Les autres contrôleurs continuent d\'essayer de répliquer avec eux.',
            'Vérifiez la réplication (repadmin /replsummary). S\'ils n\'existent plus, nettoyez leurs métadonnées '
            '(ntdsutil, ou suppression de l\'objet dans « Sites et services »).',
            [{'name': d['name'], 'detail': f'dernier signe le {d["last_seen"]}'} for d in silent]))
    writable = [d for d in data['dcs'] if not d['rodc'] and not d['disabled']]
    if len(writable) == 1:
        out.append(_finding(
            'single_dc', 'medium', 'Un seul contrôleur de domaine',
            'Sa panne (ou son chiffrement) arrête toutes les ouvertures de session, et l\'annuaire ne peut être '
            'reconstruit qu\'à partir d\'une sauvegarde.',
            'Ajoutez un deuxième contrôleur de domaine, sur une autre machine physique.',
            [{'name': writable[0]['name'], 'detail': writable[0]['os']}]))
    lvl = data['domain_level']['value']
    if lvl is not None and lvl < 7:
        out.append(_finding(
            'functional_level', 'medium' if lvl < 6 else 'info',
            f'Niveau fonctionnel du domaine : {data["domain_level"]["label"]}',
            'Un niveau ancien prive le domaine de protections récentes (groupe « Protected Users », '
            'authentification Kerberos renforcée, AES par défaut).',
            'Une fois tous les contrôleurs sous Windows Server 2016 ou plus récent, relevez le niveau fonctionnel '
            '(« Domaines et approbations Active Directory » › Augmenter le niveau fonctionnel).', [], count=1))
    order = {'critical': 0, 'high': 1, 'medium': 2, 'info': 3}
    return sorted(out, key=lambda f: (order[f['severity']], f['title']))


def summary(conn, base_dn):
    """Chiffres clés d'un domaine (vue consolidée des domaines connectés)."""
    from routes.core import paged_search
    users = active = locked = 0
    for e in paged_search(conn, base_dn, '(&(objectClass=user)(objectCategory=person))',
                          attributes=['userAccountControl', 'lockoutTime']):
        users += 1
        if not _int(_val(e, 'userAccountControl'), 512) & UF_DISABLED:
            active += 1
        lock = getattr(e, 'lockoutTime', None)
        value = getattr(lock, 'value', None) if lock is not None else None
        if value not in (None, 0, '0') and not (hasattr(value, 'year') and value.year < 1700):
            locked += 1
    groups = len(paged_search(conn, base_dn, '(objectClass=group)', attributes=['cn']))
    computers, dcs = 0, 0
    for e in paged_search(conn, base_dn, '(objectClass=computer)', attributes=['userAccountControl']):
        computers += 1
        if _int(_val(e, 'userAccountControl')) & (UF_SERVER_TRUST | UF_PARTIAL_SECRETS):
            dcs += 1
    return {'users': users, 'active': active, 'disabled': users - active, 'locked': locked,
            'groups': groups, 'computers': computers, 'dcs': dcs,
            'level': _level(_root_dse(conn)['domain_level'])['label']}
