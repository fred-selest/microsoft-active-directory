"""
Droits NTFS des répertoires partagés.

Toutes les opérations sur les fichiers passent par un script PowerShell
unique (PS_SCRIPT), exécuté sur le serveur de l'application :

- Sous l'identité de l'administrateur connecté, et non du service
  (LocalSystem) : le script ouvre le partage avec New-PSDrive -Credential.
  Les droits NTFS réels de cet administrateur s'appliquent : l'interface ne
  permet rien qu'il ne pourrait faire depuis l'explorateur Windows.
- Les paramètres (chemins, SID, mot de passe) passent en JSON sur l'entrée
  standard, jamais dans le texte du script ni sur la ligne de commande :
  aucune valeur saisie ne peut devenir du code PowerShell, et le mot de passe
  n'apparaît pas dans la liste des processus.
- Seuls les chemins situés sous une racine déclarée dans les paramètres
  (folders.roots, folders.home_root) sont acceptés.

Les identités sont toujours transmises par SID, lus dans l'AD : un groupe
tout juste créé n'est pas encore connu du serveur de fichiers par son nom
(réplication), mais son SID est utilisable immédiatement.
"""
import json
import logging
import os
import re
import subprocess

logger = logging.getLogger('folders')

PS_TIMEOUT = 60
SCAN_TIMEOUT = 300
MAX_SCAN_FOLDERS = 5000

# --- Niveaux de droits -------------------------------------------------------

# Valeurs de System.Security.AccessControl.FileSystemRights
FULL_CONTROL = 0x1F01FF
MODIFY = 0x1301BF
READ_AND_EXECUTE = 0x1200A9
READ = 0x120089
WRITE = 0x116

# Droits génériques (ACE héritables de CREATOR OWNER, etc.)
GENERIC_ALL = 0x10000000
GENERIC_EXECUTE = 0x20000000
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000

LEVELS = {
    'read': {'label': 'Lecture et exécution', 'rights': READ_AND_EXECUTE},
    'modify': {'label': 'Modification', 'rights': MODIFY},
    'full': {'label': 'Contrôle total', 'rights': FULL_CONTROL},
}

APPLIES = {
    'all': 'Ce dossier, les sous-dossiers et les fichiers',
    'this': 'Ce dossier seulement',
}

# InheritanceFlags : ContainerInherit = 1, ObjectInherit = 2
# PropagationFlags : InheritOnly = 2

WELL_KNOWN_SIDS = {
    'S-1-1-0': 'Tout le monde',
    'S-1-3-0': 'CREATEUR PROPRIETAIRE',
    'S-1-5-11': 'Utilisateurs authentifiés',
    'S-1-5-18': 'Système',
    'S-1-5-32-544': 'Administrateurs (local)',
    'S-1-5-32-545': 'Utilisateurs (local)',
}


def _expand_generic(rights):
    """Remplace les droits génériques par leur équivalent fichier."""
    rights = int(rights) & 0xFFFFFFFF
    if rights & GENERIC_ALL:
        rights |= FULL_CONTROL
    if rights & GENERIC_READ:
        rights |= READ
    if rights & GENERIC_WRITE:
        rights |= WRITE | 0x100000
    if rights & GENERIC_EXECUTE:
        rights |= 0x1200A0
    return rights & 0x0FFFFFFF


def rights_label(rights):
    """Libellé lisible d'un masque FileSystemRights."""
    rights = _expand_generic(rights)
    for value, label in ((FULL_CONTROL, 'Contrôle total'), (MODIFY, 'Modification'),
                         (READ_AND_EXECUTE, 'Lecture et exécution'), (READ, 'Lecture'),
                         (WRITE, 'Écriture')):
        if rights & value == value:
            return label
    return 'Spéciale'


def applies_label(inheritance, propagation):
    inheritance, propagation = int(inheritance or 0), int(propagation or 0)
    folders, files = bool(inheritance & 1), bool(inheritance & 2)
    only = bool(propagation & 2)
    if not folders and not files:
        return 'Ce dossier seulement'
    target = ('les sous-dossiers et les fichiers' if folders and files
              else 'les sous-dossiers' if folders else 'les fichiers')
    return f'{target.capitalize()} seulement' if only else f'Ce dossier, {target}'


# --- Chemins -----------------------------------------------------------------

_SEGMENT = r'[^\\/:*?"<>|\x00-\x1f]+'
_UNC_RE = re.compile(r'^\\\\([A-Za-z0-9][A-Za-z0-9.-]{0,252})\\(' + _SEGMENT + r')((?:\\' + _SEGMENT + r')*)$')
_NAME_RE = re.compile(r'^' + _SEGMENT + r'$')


class FolderError(Exception):
    """Erreur présentable à l'utilisateur."""


def normalize_unc(path):
    """
    Chemin UNC normalisé (\\\\serveur\\partage\\...), ou FolderError.

    Refuse les chemins locaux (C:\\...), les composants « . » et « .. » et
    les caractères interdits par Windows.
    """
    path = (path or '').strip().replace('/', '\\').rstrip('\\')
    match = _UNC_RE.match(path)
    if not match:
        raise FolderError('Chemin invalide : utilisez un chemin réseau \\\\serveur\\partage\\dossier.')
    parts = path[2:].split('\\')
    for part in parts:
        if part.strip() in ('.', '..') or part != part.rstrip(' .'):
            raise FolderError('Chemin invalide : composant « . », « .. » ou terminé par un point.')
    return path


def share_root(path):
    """\\\\serveur\\partage d'un chemin UNC normalisé."""
    parts = path[2:].split('\\')
    return '\\\\' + parts[0] + '\\' + parts[1]


def is_under(path, root):
    """path est-il root ou un de ses sous-dossiers (insensible à la casse) ?"""
    path, root = path.lower(), root.lower().rstrip('\\')
    return path == root or path.startswith(root + '\\')


def validate_folder_name(name):
    name = (name or '').strip()
    if not name or len(name) > 120 or not _NAME_RE.match(name) or name in ('.', '..') \
            or name != name.rstrip(' .'):
        raise FolderError('Nom de dossier invalide (caractères interdits : \\ / : * ? " < > |).')
    return name


# --- Paramètres --------------------------------------------------------------

def get_folder_settings():
    from core.settings_manager import load_settings
    raw = load_settings().get('folders') or {}   # une seule lecture du fichier

    def get_setting(path, default=None):
        value = raw.get(path.split('.', 1)[1], default)
        return default if value is None else value

    roots = get_setting('folders.roots', []) or []
    clean = []
    for root in roots:
        try:
            clean.append(normalize_unc(root))
        except FolderError:
            continue
    home_root = get_setting('folders.home_root', '') or ''
    try:
        home_root = normalize_unc(home_root) if home_root else ''
    except FolderError:
        home_root = ''
    drive = (get_setting('folders.home_drive', 'H:') or 'H:').strip().upper()
    if not re.match(r'^[D-Z]:$', drive):
        drive = 'H:'
    try:
        depth = max(1, min(int(get_setting('folders.scan_depth', 3) or 3), 6))
    except (TypeError, ValueError):
        depth = 3
    return {'roots': clean, 'home_root': home_root, 'home_drive': drive, 'scan_depth': depth}


def save_folder_settings(roots_text, home_root, home_drive, scan_depth):
    """Valide et enregistre les paramètres. Lève FolderError."""
    from core.settings_manager import set_setting
    roots = []
    for line in (roots_text or '').replace('\r', '').split('\n'):
        if line.strip():
            root = normalize_unc(line)
            if root.lower() not in [r.lower() for r in roots]:
                roots.append(root)
    home_root = normalize_unc(home_root) if (home_root or '').strip() else ''
    drive = (home_drive or 'H:').strip().upper()
    if len(drive) == 1:
        drive += ':'
    if not re.match(r'^[D-Z]:$', drive):
        raise FolderError('Lettre de lecteur invalide (D: à Z:).')
    try:
        depth = int(scan_depth)
    except (TypeError, ValueError):
        raise FolderError('Profondeur d\'analyse invalide.')
    if not 1 <= depth <= 6:
        raise FolderError('La profondeur d\'analyse doit être comprise entre 1 et 6.')
    set_setting('folders.roots', roots)
    set_setting('folders.home_root', home_root)
    set_setting('folders.home_drive', drive)
    set_setting('folders.scan_depth', depth)
    return get_folder_settings()


def check_allowed(path, roots=None, extra_roots=()):
    """Normalise path et vérifie qu'il est sous une racine autorisée."""
    path = normalize_unc(path)
    settings = get_folder_settings()
    allowed = list(roots if roots is not None else settings['roots']) + list(extra_roots)
    for root in sorted(allowed, key=len, reverse=True):
        if is_under(_short_host(path), _short_host(root)):
            # Même serveur nommé autrement (SRV-FIC / srv-fic.corp.local) :
            # le chemin reprend l'écriture de la racine déclarée.
            depth = len(root.rstrip('\\').split('\\'))
            rest = path.split('\\')[depth:]
            return root.rstrip('\\') + ''.join('\\' + part for part in rest)
    raise FolderError('Ce chemin n\'est pas sous une racine autorisée (voir Paramètres des répertoires).')


# --- Exécution PowerShell ----------------------------------------------------

PS_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'scripts', 'folders.ps1')
# Le script est un fichier (scripts/folders.ps1) exécuté avec -File : passé
# en -EncodedCommand, il approchait la limite de 32 767 caractères de la
# ligne de commande Windows.
with open(PS_SCRIPT_PATH, encoding='utf-8-sig') as _f:
    PS_SCRIPT = _f.read()


def _friendly_error(message):
    text = message or ''
    low = text.lower()
    if '1219' in text or 'multiple connections' in low or 'connexions multiples' in low:
        return ('Le serveur a déjà une connexion ouverte avec un autre compte. '
                'Réessayez dans quelques instants.')
    if 'access' in low and 'denied' in low or 'accès refusé' in low or 'unauthorizedaccess' in low:
        return 'Accès refusé : votre compte n\'a pas les droits nécessaires sur ce dossier.'
    if 'cannot find path' in low or 'introuvable' in low or 'does not exist' in low:
        return 'Dossier introuvable.'
    if 'network path' in low or 'chemin réseau' in low:
        return 'Serveur ou partage injoignable.'
    return text[:300] or 'Erreur inconnue.'


def run_ps(request_data, timeout=PS_TIMEOUT):
    """
    Exécute PS_SCRIPT avec request_data (dict) sur l'entrée standard.

    Returns:
        dict: la réponse du script (clé 'ok').
    Raises:
        FolderError en cas d'échec.
    """
    if os.name != 'nt':
        raise FolderError('La gestion des répertoires nécessite que l\'application tourne sous Windows.')
    try:
        proc = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
             '-File', PS_SCRIPT_PATH],
            input=json.dumps(request_data), capture_output=True, text=True,
            encoding='utf-8', errors='replace', timeout=timeout)
    except subprocess.TimeoutExpired:
        raise FolderError('L\'opération a dépassé le délai imparti.')
    except OSError as e:
        raise FolderError(f'PowerShell introuvable : {e}')
    stdout = (proc.stdout or '').strip().lstrip('\ufeff')
    try:
        result = json.loads(stdout[stdout.find('{'):]) if '{' in stdout else None
    except ValueError:
        result = None
    if not isinstance(result, dict):
        logger.error('Réponse PowerShell illisible (code %s) : %s', proc.returncode,
                     (proc.stderr or stdout)[:500])
        raise FolderError(_friendly_error(proc.stderr or stdout))
    if not result.get('ok'):
        raise FolderError(_friendly_error(result.get('error')))
    return result


def _credentials():
    """Identifiants de l'administrateur connecté (DOMAINE\\compte ou UPN)."""
    from flask import session
    from core.session_crypto import decrypt_password
    username = session.get('ad_username', '')
    password = decrypt_password(session.get('ad_password'))
    if '\\' not in username and '@' not in username:
        # Nom implicite user@domaine.dns : seuls les composants DC= de la
        # base comptent (une base limitée à une OU, OU=Paris,DC=corp,…,
        # donnait « Paris.corp.local »).
        base_dn = session.get('ad_base_dn', '')
        domain = '.'.join(p.strip().split('=', 1)[1] for p in base_dn.split(',')
                          if p.strip().upper().startswith('DC='))
        if domain:
            username = f'{username}@{domain}'
    return username, password


def _call(op, timeout=PS_TIMEOUT, credentials=None, **params):
    user, password = credentials or _credentials()
    data = {'op': op, 'user': user, 'password': password}
    data.update(params)
    return run_ps(data, timeout=timeout)


def _format_aces(aces):
    rows = []
    for ace in aces or []:
        sid = ace.get('sid', '')
        name = ace.get('name') or sid
        if name == sid and sid in WELL_KNOWN_SIDS:
            name = WELL_KNOWN_SIDS[sid]
        rows.append({
            'sid': sid, 'name': name,
            'level': rights_label(ace.get('rights', 0)),
            'type': 'Refuser' if ace.get('type') == 'Deny' else 'Autoriser',
            'deny': ace.get('type') == 'Deny',
            'inherited': bool(ace.get('inherited')),
            'applies': applies_label(ace.get('inheritance'), ace.get('propagation')),
            'path': ace.get('path', ''),
        })
    return rows


# --- Opérations --------------------------------------------------------------

def get_folder(path):
    """ACL et sous-dossiers d'un dossier autorisé."""
    path = check_allowed(path)
    result = _call('acl', path=path)
    aces = _format_aces(result.get('aces'))
    aces.sort(key=lambda a: (a['inherited'], not a['deny'], a['name'].lower()))
    return {'path': path, 'aces': aces, 'owner': result.get('owner') or '',
            'protected': bool(result.get('protected')),
            'children': list(result.get('children') or [])}


def grant(path, sid, level, applies='all'):
    path = check_allowed(path)
    if level not in LEVELS:
        raise FolderError('Niveau de droits invalide.')
    if applies not in APPLIES:
        raise FolderError('Portée invalide.')
    _call('grant', path=path, sid=_check_sid(sid), rights=LEVELS[level]['rights'],
          applies=applies)
    return path


def revoke(path, sid):
    path = check_allowed(path)
    _call('revoke', path=path, sid=_check_sid(sid))
    return path


def create_folder(parent, name, grants, protect=False, extra_roots=(), allow_existing=False,
                  reset=False):
    """
    Crée parent\\name et y ajoute les droits [(sid, level)].

    protect : coupe l'héritage, ne garde que Administrateurs, Système et les
    droits demandés. reset (avec protect, sur un dossier existant) : retire
    aussi les droits explicites déjà posés.
    """
    parent = check_allowed(parent, extra_roots=extra_roots)
    path = parent + '\\' + validate_folder_name(name)
    grant_list = []
    for sid, level in grants:
        if level not in LEVELS:
            raise FolderError('Niveau de droits invalide.')
        grant_list.append({'sid': _check_sid(sid), 'rights': LEVELS[level]['rights']})
    result = _call('mkdir', path=path, grants=grant_list, protect=bool(protect),
                   allow_existing=bool(allow_existing), reset=bool(reset and protect))
    return {'path': path, 'existed': bool(result.get('existed'))}


def prepare_scan(sids):
    """
    Paramètres d'une analyse d'accès, préparés pendant la requête HTTP
    (paramètres, identifiants de session) pour pouvoir l'exécuter ensuite
    hors requête, dans un thread.
    """
    settings = get_folder_settings()
    roots = settings['roots']
    if not roots:
        raise FolderError('Aucune racine déclarée dans les paramètres des répertoires.')
    return {'roots': roots, 'sids': sorted({_check_sid(s) for s in sids}),
            'depth': settings['scan_depth'], 'credentials': _credentials()}


def scan_access(prepared):
    """
    Dossiers où l'un des SID a un droit, sous les racines autorisées.

    Racines : droits explicites et hérités ; sous-dossiers : explicites.
    """
    result = _call('scan', timeout=SCAN_TIMEOUT, credentials=prepared['credentials'],
                   roots=prepared['roots'], sids=prepared['sids'], depth=prepared['depth'],
                   max_folders=MAX_SCAN_FOLDERS)
    found = _format_aces(result.get('found'))
    found.sort(key=lambda a: (a['path'].lower(), a['name'].lower()))
    return {'found': found, 'errors': list(result.get('errors') or [])[:50],
            'scanned': result.get('scanned', 0), 'truncated': bool(result.get('truncated')),
            'roots': prepared['roots']}


# --- Analyses en arrière-plan ------------------------------------------------
#
# Une analyse peut durer plusieurs minutes : la faire dans la requête HTTP
# bloquait un thread du serveur et dépassait le délai des navigateurs et
# proxys (« le serveur n'a pas répondu » alors que PowerShell tournait
# encore). Elle tourne dans un thread ; la page interroge son état.

import threading  # noqa: E402
import time  # noqa: E402
import uuid  # noqa: E402

_JOBS = {}
_JOBS_LOCK = threading.Lock()
JOB_TTL = 3600
MAX_RUNNING_JOBS = 2


def _purge_jobs(now):
    for job_id in [j for j, job in _JOBS.items() if now - job['created'] > JOB_TTL]:
        del _JOBS[job_id]


CACHE_TTL = 600


def start_job(owner, key, func, decorate=None, refresh=False):
    """
    Lance func() dans un thread et renvoie l'identifiant de la tâche.

    owner : identifiant de l'administrateur (seul lui peut lire le résultat).
    key : une même analyse (même compte, même dossier) relancée dans les
    CACHE_TTL secondes réutilise la tâche en cours ou son résultat, sauf
    refresh. decorate(result) complète le résultat.
    """
    now = time.time()
    with _JOBS_LOCK:
        _purge_jobs(now)
        if not refresh:
            for job_id, job in _JOBS.items():
                if (job['owner'] == owner and job.get('key') == key and
                        (job['status'] == 'running' or
                         (job['status'] == 'done' and now - job['finished'] < CACHE_TTL))):
                    return job_id
        running = [j for j in _JOBS.values() if j['status'] == 'running']
        if len(running) >= MAX_RUNNING_JOBS:
            raise FolderError('Trop d\'analyses en cours : réessayez quand l\'une d\'elles sera terminée.')
        job_id = uuid.uuid4().hex
        _JOBS[job_id] = {'owner': owner, 'key': key, 'status': 'running', 'created': now,
                         'finished': None, 'result': None, 'error': None}

    def work():
        try:
            result = func()
            if decorate:
                decorate(result)
            update = {'status': 'done', 'result': result}
        except FolderError as e:
            update = {'status': 'error', 'error': str(e)}
        except Exception:
            logger.exception('Analyse des répertoires interrompue')
            update = {'status': 'error', 'error': 'Erreur inattendue pendant l\'analyse.'}
        update['finished'] = time.time()
        with _JOBS_LOCK:
            if job_id in _JOBS:
                _JOBS[job_id].update(update)

    threading.Thread(target=work, name=f'folder-job-{job_id[:8]}', daemon=True).start()
    return job_id


def start_scan_job(owner, prepared, decorate=None, key=None, refresh=False):
    """Analyse des accès (scan_access) en arrière-plan."""
    def func():
        try:
            return scan_access(prepared)
        finally:
            prepared.pop('credentials', None)  # ne pas garder le mot de passe en mémoire
    return start_job(owner, key or uuid.uuid4().hex, func, decorate, refresh)


def get_scan_job(job_id, owner):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job or job['owner'] != owner:
            return None
        return dict(job)


# --- Découverte et vue d'ensemble -------------------------------------------

_HOST_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$')

STYPE_DISKTREE = 0
STYPE_SPECIAL = 0x80000000


def list_servers(conn, base_dn):
    """Serveurs Windows du domaine (comptes ordinateur actifs, système « Server »)."""
    from routes.core import paged_search
    entries = paged_search(conn, base_dn,
                           '(&(objectCategory=computer)(operatingSystem=*Server*)'
                           '(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                           attributes=['cn', 'dNSHostName', 'operatingSystem'])
    servers = []
    for e in entries:
        host = str(getattr(getattr(e, 'dNSHostName', None), 'value', '') or
                   getattr(getattr(e, 'cn', None), 'value', '') or '')
        if host:
            servers.append({'name': str(e.cn.value), 'host': host.lower(),
                            'os': str(getattr(getattr(e, 'operatingSystem', None), 'value', '') or '')})
    return sorted(servers, key=lambda x: x['name'].lower())


def _short_host(unc):
    """\\\\SRV.corp.local\\Partage → \\\\srv\\partage : un même serveur peut être déclaré
    par son nom court ou son nom DNS complet."""
    host, _, rest = unc[2:].partition('\\')
    return ('\\\\' + host.split('.', 1)[0] + '\\' + rest).lower()


def list_shares(server):
    """
    Partages disque d'un serveur (sans les partages administratifs C$,
    ADMIN$… ni IPC$), avec leur chemin réseau et s'ils sont déjà gérés.
    """
    server = (server or '').strip()
    if not _HOST_RE.match(server):
        raise FolderError('Nom de serveur invalide.')
    result = _call('shares', server=server)
    managed = [_short_host(r) for r in get_folder_settings()['roots']]
    shares = []
    for sh in result.get('shares') or []:
        stype = int(sh.get('type') or 0)
        if stype & 0xFF != STYPE_DISKTREE or stype & STYPE_SPECIAL or sh.get('name', '').endswith('$'):
            continue
        unc = f'\\\\{server}\\{sh["name"]}'
        try:
            unc = normalize_unc(unc)
        except FolderError:
            continue
        shares.append({'name': sh['name'], 'remark': sh.get('remark') or '', 'path': unc,
                       'managed': any(is_under(_short_host(unc), r) for r in managed)})
    return sorted(shares, key=lambda x: x['name'].lower())


def add_root(path):
    """Ajoute path aux partages gérés (sans doublon)."""
    from core.settings_manager import set_setting
    path = normalize_unc(path)
    settings = get_folder_settings()
    if path.lower() not in [r.lower() for r in settings['roots']]:
        set_setting('folders.roots', settings['roots'] + [path])
    return path


def prepare_overview(path, depth=None):
    """Paramètres d'une vue d'ensemble, préparés pendant la requête HTTP."""
    settings = get_folder_settings()
    return {'path': check_allowed(path), 'depth': max(1, min(int(depth or settings['scan_depth']), 6)),
            'credentials': _credentials()}


def rights_overview(prepared):
    """
    Droits explicites de chaque dossier d'une arborescence (et tous ceux de
    la racine), plus la liste des comptes et groupes qui y apparaissent.
    """
    try:
        result = _call('tree', timeout=SCAN_TIMEOUT, credentials=prepared['credentials'],
                       path=prepared['path'], depth=prepared['depth'], max_folders=MAX_SCAN_FOLDERS)
    finally:
        prepared.pop('credentials', None)
    folders, principals = [], {}
    for f in result.get('folders') or []:
        aces = _format_aces(f.get('aces'))
        aces.sort(key=lambda a: (a['inherited'], not a['deny'], a['name'].lower()))
        rel = f['path'][len(prepared['path']):].lstrip('\\') or '.'
        folders.append({'path': f['path'], 'rel': rel, 'level': int(f.get('level') or 0),
                        'protected': bool(f.get('protected')), 'aces': aces})
        for a in aces:
            p = principals.setdefault(a['sid'], {'sid': a['sid'], 'name': a['name'], 'folders': 0})
            p['folders'] += 1
    folders.sort(key=lambda f: f['path'].lower())
    return {'path': prepared['path'], 'depth': prepared['depth'], 'folders': folders,
            'principals': sorted(principals.values(), key=lambda p: (-p['folders'], p['name'].lower())),
            'errors': list(result.get('errors') or [])[:50], 'scanned': result.get('scanned', 0),
            'truncated': bool(result.get('truncated'))}


_SID_RE = re.compile(r'^S-1-\d+(-\d+){1,14}$')


def _check_sid(sid):
    sid = (sid or '').strip()
    if not _SID_RE.match(sid):
        raise FolderError('Identité invalide.')
    return sid


# --- AD : SID et groupes -----------------------------------------------------

def sid_to_str(value):
    """SID binaire ou texte (attribut objectSid) en chaîne S-1-…"""
    value = getattr(value, 'value', value)
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if isinstance(value, str):
        return value if value.startswith('S-1-') else ''
    if not isinstance(value, (bytes, bytearray)) or len(value) < 8:
        return ''
    revision, count = value[0], value[1]
    authority = int.from_bytes(value[2:8], 'big')
    subs = [int.from_bytes(value[8 + 4 * i:12 + 4 * i], 'little') for i in range(count)]
    return 'S-%d-%d' % (revision, authority) + ''.join('-%d' % s for s in subs)


def resolve_principal(conn, base_dn, dn):
    """
    SID d'un compte ou d'un groupe et de tous les groupes dont il est membre
    (directement, par imbrication ou comme groupe principal).

    Returns:
        dict: name, sid, kind ('user'/'group'), sids {sid: libellé}.
    """
    from ldap3 import BASE
    from ldap3.utils.conv import escape_filter_chars
    from routes.core import paged_search

    conn.search(dn, '(objectClass=*)', BASE,
                attributes=['objectSid', 'objectClass', 'cn', 'sAMAccountName', 'primaryGroupID'])
    if not conn.entries:
        raise FolderError('Compte ou groupe introuvable.')
    entry = conn.entries[0]
    sid = sid_to_str(getattr(entry, 'objectSid', None))
    if not sid:
        raise FolderError('SID introuvable pour cet objet.')
    classes = [str(c).lower() for c in (getattr(entry, 'objectClass', None).values
                                        if getattr(entry, 'objectClass', None) is not None else [])]
    kind = 'group' if 'group' in classes else 'user'
    name = str(getattr(getattr(entry, 'sAMAccountName', None), 'value', '') or
               getattr(getattr(entry, 'cn', None), 'value', '') or dn)

    sids = {sid: name}
    # 1.2.840.113556.1.4.1941 : LDAP_MATCHING_RULE_IN_CHAIN (imbrication)
    groups = paged_search(conn, base_dn,
                          f'(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={escape_filter_chars(dn)}))',
                          attributes=['objectSid', 'cn'])
    for group in groups:
        gsid = sid_to_str(getattr(group, 'objectSid', None))
        if gsid:
            sids[gsid] = str(getattr(getattr(group, 'cn', None), 'value', '') or gsid)

    if kind == 'user':
        primary = getattr(getattr(entry, 'primaryGroupID', None), 'value', None)
        if primary:
            domain_sid = sid.rsplit('-', 1)[0]
            psid = f'{domain_sid}-{int(primary)}'
            if psid not in sids:
                sids[psid] = 'Groupe principal (Utilisateurs du domaine)'
                for group in paged_search(conn, base_dn,
                                          f'(&(objectClass=group)(objectSid={escape_filter_chars(psid)}))',
                                          attributes=['cn']):
                    sids[psid] = str(group.cn.value)
                    # Groupes contenant le groupe principal (Builtin\Utilisateurs…)
                    for parent in paged_search(
                            conn, base_dn,
                            f'(&(objectClass=group)(member:1.2.840.113556.1.4.1941:='
                            f'{escape_filter_chars(group.entry_dn)}))',
                            attributes=['objectSid', 'cn']):
                        ps = sid_to_str(getattr(parent, 'objectSid', None))
                        if ps:
                            sids.setdefault(ps, str(parent.cn.value))
        # Groupes implicites de tout compte authentifié ; Utilisateurs (local)
        # contient « Utilisateurs du domaine » sur les serveurs membres.
        for wk in ('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545'):
            sids.setdefault(wk, WELL_KNOWN_SIDS[wk])
    return {'name': name, 'sid': sid, 'kind': kind, 'sids': sids, 'dn': dn}


def find_principal(conn, base_dn, name):
    """
    Utilisateur ou groupe par sAMAccountName (ou nom de groupe).

    Returns:
        (dn, sid, sAMAccountName). Raises FolderError si introuvable ou ambigu.
    """
    from ldap3 import SUBTREE
    from core.security import escape_ldap_filter
    name = (name or '').strip()
    if '\\' in name:
        name = name.split('\\', 1)[1]
    if not name:
        raise FolderError('Choisissez un utilisateur ou un groupe.')
    safe = escape_ldap_filter(name)
    # L'autocomplétion des groupes propose le cn, pas toujours égal au
    # sAMAccountName.
    conn.search(base_dn, f'(|(&(objectClass=user)(objectCategory=person)(sAMAccountName={safe}))'
                         f'(&(objectClass=group)(|(sAMAccountName={safe})(cn={safe}))))', SUBTREE,
                attributes=['objectSid', 'sAMAccountName'], size_limit=3)
    if not conn.entries:
        raise FolderError(f'Utilisateur ou groupe introuvable : {name}')
    if len(conn.entries) > 1:
        raise FolderError(f'Nom ambigu : {name} désigne plusieurs objets ; utilisez l\'identifiant.')
    entry = conn.entries[0]
    sid = sid_to_str(entry.objectSid)
    if not sid:
        raise FolderError('SID introuvable.')
    return entry.entry_dn, sid, str(entry.sAMAccountName.value)


def find_principal_sid(conn, base_dn, name):
    """SID et sAMAccountName d'un utilisateur ou groupe."""
    _, sid, sam = find_principal(conn, base_dn, name)
    return sid, sam


GROUP_DOMAIN_LOCAL_SECURITY = -2147483644   # 0x80000004
GROUP_GLOBAL_SECURITY = -2147483646         # 0x80000002

_GROUP_BAD = re.compile(r'[\\/\[\]:;|=,+*?<>@"#]')


def access_group_names(folder_name, with_global):
    """Noms des groupes AGDLP d'un dossier : DL_<nom>_L/_M (et GG_…)."""
    base = _GROUP_BAD.sub('', folder_name).strip().replace(' ', '_')[:50] or 'Dossier'
    names = {'read': {'dl': f'DL_{base}_L'}, 'modify': {'dl': f'DL_{base}_M'}}
    if with_global:
        names['read']['gg'] = f'GG_{base}_L'
        names['modify']['gg'] = f'GG_{base}_M'
    return names


def ensure_group(conn, base_dn, ou_dn, name, group_type, description, reuse=False):
    """
    Groupe de sécurité name dans ou_dn.

    Un groupe du même nom n'est repris que si reuse est vrai ; sinon
    FolderError, pour ne pas donner à un nouveau dossier les membres d'un
    groupe existant sans que l'administrateur l'ait voulu.

    Returns:
        (dn, sid, created)
    """
    from ldap3 import SUBTREE
    from ldap3.utils.dn import escape_rdn
    from core.security import escape_ldap_filter

    conn.search(base_dn, f'(&(objectClass=group)(sAMAccountName={escape_ldap_filter(name)}))',
                SUBTREE, attributes=['objectSid'])
    if conn.entries:
        entry = conn.entries[0]
        if not reuse:
            raise FolderError(f'Le groupe {name} existe déjà ({entry.entry_dn}). Cochez « Réutiliser '
                              'les groupes existants » ou indiquez un autre nom de groupes.')
        return entry.entry_dn, sid_to_str(entry.objectSid), False
    dn = f'CN={escape_rdn(name)},{ou_dn}'
    ok = conn.add(dn, ['top', 'group'], {'sAMAccountName': name, 'groupType': group_type,
                                          'description': description[:1024]})
    if not ok:
        raise FolderError(f'Création du groupe {name} impossible : '
                          f'{conn.result.get("message") or conn.result.get("description")}')
    from ldap3 import BASE
    conn.search(dn, '(objectClass=*)', BASE, attributes=['objectSid'])
    sid = sid_to_str(conn.entries[0].objectSid) if conn.entries else ''
    if not sid:
        raise FolderError(f'SID du groupe {name} introuvable après création.')
    return dn, sid, True


def add_member(conn, group_dn, member_dn):
    """Ajoute member_dn à group_dn (sans erreur s'il y est déjà)."""
    from ldap3 import MODIFY_ADD
    conn.modify(group_dn, {'member': [(MODIFY_ADD, [member_dn])]})
    code = conn.result.get('result')
    if code not in (0, 68):  # 68 : entryAlreadyExists (déjà membre)
        raise FolderError(f'Ajout de membre impossible : {conn.result.get("message") or conn.result.get("description")}')
