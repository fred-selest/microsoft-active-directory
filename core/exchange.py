"""
Boîtes aux lettres partagées Exchange Online (Microsoft 365).

Les opérations passent par scripts/exchange.ps1 et le module PowerShell
ExchangeOnlineManagement, avec une identité d'application : un certificat
du magasin de l'ordinateur, sans aucun mot de passe. La mise en place se
fait une fois avec scripts/setup_m365.ps1, qui écrit data/m365.json.

Garde-fous :
- seules les boîtes PARTAGÉES sont modifiables (vérifié dans le script
  avant chaque écriture, et ici par rapport à la liste) ;
- les adresses sont validées et passent en données (JSON sur l'entrée
  standard), jamais dans le texte du script.
"""
import json
import logging
import os
import re
import subprocess
import threading
import time

logger = logging.getLogger('exchange')

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PS_SCRIPT_PATH = os.path.join(_ROOT, 'scripts', 'exchange.ps1')
CONFIG_FILE = os.path.join(_ROOT, 'data', 'm365.json')
PS_TIMEOUT = 180
CACHE_TTL = 300

_GUID_RE = re.compile(r'^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')
_THUMB_RE = re.compile(r'^[0-9A-Fa-f]{40}$')
_ORG_RE = re.compile(r'^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$')
_ALIAS_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')

_cache = {'at': 0, 'data': None}
_lock = threading.Lock()


class ExchangeError(Exception):
    """Erreur présentable à l'utilisateur."""


def get_config():
    """Configuration écrite par scripts/setup_m365.ps1, ou None."""
    try:
        with open(CONFIG_FILE, encoding='utf-8-sig') as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return None
    if not (_GUID_RE.match(str(cfg.get('app_id', ''))) and _THUMB_RE.match(str(cfg.get('thumbprint', '')))
            and _ORG_RE.match(str(cfg.get('organization', '')))):
        return None
    return {'organization': cfg['organization'], 'app_id': cfg['app_id'],
            'thumbprint': cfg['thumbprint'].upper(), 'expires': str(cfg.get('expires', ''))}


def _friendly(message):
    text = message or ''
    low = text.lower()
    if 'is not recognized' in low or 'exchangeonlinemanagement' in low and 'not' in low:
        return 'Le module PowerShell Exchange Online n\'est pas installé : relancez scripts\\setup_m365.ps1.'
    if 'certificate' in low and ('not found' in low or 'thumbprint' in low):
        return 'Certificat introuvable sur ce serveur : relancez scripts\\setup_m365.ps1.'
    if 'aadsts' in low or 'unauthorized' in low or 'access denied' in low or 'role' in low and 'assigned' in low:
        return ('Microsoft 365 refuse la connexion de l\'application. Si la mise en place date de moins '
                f'd\'une heure, patientez ; sinon relancez scripts\\setup_m365.ps1. ({text[:160]})')
    if "couldn't be found" in low or 'introuvable' in low:
        return f'Objet introuvable dans Exchange : {text[:200]}'
    return text[:300] or 'Erreur inconnue.'


def run_ps(request, timeout=PS_TIMEOUT):
    """Exécute scripts/exchange.ps1. Raises ExchangeError."""
    cfg = get_config()
    if not cfg:
        raise ExchangeError('La liaison Microsoft 365 n\'est pas configurée.')
    if os.name != 'nt':
        raise ExchangeError('La gestion d\'Exchange Online nécessite que l\'application tourne sous Windows.')
    data = dict(request, organization=cfg['organization'], app_id=cfg['app_id'], thumbprint=cfg['thumbprint'])
    try:
        proc = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
             '-File', PS_SCRIPT_PATH],
            input=json.dumps(data), capture_output=True, text=True, encoding='utf-8',
            errors='replace', timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ExchangeError('Exchange Online n\'a pas répondu dans le délai imparti.')
    except OSError as e:
        raise ExchangeError(f'PowerShell introuvable : {e}')
    # La réponse est la dernière ligne : le module peut écrire avant elle.
    lines = [ln for ln in (proc.stdout or '').strip().splitlines() if ln.strip().startswith('{')]
    try:
        result = json.loads(lines[-1].lstrip('﻿')) if lines else None
    except ValueError:
        result = None
    if not isinstance(result, dict):
        logger.error('Réponse Exchange illisible (code %s) : %s', proc.returncode,
                     (proc.stderr or proc.stdout or '')[:500])
        raise ExchangeError(_friendly(proc.stderr or proc.stdout))
    if not result.get('ok'):
        raise ExchangeError(_friendly(result.get('error')))
    return result


def _email(value, what='Adresse'):
    from core.onboarding import valid_email
    value = (value or '').strip().lower()
    if not valid_email(value):
        raise ExchangeError(f'{what} invalide.')
    return value


def list_mailboxes(refresh=False):
    """{mailboxes: [{name, address, alias, created}], domains: [...]}, gardé 5 minutes."""
    with _lock:
        if not refresh and _cache['data'] and time.time() - _cache['at'] < CACHE_TTL:
            return _cache['data']
    result = run_ps({'op': 'list'})
    data = {'mailboxes': [{'name': str(m.get('name') or ''), 'address': str(m.get('address') or '').lower(),
                           'alias': str(m.get('alias') or ''), 'created': str(m.get('created') or '')}
                          for m in result.get('mailboxes') or []],
            'domains': [str(d).lower() for d in result.get('domains') or []]}
    with _lock:
        _cache.update(at=time.time(), data=data)
    return data


def _shared(address):
    """Adresse d'une boîte partagée connue, sinon ExchangeError."""
    address = _email(address, 'Adresse de la boîte')
    if address not in {m['address'] for m in list_mailboxes()['mailboxes']}:
        # La liste peut dater : une relecture avant de refuser.
        if address not in {m['address'] for m in list_mailboxes(refresh=True)['mailboxes']}:
            raise ExchangeError('Cette adresse n\'est pas une boîte partagée.')
    return address


def members(address):
    """Comptes ayant accès à une boîte partagée : [{user, full_access, send_as}]."""
    address = _shared(address)
    result = run_ps({'op': 'members', 'mailbox': address})
    full = {str(u).lower() for u in result.get('full_access') or []}
    send = {str(u).lower() for u in result.get('send_as') or []}
    return [{'user': u, 'full_access': u in full, 'send_as': u in send} for u in sorted(full | send)]


def grant(address, user, full_access=True, send_as=True):
    address, user = _shared(address), _email(user, 'Adresse de l\'utilisateur')
    if not (full_access or send_as):
        raise ExchangeError('Choisissez au moins un droit.')
    run_ps({'op': 'grant', 'mailbox': address, 'user': user,
            'full_access': bool(full_access), 'send_as': bool(send_as)})
    return address, user


def revoke(address, user, full_access=True, send_as=True):
    address, user = _shared(address), _email(user, 'Adresse de l\'utilisateur')
    run_ps({'op': 'revoke', 'mailbox': address, 'user': user,
            'full_access': bool(full_access), 'send_as': bool(send_as)})
    return address, user


def create(name, alias, domain):
    """Crée une boîte partagée alias@domain. Le domaine doit être un domaine accepté."""
    name = (name or '').strip()
    alias = (alias or '').strip().lower()
    domain = (domain or '').strip().lower()
    if not name or len(name) > 64 or any(c in name for c in '<>"\r\n'):
        raise ExchangeError('Nom de la boîte invalide (64 caractères au plus).')
    if not _ALIAS_RE.match(alias):
        raise ExchangeError('Adresse invalide : lettres, chiffres, points et tirets uniquement.')
    data = list_mailboxes()
    if domain not in data['domains']:
        raise ExchangeError('Ce domaine n\'est pas un domaine accepté de Microsoft 365.')
    address = _email(f'{alias}@{domain}')
    if address in {m['address'] for m in data['mailboxes']}:
        raise ExchangeError('Une boîte partagée porte déjà cette adresse.')
    run_ps({'op': 'create', 'name': name, 'alias': alias, 'address': address})
    with _lock:
        _cache.update(at=0, data=None)
    return address


def convert_to_shared(address):
    """
    Convertit la boîte personnelle d'un compte en boîte partagée (départ
    d'un collaborateur) : le courrier est conservé et la licence peut être
    retirée. Sans effet si elle est déjà partagée.
    """
    address = _email(address, 'Adresse de la boîte')
    run_ps({'op': 'to_shared', 'mailbox': address})
    with _lock:
        _cache.update(at=0, data=None)
    return address


def user_address(conn, base_dn, name):
    """Adresse Microsoft 365 (UPN) d'un utilisateur de l'AD, par identifiant ou adresse."""
    from ldap3 import SUBTREE
    from core.security import escape_ldap_filter
    name = (name or '').strip().split('\\')[-1]
    if not name:
        raise ExchangeError('Choisissez un utilisateur.')
    safe = escape_ldap_filter(name)
    conn.search(base_dn, f'(&(objectClass=user)(objectCategory=person)'
                         f'(|(sAMAccountName={safe})(userPrincipalName={safe})(mail={safe})))', SUBTREE,
                attributes=['userPrincipalName', 'mail', 'sAMAccountName'], size_limit=3)
    if len(conn.entries) != 1:
        raise ExchangeError(f'Utilisateur introuvable dans l\'annuaire : {name}')
    entry = conn.entries[0]
    for attr in ('userPrincipalName', 'mail'):
        value = str(getattr(entry, attr).value or '') if attr in entry else ''
        if value and not value.lower().endswith(('.local', '.lan')):
            return _email(value)
    raise ExchangeError(f'{name} n\'a pas d\'adresse Microsoft 365 (identifiant en .local et pas d\'e-mail).')
