"""
Plusieurs domaines dans une même session.

Tout le code de l'application lit la connexion du domaine actif dans la
session (ad_server, ad_username, ad_base_dn, user_groups…). Pour gérer
plusieurs domaines sans rien changer à ce code, chaque domaine connecté est
rangé dans session['domains'] ; « changer de domaine » recopie ses valeurs
dans ces clés. Les droits (groupes, rôle) restent donc ceux du compte
utilisé sur CE domaine.

Les domaines déjà utilisés sont mémorisés dans data/domains.json (serveur,
base, port — jamais d'identifiants) pour proposer de s'y reconnecter.
"""
import json
import logging
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime

from flask import has_request_context, session

logger = logging.getLogger('domains')

KNOWN_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'domains.json')
MAX_KNOWN = 50
MAX_CONNECTED = 10
PARALLEL_TIMEOUT = 20

# Clés de session qui décrivent la connexion au domaine actif.
ACTIVE_KEYS = ('ad_server', 'ad_username', 'ad_password', 'ad_use_ssl', 'ad_starttls', 'ad_port', 'ad_base_dn',
               'ad_domain', 'user_role', 'user_groups', 'user_dn')

_lock = threading.Lock()
_KEY_RE = re.compile(r'^[a-z0-9][a-z0-9.-]{0,252}$')


class DomainError(Exception):
    """Erreur présentable à l'utilisateur."""


def domain_key(base_dn):
    """« DC=laprovidence,DC=local » → « laprovidence.local » (nom DNS du domaine)."""
    parts = [p.strip().split('=', 1)[1] for p in str(base_dn or '').split(',')
             if p.strip().upper().startswith('DC=') and '=' in p]
    return '.'.join(parts).lower()


def base_dn_of(dns_name):
    """« laprovidence.local » → « DC=laprovidence,DC=local »."""
    return ','.join(f'DC={p}' for p in str(dns_name or '').strip('.').split('.') if p)


def netbios_of(username):
    """« LAPROVIDENCE\\admin » → « LAPROVIDENCE » ; « admin@x » → ''."""
    username = str(username or '')
    return username.split('\\', 1)[0].upper() if '\\' in username else ''


# --- Session --------------------------------------------------------------------

def _entry_from_session():
    return {k: session.get(k) for k in ACTIVE_KEYS}


def active_key():
    return domain_key(session.get('ad_base_dn', '')) if has_request_context() else ''


def remember_active():
    """Range la connexion active dans session['domains'] (à appeler après chaque connexion)."""
    if not session.get('ad_server') or not session.get('ad_base_dn'):
        return ''
    key = domain_key(session['ad_base_dn'])
    if not key:
        return ''
    domains = dict(session.get('domains') or {})
    domains[key] = _entry_from_session()
    if len(domains) > MAX_CONNECTED:
        raise DomainError(f'Vous êtes déjà connecté à {MAX_CONNECTED} domaines : déconnectez-en un d\'abord.')
    session['domains'] = domains
    return key


def connected():
    """Domaines connectés dans cette session, le domaine actif d'abord."""
    current = active_key()
    domains = session.get('domains') or {}
    rows = [{'key': key, 'username': entry.get('ad_username', ''), 'server': entry.get('ad_server', ''),
             'base_dn': entry.get('ad_base_dn', ''), 'netbios': netbios_of(entry.get('ad_username')),
             'role': entry.get('user_role', ''), 'active': key == current}
            for key, entry in domains.items()]
    return sorted(rows, key=lambda r: (not r['active'], r['key']))


def activate(key):
    """Fait de « key » le domaine actif. Raises DomainError s'il n'est pas connecté."""
    key = (key or '').strip().lower()
    remember_active()
    domains = session.get('domains') or {}
    if key not in domains:
        raise DomainError('Ce domaine n\'est pas connecté dans cette session.')
    for k, value in domains[key].items():
        if k in ACTIVE_KEYS:
            session[k] = value
    session.modified = True
    return key


def forget(key):
    """Déconnecte un domaine. S'il était actif, un autre domaine connecté prend sa place."""
    key = (key or '').strip().lower()
    remember_active()
    domains = dict(session.get('domains') or {})
    if key not in domains:
        raise DomainError('Ce domaine n\'est pas connecté.')
    was_active = key == active_key()
    del domains[key]
    session['domains'] = domains
    if was_active:
        for k in ACTIVE_KEYS:
            session.pop(k, None)
        if domains:
            activate(sorted(domains)[0])
    return was_active


def reset():
    """Nouvelle connexion « classique » : on oublie les autres domaines de la session."""
    session.pop('domains', None)


# --- Connexion à un domaine qui n'est pas le domaine actif --------------------------

def credentials(key):
    """Paramètres de connexion en clair d'un domaine connecté (dans la requête HTTP)."""
    from core.session_crypto import decrypt_password
    entry = (session.get('domains') or {}).get(key)
    if key == active_key():
        entry = _entry_from_session()
    if not entry:
        raise DomainError('Ce domaine n\'est pas connecté.')
    return {'key': key, 'server': entry['ad_server'], 'username': entry['ad_username'],
            'password': decrypt_password(entry['ad_password']), 'use_ssl': bool(entry.get('ad_use_ssl')),
            'port': entry.get('ad_port'), 'base_dn': entry.get('ad_base_dn', '')}


def connect(creds):
    """Connexion à partir de credentials(), sans toucher à la session (utilisable dans un thread)."""
    from routes.core import get_ad_connection
    return get_ad_connection(creds['server'], creds['username'], creds['password'], creds['use_ssl'],
                             creds['port'], remember=False)


def for_each(func, keys=None, timeout=PARALLEL_TIMEOUT):
    """
    Appelle func(conn, base_dn, key) sur chaque domaine connecté, en parallèle.

    Returns:
        {key: {'ok': bool, 'result': …, 'error': str}} — un domaine injoignable
        n'empêche pas les autres de répondre.
    """
    keys = [r['key'] for r in connected()] if keys is None else keys
    all_creds = []
    for key in keys:
        try:
            all_creds.append(credentials(key))
        except Exception as e:
            logger.info('Identifiants du domaine %s illisibles : %s', key, e)
    results = {key: {'ok': False, 'result': None, 'error': 'Identifiants indisponibles : reconnectez ce domaine.'}
               for key in keys}

    def run(creds):
        conn, error = connect(creds)
        if not conn:
            return {'ok': False, 'result': None, 'error': error or 'Connexion impossible.'}
        try:
            return {'ok': True, 'result': func(conn, creds['base_dn'], creds['key']), 'error': ''}
        except Exception as e:
            logger.warning('Domaine %s : %s', creds['key'], e)
            return {'ok': False, 'result': None, 'error': str(e)[:300]}
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    if not all_creds:
        return results
    pool = ThreadPoolExecutor(max_workers=min(len(all_creds), 6))
    futures = {pool.submit(run, c): c['key'] for c in all_creds}
    done, pending = wait(futures, timeout=timeout)
    for future in done:
        results[futures[future]] = future.result()
    for future in pending:
        results[futures[future]] = {'ok': False, 'result': None, 'error': 'Le domaine n\'a pas répondu à temps.'}
    pool.shutdown(wait=False)
    return results


# --- Domaines connus (sans identifiants) ---------------------------------------------

def _read_known():
    try:
        with open(KNOWN_FILE, encoding='utf-8') as f:
            data = json.load(f)
        return [d for d in data if isinstance(d, dict) and _KEY_RE.match(str(d.get('key', '')))] \
            if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def known():
    """Domaines déjà utilisés sur cette application, le plus récent d'abord."""
    return sorted(_read_known(), key=lambda d: d.get('last_used', ''), reverse=True)


def remember_known(key, server, base_dn, port=None, use_ssl=False, netbios=''):
    """Mémorise un domaine (après une connexion réussie). Aucun identifiant n'est enregistré."""
    if not _KEY_RE.match(key or ''):
        return
    with _lock:
        items = [d for d in _read_known() if d.get('key') != key]
        items.insert(0, {'key': key, 'server': str(server or '')[:255], 'base_dn': str(base_dn or '')[:500],
                      'port': port if isinstance(port, int) else None, 'use_ssl': bool(use_ssl),
                      'netbios': str(netbios or '')[:15], 'last_used': datetime.now().isoformat(timespec='seconds')})
        items = sorted(items, key=lambda d: d.get('last_used', ''), reverse=True)[:MAX_KNOWN]
        os.makedirs(os.path.dirname(KNOWN_FILE), exist_ok=True)
        tmp = KNOWN_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(items, f, ensure_ascii=False, indent=2)
        os.replace(tmp, KNOWN_FILE)


def forget_known(key):
    with _lock:
        items = [d for d in _read_known() if d.get('key') != key]
        os.makedirs(os.path.dirname(KNOWN_FILE), exist_ok=True)
        with open(KNOWN_FILE, 'w', encoding='utf-8') as f:
            json.dump(items, f, ensure_ascii=False, indent=2)


def known_entry(key):
    return next((d for d in _read_known() if d.get('key') == key), None)
