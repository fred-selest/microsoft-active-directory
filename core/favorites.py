"""
Favoris : comptes, groupes, postes et unités d'organisation épinglés par
chaque administrateur pour y revenir en un clic (tableau de bord, page
Favoris). Conservés par identifiant dans data/favorites.json : ils
survivent à la déconnexion, contrairement à l'ancien stockage en session.
"""
import json
import logging
import os
import threading
from datetime import datetime

logger = logging.getLogger('favorites')

FAVORITES_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'favorites.json')
MAX_FAVORITES = 200
TYPES = ('user', 'group', 'computer', 'ou')
_lock = threading.Lock()


def _key(username):
    return str(username or '').split('\\')[-1].split('@')[0].strip().lower()


def _read():
    try:
        with open(FAVORITES_FILE, encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def load(username):
    """Favoris d'un administrateur : [{dn, type, name, added}], par nom."""
    items = [f for f in _read().get(_key(username), [])
             if isinstance(f, dict) and f.get('dn') and f.get('type') in TYPES]
    return sorted(items, key=lambda f: (TYPES.index(f['type']), str(f.get('name', '')).lower()))


def _write(username, items):
    with _lock:
        data = _read()
        if items:
            data[_key(username)] = items
        else:
            data.pop(_key(username), None)
        os.makedirs(os.path.dirname(FAVORITES_FILE), exist_ok=True)
        tmp = FAVORITES_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, FAVORITES_FILE)


def is_favorite(username, dn):
    dn = (dn or '').lower()
    return any(f['dn'].lower() == dn for f in load(username))


def add(username, dn, kind, name):
    """Ajoute un favori. Returns False si la limite est atteinte ou la demande invalide."""
    dn, name = (dn or '').strip(), (name or '').strip()[:200]
    if not _key(username) or not dn or kind not in TYPES or not name:
        return False
    items = load(username)
    if any(f['dn'].lower() == dn.lower() for f in items):
        return True
    if len(items) >= MAX_FAVORITES:
        return False
    items.append({'dn': dn, 'type': kind, 'name': name, 'added': datetime.now().isoformat(timespec='seconds')})
    _write(username, items)
    return True


def remove(username, dn):
    dn = (dn or '').strip().lower()
    items = load(username)
    kept = [f for f in items if f['dn'].lower() != dn]
    if len(kept) != len(items):
        _write(username, kept)
