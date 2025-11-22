"""
Module de cache LDAP pour ameliorer les performances.
Met en cache les resultats des requetes frequentes.
"""

import time
import hashlib
import json
from functools import wraps

# Cache en memoire
_cache = {}
_cache_stats = {'hits': 0, 'misses': 0}

# Duree de vie du cache par defaut (en secondes)
DEFAULT_TTL = 300  # 5 minutes


def _make_key(prefix, *args, **kwargs):
    """Generer une cle de cache unique."""
    key_data = f"{prefix}:{args}:{sorted(kwargs.items())}"
    return hashlib.md5(key_data.encode()).hexdigest()


def cache_get(key):
    """Recuperer une valeur du cache."""
    if key in _cache:
        entry = _cache[key]
        if entry['expires'] > time.time():
            _cache_stats['hits'] += 1
            return entry['value']
        else:
            # Expire, supprimer
            del _cache[key]

    _cache_stats['misses'] += 1
    return None


def cache_set(key, value, ttl=DEFAULT_TTL):
    """Stocker une valeur dans le cache."""
    _cache[key] = {
        'value': value,
        'expires': time.time() + ttl,
        'created': time.time()
    }


def cache_delete(key):
    """Supprimer une entree du cache."""
    if key in _cache:
        del _cache[key]


def cache_clear(prefix=None):
    """Vider le cache (tout ou par prefixe)."""
    global _cache

    if prefix:
        keys_to_delete = [k for k in _cache.keys() if k.startswith(prefix)]
        for key in keys_to_delete:
            del _cache[key]
    else:
        _cache = {}


def cache_stats():
    """Obtenir les statistiques du cache."""
    total = _cache_stats['hits'] + _cache_stats['misses']
    hit_rate = (_cache_stats['hits'] / total * 100) if total > 0 else 0

    return {
        'hits': _cache_stats['hits'],
        'misses': _cache_stats['misses'],
        'hit_rate': round(hit_rate, 2),
        'entries': len(_cache),
        'size_kb': sum(len(str(v)) for v in _cache.values()) // 1024
    }


def cached(prefix, ttl=DEFAULT_TTL):
    """Decorateur pour mettre en cache le resultat d'une fonction."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Generer la cle
            key = _make_key(prefix, *args, **kwargs)

            # Verifier le cache
            result = cache_get(key)
            if result is not None:
                return result

            # Executer la fonction
            result = f(*args, **kwargs)

            # Mettre en cache
            cache_set(key, result, ttl)

            return result
        return decorated_function
    return decorator


def invalidate_user_cache():
    """Invalider le cache des utilisateurs."""
    cache_clear('users')


def invalidate_group_cache():
    """Invalider le cache des groupes."""
    cache_clear('groups')


def invalidate_computer_cache():
    """Invalider le cache des ordinateurs."""
    cache_clear('computers')


def invalidate_all_cache():
    """Invalider tout le cache."""
    cache_clear()
