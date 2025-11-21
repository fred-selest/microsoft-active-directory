"""
API REST pour l'interface Web Active Directory.
Fournit des endpoints pour l'automatisation et l'integration.
"""

import json
import secrets
import os
import hashlib
import hmac
from functools import wraps
from flask import request, jsonify, session
from datetime import datetime

# Stockage des cles API (en production, utiliser une base de donnees)
API_KEYS_FILE = 'data/api_keys.json'


def _hash_api_key(key: str) -> str:
    """
    Hacher une clé API de manière sécurisée.
    Utilise SHA-256 avec un salt fixe pour permettre la validation.
    """
    # Salt fixe pour les clés API (différent de celui des sessions)
    salt = b'ad_web_api_key_salt_v1'
    return hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100000).hex()


def _secure_compare(a: str, b: str) -> bool:
    """Comparaison sécurisée (timing-safe) de deux chaînes."""
    return hmac.compare_digest(a, b)


def load_api_keys():
    """Charger les cles API depuis le fichier."""
    try:
        if os.path.exists(API_KEYS_FILE):
            with open(API_KEYS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}


def save_api_keys(keys):
    """Sauvegarder les cles API dans le fichier."""
    os.makedirs(os.path.dirname(API_KEYS_FILE), exist_ok=True)
    # Permissions restrictives sur le fichier
    with open(API_KEYS_FILE, 'w') as f:
        json.dump(keys, f, indent=2)
    # Restreindre les permissions (lecture/écriture propriétaire uniquement)
    try:
        os.chmod(API_KEYS_FILE, 0o600)
    except:
        pass


def generate_api_key(name, permissions=None):
    """
    Generer une nouvelle cle API.
    IMPORTANT: La clé est retournée une seule fois, seul le hash est stocké.
    """
    # Générer la clé
    key = secrets.token_urlsafe(32)
    # Hacher la clé pour stockage sécurisé
    key_hash = _hash_api_key(key)

    keys = load_api_keys()
    keys[key_hash] = {
        'name': name,
        'created': datetime.now().isoformat(),
        'permissions': permissions or ['read'],
        'last_used': None,
        # Préfixe pour identification (premiers 8 caractères, non secret)
        'prefix': key[:8]
    }
    save_api_keys(keys)
    # Retourner la clé en clair (une seule fois)
    return key


def revoke_api_key(key_or_prefix):
    """
    Revoquer une cle API.
    Accepte soit la clé complète soit le préfixe.
    """
    keys = load_api_keys()

    # Si c'est une clé complète, la hacher
    key_hash = _hash_api_key(key_or_prefix)
    if key_hash in keys:
        del keys[key_hash]
        save_api_keys(keys)
        return True

    # Sinon, chercher par préfixe
    for stored_hash, info in list(keys.items()):
        if info.get('prefix') == key_or_prefix[:8]:
            del keys[stored_hash]
            save_api_keys(keys)
            return True

    return False


def validate_api_key(key):
    """Valider une cle API et retourner ses infos."""
    keys = load_api_keys()
    key_hash = _hash_api_key(key)

    # Recherche sécurisée (timing-safe)
    for stored_hash, info in keys.items():
        if _secure_compare(stored_hash, key_hash):
            # Mettre a jour last_used
            keys[stored_hash]['last_used'] = datetime.now().isoformat()
            save_api_keys(keys)
            return info
    return None


def require_api_key(permission='read'):
    """Decorateur pour exiger une cle API valide."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Verifier le header Authorization
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                api_key = auth_header[7:]
            else:
                api_key = request.headers.get('X-API-Key', '')

            if not api_key:
                return jsonify({
                    'success': False,
                    'error': 'API key required'
                }), 401

            key_info = validate_api_key(api_key)
            if not key_info:
                return jsonify({
                    'success': False,
                    'error': 'Invalid API key'
                }), 401

            # Verifier les permissions
            if permission not in key_info.get('permissions', []):
                return jsonify({
                    'success': False,
                    'error': f'Permission "{permission}" required'
                }), 403

            # Ajouter les infos de la cle au contexte
            request.api_key_info = key_info
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_api_documentation():
    """Retourner la documentation de l'API."""
    return {
        'version': '1.0',
        'base_url': '/api/v1',
        'authentication': {
            'type': 'Bearer Token or X-API-Key header',
            'example': 'Authorization: Bearer your-api-key'
        },
        'endpoints': {
            '/api/v1/users': {
                'GET': 'List all users',
                'POST': 'Create a new user'
            },
            '/api/v1/users/{dn}': {
                'GET': 'Get user details',
                'PUT': 'Update user',
                'DELETE': 'Delete user'
            },
            '/api/v1/groups': {
                'GET': 'List all groups',
                'POST': 'Create a new group'
            },
            '/api/v1/groups/{dn}': {
                'GET': 'Get group details',
                'PUT': 'Update group',
                'DELETE': 'Delete group'
            },
            '/api/v1/groups/{dn}/members': {
                'GET': 'List group members',
                'POST': 'Add member to group',
                'DELETE': 'Remove member from group'
            },
            '/api/v1/computers': {
                'GET': 'List all computers'
            },
            '/api/v1/computers/{dn}': {
                'GET': 'Get computer details',
                'PUT': 'Update computer',
                'DELETE': 'Delete computer'
            },
            '/api/v1/ous': {
                'GET': 'List all OUs',
                'POST': 'Create a new OU'
            },
            '/api/v1/search': {
                'GET': 'Global search across all objects'
            },
            '/api/v1/audit': {
                'GET': 'Get audit logs'
            },
            '/api/v1/stats': {
                'GET': 'Get statistics'
            }
        },
        'permissions': {
            'read': 'Read access to all resources',
            'write': 'Create and update resources',
            'delete': 'Delete resources',
            'admin': 'Full administrative access'
        }
    }
