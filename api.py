"""
API REST pour l'interface Web Active Directory.
Fournit des endpoints pour l'automatisation et l'integration.
"""

import json
import secrets
import os
from functools import wraps
from flask import request, jsonify, session
from datetime import datetime

# Stockage des cles API (en production, utiliser une base de donnees)
API_KEYS_FILE = 'data/api_keys.json'


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
    with open(API_KEYS_FILE, 'w') as f:
        json.dump(keys, f, indent=2)


def generate_api_key(name, permissions=None):
    """Generer une nouvelle cle API."""
    key = secrets.token_urlsafe(32)
    keys = load_api_keys()
    keys[key] = {
        'name': name,
        'created': datetime.now().isoformat(),
        'permissions': permissions or ['read'],
        'last_used': None
    }
    save_api_keys(keys)
    return key


def revoke_api_key(key):
    """Revoquer une cle API."""
    keys = load_api_keys()
    if key in keys:
        del keys[key]
        save_api_keys(keys)
        return True
    return False


def validate_api_key(key):
    """Valider une cle API et retourner ses infos."""
    keys = load_api_keys()
    if key in keys:
        # Mettre a jour last_used
        keys[key]['last_used'] = datetime.now().isoformat()
        save_api_keys(keys)
        return keys[key]
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
