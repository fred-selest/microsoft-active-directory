"""
Permissions Granulaires - Gestion fine des droits par groupe AD
"""
import json
import os
from pathlib import Path
from datetime import datetime

# Fichier de configuration des permissions (chemin absolu depuis la racine du projet)
PERMISSIONS_FILE = Path(__file__).resolve().parent.parent / 'data' / 'permissions.json'

# Permissions disponibles
ALL_PERMISSIONS = {
    # Users
    'users:create': 'Créer des utilisateurs',
    'users:read': 'Voir les utilisateurs',
    'users:update': 'Modifier des utilisateurs',
    'users:delete': 'Supprimer des utilisateurs',
    'users:import': 'Importer des utilisateurs',
    'users:export': 'Exporter des utilisateurs',
    
    # Groups
    'groups:create': 'Créer des groupes',
    'groups:read': 'Voir les groupes',
    'groups:update': 'Modifier des groupes',
    'groups:delete': 'Supprimer des groupes',
    
    # Computers
    'computers:create': 'Créer des ordinateurs',
    'computers:read': 'Voir les ordinateurs',
    'computers:update': 'Modifier des ordinateurs',
    'computers:delete': 'Supprimer des ordinateurs',
    
    # OUs
    'ous:create': 'Créer des OUs',
    'ous:read': 'Voir les OUs',
    'ous:update': 'Modifier des OUs',
    'ous:delete': 'Supprimer des OUs',
    
    # Tools
    'tools:locked_accounts': 'Voir comptes verrouillés',
    'tools:expiring_accounts': 'Voir comptes expirants',
    'tools:password_policy': 'Voir politique MDP',
    'tools:password_audit': 'Audit MDP',
    'tools:expiring_pdf': 'Export PDF expirants',
    
    # Admin
    'admin:settings': 'Paramètres',
    'admin:backups': 'Sauvegardes',
    'admin:audit_logs': 'Logs d\'audit',
    'admin:diagnostic': 'Diagnostic',
    'admin:security_audit': 'Audit de sécurité',
    'admin:alerts': 'Alertes',
    'admin:user_templates': 'Modèles utilisateurs',
}

# Rôles prédéfinis avec permissions
PREDEFINED_ROLES = {
    'Administrateurs du domaine': {
        'permissions': list(ALL_PERMISSIONS.keys()),
        'description': 'Accès complet'
    },
    'Administrateurs de l\'entreprise': {
        'permissions': list(ALL_PERMISSIONS.keys()),
        'description': 'Accès complet'
    },
    'IT Support': {
        'permissions': [
            'users:read', 'users:update',
            'groups:read', 'groups:update',
            'computers:read', 'computers:update',
            'ous:read',
            'tools:locked_accounts', 'tools:expiring_accounts',
            'admin:audit_logs'
        ],
        'description': 'Support informatique - Lecture + Modification limitée'
    },
    'Helpdesk': {
        'permissions': [
            'users:read', 'users:update',
            'groups:read',
            'computers:read',
            'tools:locked_accounts',
        ],
        'description': 'Helpdesk - Réinitialisation MDP et débloquage'
    },
    'Domain Users': {
        'permissions': [
            'users:read',
            'groups:read',
            'computers:read',
            'ous:read',
        ],
        'description': 'Lecture seule'
    },
}

# Anciennes permissions (système legacy) -> Nouvelles permissions
LEGACY_PERMISSION_MAPPING = {
    'read': [
        'users:read', 'groups:read', 'computers:read', 'ous:read'
    ],
    'write': [
        'users:read', 'users:update', 'users:create',
        'groups:read', 'groups:update', 'groups:create',
        'computers:read', 'computers:update', 'computers:create',
        'ous:read', 'ous:update', 'ous:create',
        'tools:locked_accounts', 'tools:expiring_accounts',
        'tools:password_policy', 'tools:password_audit'
    ],
    'delete': [
        'users:delete', 'groups:delete', 'computers:delete', 'ous:delete'
    ],
    'admin': list(ALL_PERMISSIONS.keys()),
    'audit_logs': ['admin:audit_logs'],
    'password_reset': ['users:update', 'users:read'],
    'user_create': ['users:create', 'users:read', 'users:update'],
    'user_delete': ['users:delete', 'users:read'],
    'group_modify': ['groups:update', 'groups:read', 'groups:create'],
    'backup_restore': ['admin:backups', 'admin:audit_logs'],
    'debug_access': ['admin:diagnostic'],
}


def ensure_data_dir():
    """S'assurer que le répertoire data existe."""
    PERMISSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)


def load_permissions():
    """Charger les permissions depuis le fichier JSON."""
    ensure_data_dir()
    
    if PERMISSIONS_FILE.exists():
        try:
            with open(PERMISSIONS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    
    # Valeurs par défaut
    return {
        'version': '1.0',
        'updated': datetime.now().isoformat(),
        'groups': {}
    }


def save_permissions(permissions):
    """Sauvegarder les permissions dans le fichier JSON."""
    ensure_data_dir()
    permissions['updated'] = datetime.now().isoformat()
    
    with open(PERMISSIONS_FILE, 'w', encoding='utf-8') as f:
        json.dump(permissions, f, indent=2, ensure_ascii=False)


def get_group_permissions(group_name, user_groups=None):
    """
    Obtenir les permissions d'un groupe ou d'un utilisateur.
    
    Args:
        group_name: Nom du groupe AD
        user_groups: Liste des groupes de l'utilisateur (pour héritage)
    
    Returns:
        set: Permissions du groupe
    """
    permissions = load_permissions()
    
    # Permissions directes du groupe
    group_perms = set()
    
    if group_name in permissions.get('groups', {}):
        group_data = permissions['groups'][group_name]
        if group_data.get('enabled', True):
            group_perms = set(group_data.get('permissions', []))
    
    # Si pas de permissions spécifiques, utiliser les rôles prédéfinis
    if not group_perms and group_name in PREDEFINED_ROLES:
        group_perms = set(PREDEFINED_ROLES[group_name]['permissions'])
    
    # Si user_groups fourni, fusionner les permissions (héritage)
    if user_groups:
        for ug in user_groups:
            if ug in permissions.get('groups', {}):
                ug_data = permissions['groups'][ug]
                if ug_data.get('enabled', True):
                    group_perms.update(ug_data.get('permissions', []))
    
    return group_perms


def has_permission(user_groups, required_permission, username=None, user_dn=None):
    """
    Vérifier si un utilisateur a une permission spécifique.
    Gère les nouvelles permissions granulaires, les anciennes (legacy),
    et les sujets de type utilisateur ou OU.

    Args:
        user_groups: Liste des groupes AD de l'utilisateur
        required_permission: Permission requise (ex: 'users:create' ou 'write')
        username: sAMAccountName de l'utilisateur (pour sujets de type 'user')
        user_dn: DN complet de l'utilisateur (pour sujets de type 'ou')

    Returns:
        bool: True si l'utilisateur a la permission
    """
    if not user_groups and not username:
        return False

    # Convertir les permissions legacy
    if required_permission in LEGACY_PERMISSION_MAPPING:
        required_permissions = set(LEGACY_PERMISSION_MAPPING[required_permission])
    else:
        required_permissions = {required_permission}

    permissions_data = load_permissions()
    custom_groups = permissions_data.get('groups', {})

    # Vérifier les entrées personnalisées (group, user, ou)
    for subject_name, entry in custom_groups.items():
        if not entry.get('enabled', True):
            continue

        subject_type = entry.get('subject_type', 'group')
        matched = False

        if subject_type == 'group':
            matched = subject_name in (user_groups or [])
        elif subject_type == 'user':
            matched = bool(username) and username.lower() == subject_name.lower()
        elif subject_type == 'ou':
            matched = bool(user_dn) and subject_name.lower() in user_dn.lower()

        if matched:
            entry_perms = set(entry.get('permissions', []))
            if entry_perms & required_permissions:
                return True

    # Vérifier les rôles prédéfinis (type 'group' uniquement)
    for group in (user_groups or []):
        if group in PREDEFINED_ROLES:
            role_perms = set(PREDEFINED_ROLES[group]['permissions'])
            if role_perms & required_permissions:
                return True

    # Fallback rôle admin legacy
    from flask import session
    if session.get('user_role') == 'admin':
        return True

    return False


def has_any_permission(user_groups, permissions):
    """
    Vérifier si un utilisateur a au moins une des permissions.
    
    Args:
        user_groups: Liste des groupes AD de l'utilisateur
        permissions: Liste de permissions requises
    
    Returns:
        bool: True si l'utilisateur a au moins une permission
    """
    for perm in permissions:
        if has_permission(user_groups, perm):
            return True
    return False


def get_all_groups_with_permissions():
    """
    Obtenir tous les groupes (et sujets) avec leurs permissions.

    Returns:
        dict: {subject_name: {permissions, description, enabled, custom, subject_type}}
    """
    permissions = load_permissions()
    result = {}

    # Entrées personnalisées (group / user / ou)
    for subject_name, group_data in permissions.get('groups', {}).items():
        result[subject_name] = {
            'permissions': group_data.get('permissions', []),
            'description': group_data.get('description', ''),
            'enabled': group_data.get('enabled', True),
            'subject_type': group_data.get('subject_type', 'group'),
            'custom': True
        }

    # Rôles prédéfinis (si pas déjà dans personnalisés)
    for group_name, role_data in PREDEFINED_ROLES.items():
        if group_name not in result:
            result[group_name] = {
                'permissions': role_data['permissions'],
                'description': role_data['description'],
                'enabled': True,
                'subject_type': 'group',
                'custom': False
            }

    return result


def set_group_permissions(group_name, permissions_list, description='', enabled=True,
                          subject_type='group', old_name=None):
    """
    Définir les permissions d'un sujet (groupe, utilisateur ou OU).

    Args:
        group_name: Nom/identifiant du sujet
        permissions_list: Liste des permissions
        description: Description du rôle
        enabled: Entrée activée
        subject_type: 'group' | 'user' | 'ou'
        old_name: Ancien nom si renommage

    Returns:
        bool: True si sauvegardé avec succès
    """
    try:
        perms = load_permissions()

        if 'groups' not in perms:
            perms['groups'] = {}

        # Supprimer l'ancienne entrée si renommage
        if old_name and old_name != group_name and old_name in perms['groups']:
            del perms['groups'][old_name]

        # Valider subject_type
        if subject_type not in ('group', 'user', 'ou'):
            subject_type = 'group'

        perms['groups'][group_name] = {
            'permissions': [p for p in permissions_list if p in ALL_PERMISSIONS],
            'description': description,
            'enabled': bool(enabled),
            'subject_type': subject_type,
            'updated': datetime.now().isoformat()
        }

        save_permissions(perms)
        return True
    except Exception:
        return False


def delete_group_permissions(group_name):
    """
    Supprimer les permissions d'un groupe.
    
    Args:
        group_name: Nom du groupe
    
    Returns:
        bool: True si supprimé avec succès
    """
    try:
        perms = load_permissions()
        
        if group_name in perms.get('groups', {}):
            del perms['groups'][group_name]
            save_permissions(perms)
            return True
        
        return False
    except Exception:
        return False


def get_available_permissions():
    """
    Obtenir toutes les permissions disponibles avec descriptions.
    
    Returns:
        dict: {permission: description}
    """
    return ALL_PERMISSIONS.copy()


def get_permission_categories():
    """
    Obtenir les catégories de permissions.
    
    Returns:
        dict: {category: [permissions]}
    """
    categories = {
        'users': [],
        'groups': [],
        'computers': [],
        'ous': [],
        'tools': [],
        'admin': []
    }
    
    for perm in ALL_PERMISSIONS.keys():
        category = perm.split(':')[0]
        if category in categories:
            categories[category].append(perm)
    
    return categories
