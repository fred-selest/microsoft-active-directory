"""
Permissions Granulaires - Gestion fine des droits par groupe AD
"""
import json
import os
from pathlib import Path
from datetime import datetime

# Fichier de configuration des permissions
PERMISSIONS_FILE = Path('data/permissions.json')

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
    'Domain Admins': {
        'permissions': list(ALL_PERMISSIONS.keys()),
        'description': 'Accès complet'
    },
    'Administrateurs du domaine': {
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


def has_permission(user_groups, required_permission):
    """
    Vérifier si un utilisateur a une permission spécifique.
    
    Args:
        user_groups: Liste des groupes AD de l'utilisateur
        required_permission: Permission requise (ex: 'users:create')
    
    Returns:
        bool: True si l'utilisateur a la permission
    """
    if not user_groups:
        return False
    
    # Vérifier chaque groupe de l'utilisateur
    for group in user_groups:
        group_perms = get_group_permissions(group, user_groups)
        if required_permission in group_perms:
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
    Obtenir tous les groupes avec leurs permissions.
    
    Returns:
        dict: {group_name: {permissions: [], description: str, enabled: bool}}
    """
    permissions = load_permissions()
    result = {}
    
    # Groupes personnalisés
    for group_name, group_data in permissions.get('groups', {}).items():
        result[group_name] = {
            'permissions': group_data.get('permissions', []),
            'description': group_data.get('description', ''),
            'enabled': group_data.get('enabled', True),
            'custom': True
        }
    
    # Groupes prédéfinis (si pas déjà dans personnalisés)
    for group_name, role_data in PREDEFINED_ROLES.items():
        if group_name not in result:
            result[group_name] = {
                'permissions': role_data['permissions'],
                'description': role_data['description'],
                'enabled': True,
                'custom': False
            }
    
    return result


def set_group_permissions(group_name, permissions_list, description='', enabled=True):
    """
    Définir les permissions d'un groupe.
    
    Args:
        group_name: Nom du groupe AD
        permissions_list: Liste des permissions
        description: Description du rôle
        enabled: Groupe activé
    
    Returns:
        bool: True si sauvegardé avec succès
    """
    try:
        perms = load_permissions()
        
        if 'groups' not in perms:
            perms['groups'] = {}
        
        perms['groups'][group_name] = {
            'permissions': permissions_list,
            'description': description,
            'enabled': enabled,
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
