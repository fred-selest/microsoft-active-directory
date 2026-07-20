"""
Permissions Granulaires - Gestion fine des droits par groupe AD
"""
import json
import logging
import os
from pathlib import Path
from datetime import datetime

logger = logging.getLogger('granular_permissions')

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
    'tools:unlock_accounts': 'Déverrouiller des comptes',
    'tools:expiring_accounts': 'Voir comptes expirants',
    'tools:password_policy': 'Voir politique MDP',
    'tools:password_audit': 'Audit MDP',
    'tools:expiring_pdf': 'Export PDF expirants',
    'tools:recycle_bin': 'Corbeille AD (voir et restaurer)',
    'tools:laps': 'Consulter les mots de passe LAPS',
    'tools:bitlocker': 'Consulter les clés de récupération BitLocker',

    # Admin
    'admin:settings': 'Paramètres',
    'admin:backups': 'Sauvegardes',
    'admin:audit_logs': 'Logs d\'audit',
    'admin:diagnostic': 'Diagnostic',
    'admin:security_audit': 'Audit de sécurité',
    'admin:alerts': 'Alertes',
    'admin:user_templates': 'Modèles utilisateurs',
    'admin:permissions': 'Gérer les permissions (méta — donne le pouvoir de tout s\'accorder)',
    'admin:api_keys': 'Générer et révoquer les clés API',
    'admin:log_analysis': 'Analyse des logs',

    # Système — actions à fort impact sur le contrôleur de domaine
    'system:execute_script': 'Exécuter des scripts PowerShell sur le DC',
    'system:update': 'Déclencher une mise à jour de l\'application',
    'system:configure_ldaps': 'Configurer LDAPS / LAPS sur le domaine',
}

# Permissions considérées comme sensibles : elles permettent, directement ou
# indirectement, d'obtenir un contrôle complet sur le domaine. A n'accorder
# qu'aux administrateurs. Utilisé par l'UI pour afficher un avertissement.
SENSITIVE_PERMISSIONS = {
    'system:execute_script',
    'system:update',
    'system:configure_ldaps',
    'admin:permissions',
    'admin:settings',
    'tools:laps',
    'tools:bitlocker',
}

# Rôles prédéfinis avec permissions
# (uniquement les groupes AD natifs en français)
PREDEFINED_ROLES = {
    'Administrateurs du domaine': {
        'permissions': list(ALL_PERMISSIONS.keys()),
        'description': 'Accès complet'
    },
    'Administrateurs de l\'entreprise': {
        'permissions': list(ALL_PERMISSIONS.keys()),
        'description': 'Accès complet'
    },
    'Utilisateurs du domaine': {
        'permissions': [
            'users:read',
            'groups:read',
            'computers:read',
            'ous:read',
        ],
        'description': 'Lecture seule'
    },
}

# NOTE SECURITE (constat C1 de AUDIT_2026-07-20.md)
#
# Ce module exposait auparavant un LEGACY_PERMISSION_MAPPING traduisant des
# alias larges ('admin', 'write', 'delete') en listes de permissions, combiné
# à un contrôle par *intersection* :
#
#     if entry_perms & required_permissions:   # <- accordait sur 1 seul match
#         return True
#
# Comme 'admin' était traduit en la totalité des permissions, n'importe quelle
# permission unique (par ex. 'users:read') satisfaisait require_permission('admin')
# et donnait accès aux 64 routes d'administration, dont l'exécution de scripts
# PowerShell sur le contrôleur de domaine.
#
# Le mapping a été supprimé et le contrôle passé en *inclusion* (voir
# has_permission ci-dessous). Les gardes de routes utilisent désormais des
# permissions granulaires. Ne pas réintroduire d'alias à large périmètre.


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


def get_effective_permissions(user_groups, username=None, user_dn=None):
    """
    Calculer l'ensemble des permissions effectives d'un utilisateur.

    Les permissions s'additionnent : entrées personnalisées correspondantes
    (groupe / utilisateur / OU) + rôles prédéfinis des groupes de l'utilisateur.

    Args:
        user_groups: Liste des noms de groupes AD (CN) de l'utilisateur
        username: sAMAccountName ou DOMAINE\\login
        user_dn: DN complet de l'utilisateur (pour les règles de type 'ou')

    Returns:
        set: Permissions effectives
    """
    effective = set()

    permissions_data = load_permissions()
    custom_groups = permissions_data.get('groups', {})

    # Entrées personnalisées (group / user / ou)
    for subject_name, entry in custom_groups.items():
        if not entry.get('enabled', True):
            continue

        subject_type = entry.get('subject_type', 'group')
        matched = False

        if subject_type == 'group':
            matched = subject_name in (user_groups or [])
        elif subject_type == 'user':
            if username:
                sam = username.split('\\')[-1].split('@')[0]
                matched = sam.lower() == subject_name.lower()
        elif subject_type == 'ou':
            matched = bool(user_dn) and subject_name.lower() in user_dn.lower()

        if matched:
            effective |= set(entry.get('permissions', []))

    # Rôles prédéfinis (type 'group' uniquement)
    for group in (user_groups or []):
        if group in PREDEFINED_ROLES:
            effective |= set(PREDEFINED_ROLES[group]['permissions'])

    return effective


def has_permission(user_groups, required_permission, username=None, user_dn=None):
    """
    Vérifier si un utilisateur détient une permission.

    Le contrôle se fait par INCLUSION : la permission demandée doit figurer
    explicitement dans les permissions effectives de l'utilisateur. Voir la
    note de sécurité en tête de module (constat C1) — un contrôle par
    intersection accordait auparavant l'accès administrateur à quiconque
    détenait une permission quelconque.

    Args:
        user_groups: Liste des noms de groupes AD (CN) de l'utilisateur
        required_permission: Permission requise, ex. 'users:delete'
        username: sAMAccountName ou DOMAINE\\login
        user_dn: DN complet de l'utilisateur

    Returns:
        bool: True si la permission est accordée
    """
    if not user_groups and not username:
        return False

    # Une permission inconnue est refusée. Cela transforme une faute de frappe
    # dans un garde de route en refus d'accès (visible, corrigeable) plutôt
    # qu'en autorisation silencieuse.
    if required_permission not in ALL_PERMISSIONS:
        logger.error(
            f"Permission inconnue demandée: '{required_permission}' — accès refusé. "
            f"Vérifiez le garde @require_permission correspondant."
        )
        return False

    effective = get_effective_permissions(user_groups, username=username, user_dn=user_dn)

    if required_permission in effective:
        logger.debug(f"Permission '{required_permission}' accordée à {username}")
        return True

    # Filet de sécurité : les administrateurs du domaine (déterminés par
    # config.ADMIN_GROUPS lors de la connexion) conservent un accès complet,
    # afin qu'une configuration de permissions erronée ne puisse pas verrouiller
    # définitivement l'accès à l'application.
    from flask import session
    if session.get('user_role') == 'admin':
        logger.debug(
            f"Permission '{required_permission}' accordée à {username} "
            f"via le filet de sécurité 'administrateur du domaine'"
        )
        return True

    logger.info(
        f"Permission '{required_permission}' refusée à {username} "
        f"(groupes={user_groups})"
    )
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
    # Construit dynamiquement depuis ALL_PERMISSIONS : ajouter une permission
    # dans une nouvelle categorie suffit pour qu'elle apparaisse dans l'UI,
    # sans avoir a maintenir cette liste en parallele.
    categories = {}

    for perm in ALL_PERMISSIONS.keys():
        category = perm.split(':')[0]
        categories.setdefault(category, []).append(perm)

    return categories
