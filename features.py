"""
Module utilitaire pour les Feature Flags.
Permet de vérifier si une fonctionnalité est activée et d'afficher des pages de fonctionnalité désactivée.
"""

from flask import render_template, abort
from config import get_config

config = get_config()

# Dictionnaire de toutes les fonctionnalités
FEATURE_FLAGS = {
    # Utilisateurs
    'users': config.FEATURE_USERS_ENABLED,
    'create_user': config.FEATURE_CREATE_USER_ENABLED,
    'edit_user': config.FEATURE_EDIT_USER_ENABLED,
    'delete_user': config.FEATURE_DELETE_USER_ENABLED,
    'import_users': config.FEATURE_IMPORT_USERS_ENABLED,
    'export_users': config.FEATURE_EXPORT_USERS_ENABLED,
    
    # Groupes
    'groups': config.FEATURE_GROUPS_ENABLED,
    'create_group': config.FEATURE_CREATE_GROUP_ENABLED,
    'edit_group': config.FEATURE_EDIT_GROUP_ENABLED,
    'delete_group': config.FEATURE_DELETE_GROUP_ENABLED,
    
    # Ordinateurs
    'computers': config.FEATURE_COMPUTERS_ENABLED,
    'laps': config.FEATURE_LAPS_ENABLED,
    'bitlocker': config.FEATURE_BITLOCKER_ENABLED,
    
    # OUs
    'ous': config.FEATURE_OUS_ENABLED,
    
    # Outils avancés
    'recycle_bin': config.FEATURE_RECYCLE_BIN_ENABLED,
    'locked_accounts': config.FEATURE_LOCKED_ACCOUNTS_ENABLED,
    'expiring_accounts': config.FEATURE_EXPIRING_ACCOUNTS_ENABLED,
    'password_policy': config.FEATURE_PASSWORD_POLICY_ENABLED,
    'password_audit': config.FEATURE_PASSWORD_AUDIT_ENABLED,
    
    # Administration
    'audit_logs': config.FEATURE_AUDIT_LOGS_ENABLED,
    'backups': config.FEATURE_BACKUPS_ENABLED,
    'diagnostic': config.FEATURE_DIAGNOSTIC_ENABLED,
    'api_docs': config.FEATURE_API_DOCS_ENABLED,
    'settings': config.FEATURE_SETTINGS_ENABLED,
    
    # Fonctionnalités utilisateur
    'favorites': config.FEATURE_FAVORITES_ENABLED,
    'templates': config.FEATURE_TEMPLATES_ENABLED,
    'dark_mode': config.FEATURE_DARK_MODE_ENABLED,
    'language_switch': config.FEATURE_LANGUAGE_SWITCH_ENABLED,
    
    # Système
    'update_check': config.FEATURE_UPDATE_CHECK_ENABLED,
    'pwa': config.FEATURE_PWA_ENABLED,
}


def is_feature_enabled(feature_name):
    """
    Vérifier si une fonctionnalité est activée.
    
    Args:
        feature_name: Nom de la fonctionnalité
        
    Returns:
        bool: True si activée, False sinon
    """
    return FEATURE_FLAGS.get(feature_name, False)


def require_feature(feature_name):
    """
    Décorateur pour exiger qu'une fonctionnalité soit activée.
    
    Args:
        feature_name: Nom de la fonctionnalité
        
    Returns:
        Décorateur Flask
    """
    from functools import wraps
    from flask import request
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not is_feature_enabled(feature_name):
                # Retourner une page "fonctionnalité désactivée"
                return render_template('feature_disabled.html', 
                                     feature_name=feature_name,
                                     connected=False), 503
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_enabled_features():
    """
    Obtenir la liste des fonctionnalités activées.
    
    Returns:
        list: Liste des noms de fonctionnalités activées
    """
    return [name for name, enabled in FEATURE_FLAGS.items() if enabled]


def get_disabled_features():
    """
    Obtenir la liste des fonctionnalités désactivées.
    
    Returns:
        list: Liste des noms de fonctionnalités désactivées
    """
    return [name for name, enabled in FEATURE_FLAGS.items() if not enabled]


def get_feature_status():
    """
    Obtenir le statut de toutes les fonctionnalités.
    
    Returns:
        dict: Dictionnaire {nom: enabled}
    """
    return FEATURE_FLAGS.copy()
