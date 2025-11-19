#!/usr/bin/env python3
"""
Systeme de journal d'audit pour l'interface Web Active Directory.
Enregistre toutes les actions effectuees par les utilisateurs.
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from config import get_config

config = get_config()

# Configuration du logger d'audit
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)

# Handler pour fichier
log_file = config.LOG_DIR / 'audit.log'
file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setLevel(logging.INFO)

# Format du log
formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
file_handler.setFormatter(formatter)
audit_logger.addHandler(file_handler)


def log_action(action, user, details=None, success=True, ip_address=None):
    """
    Enregistrer une action dans le journal d'audit.

    Args:
        action: Type d'action (create_user, delete_user, modify_group, etc.)
        user: Utilisateur qui effectue l'action
        details: Details supplementaires (dict)
        success: True si l'action a reussi
        ip_address: Adresse IP de l'utilisateur
    """
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'user': user,
        'success': success,
        'ip_address': ip_address or 'unknown',
        'details': details or {}
    }

    # Format lisible pour le log
    status = 'SUCCESS' if success else 'FAILED'
    details_str = json.dumps(details) if details else ''

    audit_logger.info(f"{status} | {action} | {user} | {ip_address} | {details_str}")

    return log_entry


def get_audit_logs(limit=100, action_filter=None, user_filter=None):
    """
    Recuperer les logs d'audit.

    Args:
        limit: Nombre maximum de logs a retourner
        action_filter: Filtrer par type d'action
        user_filter: Filtrer par utilisateur

    Returns:
        Liste des logs
    """
    logs = []
    log_file = config.LOG_DIR / 'audit.log'

    if not log_file.exists():
        return logs

    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Parcourir les lignes en ordre inverse (plus recent en premier)
        for line in reversed(lines):
            if len(logs) >= limit:
                break

            try:
                # Parser la ligne de log
                parts = line.strip().split(' - ', 1)
                if len(parts) != 2:
                    continue

                timestamp = parts[0]
                content = parts[1]

                # Parser le contenu
                content_parts = content.split(' | ')
                if len(content_parts) < 4:
                    continue

                status = content_parts[0]
                action = content_parts[1]
                user = content_parts[2]
                ip = content_parts[3]
                details = content_parts[4] if len(content_parts) > 4 else '{}'

                # Appliquer les filtres
                if action_filter and action_filter.lower() not in action.lower():
                    continue
                if user_filter and user_filter.lower() not in user.lower():
                    continue

                logs.append({
                    'timestamp': timestamp,
                    'status': status,
                    'action': action,
                    'user': user,
                    'ip': ip,
                    'details': json.loads(details) if details and details != '{}' else {}
                })

            except Exception:
                continue

    except Exception as e:
        print(f"Erreur lecture logs: {e}")

    return logs


# Actions predefinies
ACTIONS = {
    # Utilisateurs
    'CREATE_USER': 'create_user',
    'EDIT_USER': 'edit_user',
    'DELETE_USER': 'delete_user',
    'ENABLE_USER': 'enable_user',
    'DISABLE_USER': 'disable_user',
    'RESET_PASSWORD': 'reset_password',
    'MOVE_USER': 'move_user',

    # Groupes
    'CREATE_GROUP': 'create_group',
    'EDIT_GROUP': 'edit_group',
    'DELETE_GROUP': 'delete_group',
    'ADD_MEMBER': 'add_group_member',
    'REMOVE_MEMBER': 'remove_group_member',

    # OUs
    'CREATE_OU': 'create_ou',
    'EDIT_OU': 'edit_ou',
    'DELETE_OU': 'delete_ou',

    # Session
    'LOGIN': 'login',
    'LOGOUT': 'logout',

    # Import/Export
    'IMPORT_USERS': 'import_users',
    'EXPORT_USERS': 'export_users',

    # Bulk
    'BULK_OPERATION': 'bulk_operation',
}
