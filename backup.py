#!/usr/bin/env python3
"""
Systeme de backup et historique pour l'interface Web Active Directory.
Permet de sauvegarder les objets avant modification et de suivre les changements.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from config import get_config

config = get_config()

# Repertoire de backup
BACKUP_DIR = config.DATA_DIR / 'backups'
HISTORY_DIR = config.DATA_DIR / 'history'


def init_backup_dirs():
    """Initialiser les repertoires de backup et historique."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)


def backup_object(obj_type, dn, attributes):
    """
    Sauvegarder un objet AD avant modification.

    Args:
        obj_type: Type d'objet (user, group, ou, computer)
        dn: Distinguished Name de l'objet
        attributes: Dictionnaire des attributs actuels

    Returns:
        Chemin du fichier de backup
    """
    init_backup_dirs()

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_dn = dn.replace(',', '_').replace('=', '-').replace(' ', '_')[:100]
    filename = f"{obj_type}_{safe_dn}_{timestamp}.json"
    filepath = BACKUP_DIR / filename

    backup_data = {
        'timestamp': datetime.now().isoformat(),
        'object_type': obj_type,
        'dn': dn,
        'attributes': attributes
    }

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(backup_data, f, indent=2, ensure_ascii=False, default=str)

    return str(filepath)


def get_backups(obj_type=None, dn=None, limit=50):
    """
    Recuperer la liste des backups.

    Args:
        obj_type: Filtrer par type d'objet
        dn: Filtrer par DN
        limit: Nombre maximum de resultats

    Returns:
        Liste des backups
    """
    init_backup_dirs()
    backups = []

    for filepath in sorted(BACKUP_DIR.glob('*.json'), reverse=True):
        if len(backups) >= limit:
            break

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if obj_type and data.get('object_type') != obj_type:
                continue
            if dn and data.get('dn') != dn:
                continue

            data['filename'] = filepath.name
            backups.append(data)
        except Exception:
            continue

    return backups


def get_backup_content(filename):
    """Recuperer le contenu d'un backup specifique."""
    filepath = BACKUP_DIR / filename
    if filepath.exists():
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


def record_change(obj_type, dn, action, user, old_values=None, new_values=None, details=None):
    """
    Enregistrer un changement dans l'historique.

    Args:
        obj_type: Type d'objet (user, group, ou, computer)
        dn: Distinguished Name de l'objet
        action: Type d'action (create, modify, delete, etc.)
        user: Utilisateur qui effectue l'action
        old_values: Anciennes valeurs (pour modifications)
        new_values: Nouvelles valeurs (pour modifications)
        details: Details supplementaires
    """
    init_backup_dirs()

    # Fichier d'historique par objet
    safe_dn = dn.replace(',', '_').replace('=', '-').replace(' ', '_')[:100]
    history_file = HISTORY_DIR / f"{obj_type}_{safe_dn}.json"

    # Charger l'historique existant
    history = []
    if history_file.exists():
        try:
            with open(history_file, 'r', encoding='utf-8') as f:
                history = json.load(f)
        except Exception:
            history = []

    # Ajouter l'entree
    entry = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'user': user,
        'old_values': old_values,
        'new_values': new_values,
        'details': details
    }
    history.append(entry)

    # Sauvegarder
    with open(history_file, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=2, ensure_ascii=False, default=str)


def get_object_history(obj_type, dn):
    """
    Recuperer l'historique des changements pour un objet.

    Args:
        obj_type: Type d'objet
        dn: Distinguished Name

    Returns:
        Liste des changements (plus recent en premier)
    """
    init_backup_dirs()

    safe_dn = dn.replace(',', '_').replace('=', '-').replace(' ', '_')[:100]
    history_file = HISTORY_DIR / f"{obj_type}_{safe_dn}.json"

    if history_file.exists():
        try:
            with open(history_file, 'r', encoding='utf-8') as f:
                history = json.load(f)
                return list(reversed(history))
        except Exception:
            pass

    return []


def get_all_history(limit=100):
    """
    Recuperer tout l'historique recent.

    Args:
        limit: Nombre maximum d'entrees

    Returns:
        Liste des changements recents
    """
    init_backup_dirs()
    all_entries = []

    for filepath in HISTORY_DIR.glob('*.json'):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                history = json.load(f)

            # Extraire le type et DN du nom de fichier
            parts = filepath.stem.split('_', 1)
            obj_type = parts[0] if parts else 'unknown'

            for entry in history:
                entry['object_type'] = obj_type
                entry['filename'] = filepath.stem
                all_entries.append(entry)
        except Exception:
            continue

    # Trier par timestamp decroissant
    all_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    return all_entries[:limit]
