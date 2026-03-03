#!/usr/bin/env python3
"""
Vérification et application rapide des mises à jour.
Wrapper structuré autour de updater.py.
"""
from pathlib import Path
from updater import (get_current_version, get_remote_version,
                     get_file_list, download_file, should_skip)


def check_for_updates_fast():
    """
    Vérifier rapidement si une mise à jour est disponible.

    Retourne un dict avec les clés :
      update_available (bool), current_version (str),
      latest_version (str|None), error (str|None)
    """
    current = get_current_version()
    try:
        latest = get_remote_version()
        if latest is None:
            return {
                'update_available': False,
                'current_version': current,
                'latest_version': None,
                'error': 'Impossible de contacter le serveur de mise à jour'
            }
        return {
            'update_available': latest != current,
            'current_version': current,
            'latest_version': latest,
            'error': None
        }
    except Exception as e:
        return {
            'update_available': False,
            'current_version': current,
            'latest_version': None,
            'error': str(e)
        }


def perform_fast_update(silent=False):
    """
    Télécharger et appliquer la mise à jour.

    Retourne un dict avec les clés :
      success (bool), files_updated (int), errors (list[str])
    """
    app_dir = Path(__file__).parent

    if not silent:
        print("Récupération de la liste des fichiers...")

    files = get_file_list()
    if not files:
        return {
            'success': False,
            'files_updated': 0,
            'errors': ['Impossible de récupérer la liste des fichiers depuis GitHub']
        }

    files_to_update = [f for f in files if not should_skip(f)]
    errors = []
    updated = 0

    for filepath in files_to_update:
        try:
            if download_file(filepath, app_dir):
                updated += 1
            else:
                errors.append(filepath)
        except Exception as e:
            errors.append(f"{filepath}: {e}")

    return {
        'success': len(errors) == 0,
        'files_updated': updated,
        'errors': errors
    }
