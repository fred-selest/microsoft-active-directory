"""
Module de validation des chemins pour prévenir les attaques path traversal.
"""

import os
from pathlib import Path


def is_safe_path(base_dir: Path, target_path: Path) -> bool:
    """
    Vérifie qu'un chemin cible est bien à l'intérieur d'un répertoire de base.
    Prévient les attaques path traversal (ex: ../../../etc/passwd).

    Args:
        base_dir: Le répertoire de base autorisé
        target_path: Le chemin à vérifier

    Returns:
        True si le chemin est sûr, False sinon
    """
    try:
        # Résoudre les chemins pour éliminer les .. et les liens symboliques
        base_resolved = base_dir.resolve()
        target_resolved = target_path.resolve()

        # Vérifier que le chemin cible commence par le chemin de base
        return str(target_resolved).startswith(str(base_resolved))
    except (OSError, ValueError):
        return False


def sanitize_filename(filename: str, max_length: int = 100) -> str:
    """
    Nettoie un nom de fichier pour le rendre sûr.
    Supprime les caractères dangereux et limite la longueur.

    Args:
        filename: Le nom de fichier à nettoyer
        max_length: Longueur maximale du nom de fichier

    Returns:
        Le nom de fichier nettoyé
    """
    if not filename:
        return "unnamed"

    # Caractères dangereux à supprimer ou remplacer
    dangerous_chars = ['/', '\\', '..', '\x00', '\n', '\r', '<', '>', ':', '"', '|', '?', '*']

    safe_name = filename
    for char in dangerous_chars:
        safe_name = safe_name.replace(char, '_')

    # Supprimer les espaces au début et à la fin
    safe_name = safe_name.strip()

    # Supprimer les points au début (fichiers cachés)
    safe_name = safe_name.lstrip('.')

    # Limiter la longueur
    if len(safe_name) > max_length:
        # Conserver l'extension si présente
        name, ext = os.path.splitext(safe_name)
        if ext:
            safe_name = name[:max_length - len(ext)] + ext
        else:
            safe_name = safe_name[:max_length]

    # Si le nom est vide après nettoyage, utiliser un nom par défaut
    if not safe_name:
        safe_name = "unnamed"

    return safe_name


def safe_join(base_dir: Path, *paths) -> Path:
    """
    Joint des chemins de manière sécurisée.
    Vérifie que le résultat reste dans le répertoire de base.

    Args:
        base_dir: Le répertoire de base
        *paths: Les sous-chemins à joindre

    Returns:
        Le chemin joint si sûr

    Raises:
        ValueError: Si le chemin résultant sort du répertoire de base
    """
    # Nettoyer chaque composant
    safe_paths = [sanitize_filename(str(p)) for p in paths]

    # Construire le chemin
    result = base_dir
    for p in safe_paths:
        result = result / p

    # Vérifier la sécurité
    if not is_safe_path(base_dir, result):
        raise ValueError(f"Tentative d'accès path traversal détectée: {'/'.join(safe_paths)}")

    return result


def validate_dn_for_filename(dn: str) -> str:
    """
    Convertit un Distinguished Name en nom de fichier sûr.

    Args:
        dn: Le Distinguished Name AD

    Returns:
        Une version sûre pour utilisation comme nom de fichier
    """
    if not dn:
        return "unknown"

    # Remplacer les séparateurs DN par des underscores
    safe_dn = dn.replace(',', '_').replace('=', '-').replace(' ', '_')

    # Appliquer la sanitization standard
    return sanitize_filename(safe_dn, max_length=100)
