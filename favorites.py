"""
Module de gestion des favoris pour l'interface Web Active Directory.
Permet aux utilisateurs de marquer des objets comme favoris.
"""

import json
import os
from datetime import datetime

FAVORITES_FILE = 'data/favorites.json'


def load_favorites():
    """Charger les favoris depuis le fichier."""
    try:
        if os.path.exists(FAVORITES_FILE):
            with open(FAVORITES_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}


def save_favorites(favorites):
    """Sauvegarder les favoris dans le fichier."""
    os.makedirs(os.path.dirname(FAVORITES_FILE), exist_ok=True)
    with open(FAVORITES_FILE, 'w') as f:
        json.dump(favorites, f, indent=2, ensure_ascii=False)


def get_user_favorites(username):
    """
    Obtenir les favoris d'un utilisateur.

    Args:
        username: Nom d'utilisateur

    Returns:
        Liste des favoris de l'utilisateur
    """
    favorites = load_favorites()
    return favorites.get(username, [])


def add_favorite(username, obj_type, dn, name, description=''):
    """
    Ajouter un objet aux favoris.

    Args:
        username: Nom d'utilisateur
        obj_type: Type d'objet (user, group, computer, ou)
        dn: Distinguished Name de l'objet
        name: Nom affiche
        description: Description optionnelle

    Returns:
        True si ajoute, False si deja present
    """
    favorites = load_favorites()

    if username not in favorites:
        favorites[username] = []

    # Verifier si deja favori
    for fav in favorites[username]:
        if fav['dn'] == dn:
            return False

    favorites[username].append({
        'type': obj_type,
        'dn': dn,
        'name': name,
        'description': description,
        'added': datetime.now().isoformat()
    })

    save_favorites(favorites)
    return True


def remove_favorite(username, dn):
    """
    Retirer un objet des favoris.

    Args:
        username: Nom d'utilisateur
        dn: Distinguished Name de l'objet

    Returns:
        True si retire, False si non trouve
    """
    favorites = load_favorites()

    if username not in favorites:
        return False

    initial_count = len(favorites[username])
    favorites[username] = [f for f in favorites[username] if f['dn'] != dn]

    if len(favorites[username]) < initial_count:
        save_favorites(favorites)
        return True

    return False


def is_favorite(username, dn):
    """
    Verifier si un objet est dans les favoris.

    Args:
        username: Nom d'utilisateur
        dn: Distinguished Name de l'objet

    Returns:
        True si favori, False sinon
    """
    favorites = load_favorites()

    if username not in favorites:
        return False

    for fav in favorites[username]:
        if fav['dn'] == dn:
            return True

    return False


def get_favorites_by_type(username, obj_type):
    """
    Obtenir les favoris d'un type specifique.

    Args:
        username: Nom d'utilisateur
        obj_type: Type d'objet (user, group, computer, ou)

    Returns:
        Liste des favoris du type specifie
    """
    favorites = get_user_favorites(username)
    return [f for f in favorites if f['type'] == obj_type]


def get_favorites_count(username):
    """
    Obtenir le nombre de favoris par type.

    Args:
        username: Nom d'utilisateur

    Returns:
        Dictionnaire avec les compteurs
    """
    favorites = get_user_favorites(username)

    counts = {
        'total': len(favorites),
        'user': 0,
        'group': 0,
        'computer': 0,
        'ou': 0
    }

    for fav in favorites:
        obj_type = fav.get('type', 'other')
        if obj_type in counts:
            counts[obj_type] += 1

    return counts


def clear_favorites(username):
    """
    Supprimer tous les favoris d'un utilisateur.

    Args:
        username: Nom d'utilisateur
    """
    favorites = load_favorites()

    if username in favorites:
        del favorites[username]
        save_favorites(favorites)
