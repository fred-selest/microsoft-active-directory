"""
Gestionnaire de parametres pour l'interface d'administration.
Permet de configurer dynamiquement le logo, menus, couleurs, etc.
"""

import json
import os

SETTINGS_FILE = os.path.join(os.path.dirname(__file__), 'data', 'settings.json')

DEFAULT_SETTINGS = {
    'site': {
        'title': 'AD Web Interface',
        'logo': '',  # Chemin vers le logo personnalise
        'footer': 'Active Directory Web Interface - Compatible Windows & Linux',
        'theme_color': '#0078d4'
    },
    'menu': {
        'items': [
            {'id': 'dashboard', 'label': 'Tableau de bord', 'url': 'dashboard', 'enabled': True, 'order': 1},
            {'id': 'search', 'label': 'Recherche', 'url': 'global_search', 'enabled': True, 'order': 2},
            {'id': 'users', 'label': 'Utilisateurs', 'url': 'users', 'enabled': True, 'order': 3},
            {'id': 'groups', 'label': 'Groupes', 'url': 'groups', 'enabled': True, 'order': 4},
            {'id': 'computers', 'label': 'Ordinateurs', 'url': 'computers', 'enabled': True, 'order': 5},
            {'id': 'structure', 'label': 'Structure', 'url': 'ous', 'enabled': True, 'order': 6}
        ],
        'dropdown_items': [
            {'id': 'laps', 'label': 'LAPS', 'url': 'laps_passwords', 'enabled': True, 'order': 1},
            {'id': 'bitlocker', 'label': 'BitLocker', 'url': 'bitlocker_keys', 'enabled': True, 'order': 2},
            {'id': 'recycle', 'label': 'Corbeille', 'url': 'recycle_bin', 'enabled': True, 'order': 3},
            {'id': 'templates', 'label': 'Modeles', 'url': 'user_templates_page', 'enabled': True, 'order': 4},
            {'id': 'favorites', 'label': 'Favoris', 'url': 'favorites_page', 'enabled': True, 'order': 5},
            {'id': 'expiring', 'label': 'Expirations', 'url': 'expiring_accounts', 'enabled': True, 'order': 6},
            {'id': 'alerts', 'label': 'Alertes', 'url': 'alerts_page', 'enabled': True, 'order': 7},
            {'id': 'audit', 'label': 'Audit', 'url': 'audit_logs', 'enabled': True, 'order': 8},
            {'id': 'api', 'label': 'API', 'url': 'api_documentation_page', 'enabled': True, 'order': 9}
        ]
    },
    'features': {
        'dark_mode': True,
        'language_switch': False,
        'update_check': True,
        'pwa_enabled': True
    },
    'security': {
        'session_timeout': 30,  # minutes
        'max_login_attempts': 5,
        'require_https': False
    }
}


def ensure_data_dir():
    """S'assurer que le repertoire data existe."""
    data_dir = os.path.dirname(SETTINGS_FILE)
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)


def load_settings():
    """Charger les parametres depuis le fichier JSON."""
    ensure_data_dir()

    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                settings = json.load(f)
                # Fusionner avec les parametres par defaut pour les nouvelles options
                return merge_settings(DEFAULT_SETTINGS, settings)
        except Exception as e:
            print(f"Erreur chargement parametres: {e}")

    return DEFAULT_SETTINGS.copy()


def save_settings(settings):
    """Sauvegarder les parametres dans le fichier JSON."""
    ensure_data_dir()

    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Erreur sauvegarde parametres: {e}")
        return False


def merge_settings(default, current):
    """Fusionner les parametres actuels avec les valeurs par defaut."""
    result = default.copy()

    for key, value in current.items():
        if key in result:
            if isinstance(value, dict) and isinstance(result[key], dict):
                result[key] = merge_settings(result[key], value)
            else:
                result[key] = value
        else:
            result[key] = value

    return result


def get_setting(path, default=None):
    """
    Obtenir une valeur de parametre par son chemin.
    Exemple: get_setting('site.title') retourne le titre du site.
    """
    settings = load_settings()
    keys = path.split('.')
    value = settings

    try:
        for key in keys:
            value = value[key]
        return value
    except (KeyError, TypeError):
        return default


def set_setting(path, value):
    """
    Definir une valeur de parametre par son chemin.
    Exemple: set_setting('site.title', 'Mon Site')
    """
    settings = load_settings()
    keys = path.split('.')

    # Naviguer jusqu'au dernier niveau
    current = settings
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]

    # Definir la valeur
    current[keys[-1]] = value

    return save_settings(settings)


def reset_settings():
    """Reinitialiser les parametres aux valeurs par defaut."""
    return save_settings(DEFAULT_SETTINGS.copy())


def get_menu_items():
    """Obtenir les elements du menu principal tries par ordre."""
    settings = load_settings()
    items = settings.get('menu', {}).get('items', [])
    return sorted([item for item in items if item.get('enabled', True)], key=lambda x: x.get('order', 99))


def get_dropdown_items():
    """Obtenir les elements du menu deroulant tries par ordre."""
    settings = load_settings()
    items = settings.get('menu', {}).get('dropdown_items', [])
    return sorted([item for item in items if item.get('enabled', True)], key=lambda x: x.get('order', 99))


def update_menu_item(item_id, updates, is_dropdown=False):
    """Mettre a jour un element de menu."""
    settings = load_settings()
    menu_key = 'dropdown_items' if is_dropdown else 'items'
    items = settings.get('menu', {}).get(menu_key, [])

    for item in items:
        if item.get('id') == item_id:
            item.update(updates)
            break

    return save_settings(settings)
