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
        'logo_height': '40px',  # Hauteur du logo
        'logo_position': 'left',  # left, center, right
        'footer': 'Active Directory Web Interface - Compatible Windows & Linux',
        'theme_color': '#0078d4',
        'custom_css': ''  # CSS personnalise additionnel
    },
    'menu': {
        # Section "Gestion" — visible par tous les utilisateurs connectés
        # endpoint : nom Flask complet (blueprint.fonction ou fonction)
        # icon : caractère unicode (évite les dépendances à des librairies d'icônes)
        'items': [
            {'id': 'dashboard',  'label': 'Tableau de bord', 'endpoint': 'dashboard',               'icon': '📊', 'enabled': True,  'order': 1},
            {'id': 'users',      'label': 'Utilisateurs',    'endpoint': 'users.list_users',         'icon': '👥', 'enabled': True,  'order': 2},
            {'id': 'groups',     'label': 'Groupes',         'endpoint': 'groups.list_groups',       'icon': '👨‍👩‍👧‍👦', 'enabled': True,  'order': 3},
            {'id': 'computers',  'label': 'Ordinateurs',     'endpoint': 'computers.list_computers', 'icon': '💻', 'enabled': True,  'order': 4},
            {'id': 'ous',        'label': "Unités d'org.",   'endpoint': 'ous',                      'icon': '📁', 'enabled': True,  'order': 5},
            {'id': 'search',     'label': 'Recherche',       'endpoint': 'global_search',            'icon': '🔎', 'enabled': False, 'order': 6},
        ],
        # Section "Outils" — visible par les admins uniquement
        'tool_items': [
            {'id': 'laps',          'label': 'LAPS',            'endpoint': 'tools.laps_passwords',  'icon': '🔑', 'feature': 'FEATURE_LAPS_ENABLED',             'enabled': True,  'order': 1},
            {'id': 'bitlocker',     'label': 'BitLocker',       'endpoint': 'tools.bitlocker_keys',  'icon': '🔐', 'feature': 'FEATURE_BITLOCKER_ENABLED',         'enabled': True,  'order': 2},
            {'id': 'recycle',       'label': 'Corbeille',       'endpoint': 'tools.recycle_bin',     'icon': '🗑️', 'feature': 'FEATURE_RECYCLE_BIN_ENABLED',       'enabled': True,  'order': 3},
            {'id': 'locked',        'label': 'Comptes verrouillés', 'endpoint': 'tools.locked_accounts', 'icon': '🔒', 'feature': 'FEATURE_LOCKED_ACCOUNTS_ENABLED', 'enabled': True, 'order': 4},
            {'id': 'expiring',      'label': 'Expirations',     'endpoint': 'tools.expiring_accounts', 'icon': '⏰', 'feature': 'FEATURE_EXPIRING_ACCOUNTS_ENABLED', 'enabled': True, 'order': 5},
            {'id': 'pwd_policy',    'label': 'Politique MDP',   'endpoint': 'tools.password_policy', 'icon': '🛡️', 'feature': 'FEATURE_PASSWORD_POLICY_ENABLED',   'enabled': True,  'order': 6},
            {'id': 'pwd_audit',     'label': 'Audit MDP',       'endpoint': 'tools.password_audit',  'icon': '🔍', 'feature': 'FEATURE_PASSWORD_AUDIT_ENABLED',    'enabled': True,  'order': 7},
        ],
        # Section "Administration" — visible par les admins uniquement
        'admin_items': [
            {'id': 'alerts',     'label': 'Alertes',      'endpoint': 'tools.alerts',       'icon': '🔔', 'feature': None,                          'enabled': True,  'order': 1},
            {'id': 'audit',      'label': 'Audit',        'endpoint': 'audit_logs',         'icon': '📋', 'feature': 'FEATURE_AUDIT_LOGS_ENABLED',  'enabled': True,  'order': 2},
            {'id': 'diagnostic', 'label': 'Diagnostic',   'endpoint': 'diagnostic_page',    'icon': '🔧', 'feature': 'FEATURE_DIAGNOSTIC_ENABLED',  'enabled': True,  'order': 3},
            {'id': 'backups',    'label': 'Sauvegardes',  'endpoint': 'tools.backups',      'icon': '💾', 'feature': 'FEATURE_BACKUPS_ENABLED',     'enabled': True,  'order': 4},
            {'id': 'admin',      'label': 'Admin',        'endpoint': 'admin.admin_page',   'icon': '⚙️', 'feature': 'FEATURE_SETTINGS_ENABLED',   'enabled': True,  'order': 5},
        ],
    },
    'features': {
        'dark_mode': True,
        'language_switch': False,
        'update_check': True,
        'pwa_enabled': True,
        'custom_logo': False,
        'show_footer': True
    },
    'security': {
        'session_timeout': 30,  # minutes
        'max_login_attempts': 5,
        'require_https': False
    },
    'branding': {
        'primary_color': '#0078d4',
        'secondary_color': '#107c10',
        'danger_color': '#d13438',
        'warning_color': '#ffb900',
        'info_color': '#00b7c3',
        'font_family': 'Segoe UI, sans-serif',
        'border_radius': '8px',
        'show_branding': True  # Afficher "Powered by AD Web Interface"
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


def _sorted_enabled(items):
    return sorted([i for i in items if i.get('enabled', True)], key=lambda x: x.get('order', 99))


def get_menu_items():
    """Éléments de la section Gestion (tous utilisateurs connectés)."""
    settings = load_settings()
    return _sorted_enabled(settings.get('menu', {}).get('items', []))


def get_tool_items():
    """Éléments de la section Outils (admins uniquement)."""
    settings = load_settings()
    return _sorted_enabled(settings.get('menu', {}).get('tool_items', []))


def get_admin_items():
    """Éléments de la section Administration (admins uniquement)."""
    settings = load_settings()
    return _sorted_enabled(settings.get('menu', {}).get('admin_items', []))


def get_dropdown_items():
    """Alias conservé pour compatibilité — retourne tool_items."""
    return get_tool_items()


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
