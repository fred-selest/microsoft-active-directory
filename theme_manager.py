"""
Gestionnaire de thèmes pour AD Web Interface
Permet de changer et personnaliser les thèmes de l'application
"""

import json
import os
from pathlib import Path

THEMES_DIR = Path('data/themes')
DEFAULT_THEME = 'default'

DEFAULT_THEMES = {
    'default': {
        'name': 'Défaut',
        'primary_color': '#0078d4',
        'secondary_color': '#107c10',
        'danger_color': '#d13438',
        'warning_color': '#ffb900',
        'info_color': '#00b7c3',
        'success_color': '#28a745',
        'bg_light': '#ffffff',
        'bg_dark': '#1a1a2e',
        'text_light': '#333333',
        'text_dark': '#ffffff',
        'border_radius': '8px',
        'font_family': 'Segoe UI, sans-serif',
        'sidebar_position': 'left',
        'layout': 'default'
    },
    'dark': {
        'name': 'Sombre',
        'primary_color': '#00d9ff',
        'secondary_color': '#00ff88',
        'danger_color': '#ff4444',
        'warning_color': '#ffbb00',
        'info_color': '#44aaff',
        'success_color': '#00cc66',
        'bg_light': '#2d2d2d',
        'bg_dark': '#1a1a2e',
        'text_light': '#ffffff',
        'text_dark': '#ffffff',
        'border_radius': '8px',
        'font_family': 'Segoe UI, sans-serif',
        'sidebar_position': 'left',
        'layout': 'dark'
    },
    'blue': {
        'name': 'Bleu Océan',
        'primary_color': '#0066cc',
        'secondary_color': '#0099ff',
        'danger_color': '#cc3333',
        'warning_color': '#ff9900',
        'info_color': '#00cccc',
        'success_color': '#009966',
        'bg_light': '#f0f8ff',
        'bg_dark': '#003366',
        'text_light': '#003366',
        'text_dark': '#ffffff',
        'border_radius': '12px',
        'font_family': 'Arial, sans-serif',
        'sidebar_position': 'left',
        'layout': 'blue'
    },
    'green': {
        'name': 'Vert Nature',
        'primary_color': '#228B22',
        'secondary_color': '#32CD32',
        'danger_color': '#DC143C',
        'warning_color': '#FFD700',
        'info_color': '#20B2AA',
        'success_color': '#006400',
        'bg_light': '#f0fff0',
        'bg_dark': '#1a3a1a',
        'text_light': '#1a3a1a',
        'text_dark': '#ffffff',
        'border_radius': '10px',
        'font_family': 'Verdana, sans-serif',
        'sidebar_position': 'left',
        'layout': 'green'
    },
    'purple': {
        'name': 'Violet Royal',
        'primary_color': '#6B3FA0',
        'secondary_color': '#9370DB',
        'danger_color': '#DC143C',
        'warning_color': '#FFA500',
        'info_color': '#00CED1',
        'success_color': '#228B22',
        'bg_light': '#f8f0ff',
        'bg_dark': '#2d1b4e',
        'text_light': '#2d1b4e',
        'text_dark': '#ffffff',
        'border_radius': '15px',
        'font_family': 'Georgia, serif',
        'sidebar_position': 'left',
        'layout': 'purple'
    },
    'minimal': {
        'name': 'Minimaliste',
        'primary_color': '#333333',
        'secondary_color': '#666666',
        'danger_color': '#cc0000',
        'warning_color': '#ff9900',
        'info_color': '#0066cc',
        'success_color': '#009900',
        'bg_light': '#ffffff',
        'bg_dark': '#000000',
        'text_light': '#000000',
        'text_dark': '#ffffff',
        'border_radius': '0px',
        'font_family': 'Helvetica, Arial, sans-serif',
        'sidebar_position': 'top',
        'layout': 'minimal'
    },
    'corporate': {
        'name': 'Entreprise',
        'primary_color': '#1a365d',
        'secondary_color': '#2c5282',
        'danger_color': '#c53030',
        'warning_color': '#d69e2e',
        'info_color': '#3182ce',
        'success_color': '#2f855a',
        'bg_light': '#f7fafc',
        'bg_dark': '#1a202c',
        'text_light': '#1a202c',
        'text_dark': '#ffffff',
        'border_radius': '6px',
        'font_family': 'Segoe UI, sans-serif',
        'sidebar_position': 'left',
        'layout': 'corporate'
    }
}


def ensure_themes_dir():
    """S'assurer que le répertoire des thèmes existe."""
    THEMES_DIR.mkdir(parents=True, exist_ok=True)
    
    # Sauvegarder les thèmes par défaut s'ils n'existent pas
    for theme_id, theme_data in DEFAULT_THEMES.items():
        theme_file = THEMES_DIR / f'{theme_id}.json'
        if not theme_file.exists():
            # Éviter la récursion en écrivant directement
            with open(theme_file, 'w', encoding='utf-8') as f:
                json.dump(theme_data, f, indent=2, ensure_ascii=False)


def get_available_themes():
    """Obtenir la liste des thèmes disponibles."""
    ensure_themes_dir()
    
    themes = {}
    for theme_file in THEMES_DIR.glob('*.json'):
        theme_id = theme_file.stem
        theme_data = load_theme(theme_id)
        if theme_data:
            themes[theme_id] = {
                'id': theme_id,
                'name': theme_data.get('name', theme_id),
                'preview': theme_data.get('primary_color', '#0078d4')
            }
    
    return themes


def load_theme(theme_id):
    """Charger un thème par son ID."""
    theme_file = THEMES_DIR / f'{theme_id}.json'
    
    if theme_file.exists():
        try:
            with open(theme_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None
    
    return DEFAULT_THEMES.get(theme_id)


def save_theme(theme_id, theme_data):
    """Sauvegarder un thème."""
    ensure_themes_dir()
    
    theme_file = THEMES_DIR / f'{theme_id}.json'
    with open(theme_file, 'w', encoding='utf-8') as f:
        json.dump(theme_data, f, indent=2, ensure_ascii=False)
    
    return True


def delete_theme(theme_id):
    """Supprimer un thème personnalisé."""
    if theme_id in DEFAULT_THEMES:
        return False  # Ne pas supprimer les thèmes par défaut
    
    theme_file = THEMES_DIR / f'{theme_id}.json'
    if theme_file.exists():
        theme_file.unlink()
        return True
    
    return False


def get_current_theme():
    """Obtenir le thème actuel depuis la session ou les paramètres."""
    try:
        from settings_manager import load_settings
        settings = load_settings()
        theme_id = settings.get('theme', {}).get('current', 'default')
        return load_theme(theme_id) or DEFAULT_THEMES['default']
    except Exception:
        return DEFAULT_THEMES['default']


def set_current_theme(theme_id):
    """Définir le thème actuel."""
    try:
        from settings_manager import load_settings, save_settings
        settings = load_settings()
        settings['theme'] = {'current': theme_id}
        save_settings(settings)
        return True
    except Exception:
        return False


def create_custom_theme(name, base_theme='default'):
    """Créer un nouveau thème personnalisé."""
    import uuid
    
    theme_id = f'custom_{uuid.uuid4().hex[:8]}'
    base_data = load_theme(base_theme) or DEFAULT_THEMES['default']
    
    new_theme = {
        **base_data,
        'name': name,
        'custom': True
    }
    
    save_theme(theme_id, new_theme)
    return theme_id


def export_theme(theme_id):
    """Exporter un thème en fichier CSS."""
    theme_data = load_theme(theme_id)
    if not theme_data:
        return None
    
    css = f"""/* Thème: {theme_data.get('name', theme_id)} */
/* Généré automatiquement par AD Web Interface */

:root {{
    --primary-color: {theme_data.get('primary_color', '#0078d4')};
    --secondary-color: {theme_data.get('secondary_color', '#107c10')};
    --danger-color: {theme_data.get('danger_color', '#d13438')};
    --warning-color: {theme_data.get('warning_color', '#ffb900')};
    --info-color: {theme_data.get('info_color', '#00b7c3')};
    --success-color: {theme_data.get('success_color', '#28a745')};
    --bg-light: {theme_data.get('bg_light', '#ffffff')};
    --bg-dark: {theme_data.get('bg_dark', '#1a1a2e')};
    --text-light: {theme_data.get('text_light', '#333333')};
    --text-dark: {theme_data.get('text_dark', '#ffffff')};
    --border-radius: {theme_data.get('border_radius', '8px')};
    --font-family: {theme_data.get('font_family', 'Segoe UI, sans-serif')};
    --sidebar-position: {theme_data.get('sidebar_position', 'left')};
    --layout: {theme_data.get('layout', 'default')};
}}
"""
    return css
