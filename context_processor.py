"""
Context processor Flask — injecte les variables globales dans tous les templates.
Extrait de app.py pour alléger le fichier principal.
"""
import time

from flask import session

from config import get_config
from security import generate_csrf_token
from translations import Translator
from alerts import get_alert_counts
from features import is_feature_enabled
from routes.core import ROLE_PERMISSIONS

config = get_config()

# Cache léger pour éviter de requêter GitHub à chaque requête (TTL 5 min)
_update_cache = {'last_check': 0, 'result': None}


def inject_globals():
    """Injecter les variables globales dans les templates."""
    global _update_cache

    if _update_cache['result'] is None or (time.time() - _update_cache['last_check']) > 300:
        try:
            from updater import check_for_updates_fast
            _update_cache['result'] = check_for_updates_fast()
            _update_cache['last_check'] = time.time()
        except Exception:
            _update_cache['result'] = {'update_available': False, 'error': 'check_failed'}

    lang = session.get('language', 'fr')
    translator = Translator(lang)

    try:
        from settings_manager import (load_settings, get_menu_items,
                                      get_tool_items, get_admin_items, get_dropdown_items)
        settings = load_settings()
        menu_items = get_menu_items()
        tool_items = get_tool_items()
        admin_items = get_admin_items()
        dropdown_items = get_dropdown_items()
    except Exception:
        settings, menu_items, tool_items, admin_items, dropdown_items = {}, [], [], [], {}

    def has_permission(permission):
        if not config.RBAC_ENABLED:
            return True
        user_role = session.get('user_role', config.DEFAULT_ROLE)
        return permission in ROLE_PERMISSIONS.get(user_role, [])

    try:
        alert_counts = get_alert_counts()
    except Exception:
        alert_counts = {'total': 0}

    from updater import get_current_version
    return {
        'update_info': _update_cache['result'],
        'user_role': session.get('user_role', config.DEFAULT_ROLE),
        'has_permission': has_permission,
        'dark_mode': session.get('dark_mode', False),
        'config': config,
        'csrf_token': generate_csrf_token,
        't': translator,
        'current_lang': lang,
        'alert_counts': alert_counts,
        'site_settings': settings.get('site', {}),
        'branding': settings.get('branding', {}),
        'menu_items': menu_items,
        'tool_items': tool_items,
        'admin_items': admin_items,
        'dropdown_items': dropdown_items,
        'feature_settings': settings.get('features', {}),
        'is_feature_enabled': is_feature_enabled,
        'app_version': get_current_version(),
    }
