"""
Context processor Flask — injecte les variables globales dans tous les templates.
Extrait de app.py pour alléger le fichier principal.
"""
import time

from flask import session

from config import get_config
from core.security import generate_csrf_token
from core.translations import Translator
from core.alerts import get_alert_counts
from core.features import is_feature_enabled
from routes.core import get_ad_connection

config = get_config()

# Cache léger pour éviter de requêter GitHub à chaque requête (TTL 5 min)
_update_cache = {'last_check': 0, 'result': None}


def inject_globals():
    """Injecter les variables globales dans les templates."""
    global _update_cache

    if _update_cache['result'] is None or (time.time() - _update_cache['last_check']) > 300:
        try:
            from core.updater import check_for_updates_fast
            _update_cache['result'] = check_for_updates_fast()
            _update_cache['last_check'] = time.time()
        except Exception:
            _update_cache['result'] = {'update_available': False, 'error': 'check_failed'}

    lang = session.get('language', 'fr')
    translator = Translator(lang)

    try:
        from core.settings_manager import (load_settings, get_menu_items,
                                           get_tool_items, get_admin_items, get_dropdown_items)
        settings = load_settings()
        menu_items = get_menu_items()
        tool_items = get_tool_items()
        admin_items = get_admin_items()
        dropdown_items = get_dropdown_items()
    except Exception:
        settings, menu_items, tool_items, admin_items, dropdown_items = {}, [], [], [], {}

    def check_user_permission(permission):
        """Vérifie si l'utilisateur actuel a une permission spécifique."""
        if not config.RBAC_ENABLED:
            return True
        user_groups = session.get('user_groups', [])
        user_role = session.get('user_role', config.DEFAULT_ROLE)
        
        # Les admins ont toutes les permissions
        if user_role == 'admin':
            return True
        
        # Sinon vérifier les permissions granulaires
        if user_groups:
            from core.granular_permissions import has_permission as has_granular_permission
            return has_granular_permission(user_groups, permission)
        
        return False

    try:
        alert_counts = get_alert_counts()
    except Exception:
        alert_counts = {'total': 0}

    from core.updater import get_current_version
    
    # Vérifier si connecté à AD
    from routes.core import is_connected
    connected = is_connected()
    
    return {
        'update_info': _update_cache['result'],
        'user_role': session.get('user_role', config.DEFAULT_ROLE),
        'check_user_permission': check_user_permission,
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
        'connected': connected,
    }
