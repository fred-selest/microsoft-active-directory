"""
Module de debug pour AD Web Interface.
Fournit des outils de débogage pour le développement.
"""

import logging
import json
from datetime import datetime
from functools import wraps
from flask import session, g
import time

# Configuration logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/debug.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('ad_debug')


class DebugTimer:
    """Chronomètre pour mesurer les performances."""
    
    def __init__(self, name="Operation"):
        self.name = name
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        logger.debug(f"⏱️  DÉBUT: {self.name}")
        return self
    
    def __exit__(self, *args):
        self.end_time = time.time()
        elapsed = (self.end_time - self.start_time) * 1000  # ms
        logger.debug(f"⏱️  FIN: {self.name} - {elapsed:.2f}ms")


def debug_route(func):
    """Décorateur pour debugger une route."""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        route_name = func.__name__
        logger.debug("=" * 60)
        logger.debug(f"🔍 ROUTE: {route_name}")
        logger.debug(f"📅 DATE: {datetime.now().isoformat()}")
        logger.debug(f"👤 USER: {session.get('username', 'anonymous')}")
        logger.debug(f"🔑 ROLE: {session.get('user_role', 'none')}")
        logger.debug(f"📄 ARGS: {args}")
        logger.debug(f"📄 KWARGS: {kwargs}")
        
        # Timer pour performance
        with DebugTimer(f"Route {route_name}") as timer:
            try:
                result = func(*args, **kwargs)
                logger.debug(f"✅ SUCCÈS: {route_name}")
                return result
            except Exception as e:
                logger.error(f"❌ ERREUR: {route_name}")
                logger.error(f"   Message: {str(e)}")
                logger.error(f"   Type: {type(e).__name__}")
                import traceback
                logger.error(f"   Traceback:\n{traceback.format_exc()}")
                raise
    
    return decorated_function


def log_session_data():
    """Logger les données de session."""
    session_info = {
        'connected': bool(session.get('ad_server')),
        'server': session.get('ad_server', 'none'),
        'username': session.get('ad_username', 'none'),
        'user_role': session.get('user_role', 'none'),
        'dark_mode': session.get('dark_mode', False),
        'language': session.get('language', 'fr'),
    }
    logger.debug(f"💾 SESSION: {json.dumps(session_info, indent=2)}")
    return session_info


def check_feature_flags():
    """Vérifier l'état des feature flags."""
    from config import get_config
    config = get_config()
    
    flags = {
        'users': config.FEATURE_USERS_ENABLED,
        'groups': config.FEATURE_GROUPS_ENABLED,
        'computers': config.FEATURE_COMPUTERS_ENABLED,
        'laps': config.FEATURE_LAPS_ENABLED,
        'bitlocker': config.FEATURE_BITLOCKER_ENABLED,
        'recycle_bin': config.FEATURE_RECYCLE_BIN_ENABLED,
        'locked_accounts': config.FEATURE_LOCKED_ACCOUNTS_ENABLED,
        'audit_logs': config.FEATURE_AUDIT_LOGS_ENABLED,
        'diagnostic': config.FEATURE_DIAGNOSTIC_ENABLED,
    }
    
    for flag, enabled in flags.items():
        status = "✅" if enabled else "❌"
        logger.debug(f"🚩 FEATURE FLAG: {status} {flag}")
    
    return flags


def debug_ldap_query(func):
    """Décorateur pour debugger les requêtes LDAP."""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        logger.debug("=" * 60)
        logger.debug(f"🔍 LDAP QUERY: {func.__name__}")
        
        with DebugTimer(f"LDAP {func.__name__}") as timer:
            try:
                result = func(*args, **kwargs)
                if hasattr(result, 'entries'):
                    logger.debug(f"📊 RÉSULTATS: {len(result.entries)} entrées")
                return result
            except Exception as e:
                logger.error(f"❌ LDAP ERROR: {str(e)}")
                raise
    
    return decorated_function


def get_debug_info():
    """Récupérer toutes les informations de debug."""
    from config import get_config
    config = get_config()
    
    debug_data = {
        'timestamp': datetime.now().isoformat(),
        'session': {
            'connected': bool(session.get('ad_server')),
            'server': session.get('ad_server', 'none'),
            'username': session.get('ad_username', 'none'),
            'user_role': session.get('user_role', 'none'),
            'dark_mode': session.get('dark_mode', False),
        },
        'config': {
            'debug': config.DEBUG,
            'rbac_enabled': config.RBAC_ENABLED,
            'default_role': config.DEFAULT_ROLE,
        },
        'feature_flags': {
            'users': config.FEATURE_USERS_ENABLED,
            'groups': config.FEATURE_GROUPS_ENABLED,
            'computers': config.FEATURE_COMPUTERS_ENABLED,
            'laps': config.FEATURE_LAPS_ENABLED,
            'bitlocker': config.FEATURE_BITLOCKER_ENABLED,
            'recycle_bin': config.FEATURE_RECYCLE_BIN_ENABLED,
            'locked_accounts': config.FEATURE_LOCKED_ACCOUNTS_ENABLED,
            'audit_logs': config.FEATURE_AUDIT_LOGS_ENABLED,
            'diagnostic': config.FEATURE_DIAGNOSTIC_ENABLED,
        },
        'environment': {
            'flask_env': config.FLASK_ENV if hasattr(config, 'FLASK_ENV') else 'unknown',
            'host': config.HOST,
            'port': config.PORT,
        }
    }
    
    return debug_data


def init_debug(app):
    """Initialiser le debug pour l'application Flask."""
    
    @app.before_request
    def before_request():
        """Avant chaque requête."""
        g.start_time = time.time()
        logger.debug(f"➡️  REQUEST: {request.method} {request.path}")
    
    @app.after_request
    def after_request(response):
        """Après chaque requête."""
        if hasattr(g, 'start_time'):
            elapsed = (time.time() - g.start_time) * 1000
            logger.debug(f"⬅️  RESPONSE: {response.status_code} - {elapsed:.2f}ms")
        return response
    
    logger.info("🔧 Debug module initialized")
