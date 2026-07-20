"""
Interface Web Multi-Plateforme pour Microsoft Active Directory.
Version modulaire avec Blueprints.
"""

# IMPORTANT: OpenSSL MD4/NTLM init (DOIT ÊTRE LE PREMIER IMPORT)
import _openssl_init

from flask import Flask, session, redirect, url_for, render_template
from config import get_config
from core.security import add_security_headers
from core.session_crypto import init_crypto
from core.context_processor import inject_globals
from core.debug_utils import init_debug, logger

# Appliquer les fichiers staging d'une mise à jour précédente
try:
    import shutil
    from pathlib import Path
    staging = Path(__file__).parent / 'data' / '.update_staging'
    if staging.exists():
        applied = 0
        for src in staging.rglob('*'):
            if src.is_file():
                rel = src.relative_to(staging)
                dest = Path(__file__).parent / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(src), str(dest))
                applied += 1
        # Nettoyer staging
        shutil.rmtree(staging, ignore_errors=True)
        if applied > 0:
            logger.info(f"Update staging appliqué: {applied} fichiers")
except Exception as e:
    logger.error(f"Erreur application staging: {e}")

# Import des blueprints
from routes.main import main_bp
from routes.users import users_bp
from routes.groups import groups_bp
from routes.computers import computers_bp
from routes.tools import tools_bp
from routes.admin import admin_bp
from routes.ous import ous_bp
from routes.debug import debug_bp
from routes.api import api_bp
from routes.admin_tools import admin_tools_bp

app = Flask(__name__)
config = get_config()

# Configuration Flask
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['DEBUG'] = config.DEBUG
app.config['PERMANENT_SESSION_LIFETIME'] = config.PERMANENT_SESSION_LIFETIME

# Templates — toujours recharger pour eviter le cache apres mise a jour
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True

# Session cookie
from core.security import get_secure_session_config
secure_session = get_secure_session_config()
app.config['SESSION_COOKIE_SECURE'] = secure_session['SESSION_COOKIE_SECURE']
app.config['SESSION_COOKIE_HTTPONLY'] = secure_session['SESSION_COOKIE_HTTPONLY']
app.config['SESSION_COOKIE_SAMESITE'] = secure_session['SESSION_COOKIE_SAMESITE']
app.config['SESSION_COOKIE_NAME'] = secure_session['SESSION_COOKIE_NAME']

# Initialisation
config.init_directories()
init_crypto(config.SECRET_KEY)

# Sessions côté serveur (C4) : le cookie ne porte qu'un identifiant opaque ;
# les données (dont le mot de passe AD chiffré) restent sur le serveur.
from core.server_session import init_server_sessions
init_server_sessions(app, config.DATA_DIR / 'sessions')

# Enregistrement des blueprints
app.register_blueprint(main_bp)
app.register_blueprint(users_bp)
app.register_blueprint(groups_bp)
app.register_blueprint(computers_bp)
app.register_blueprint(tools_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(ous_bp)
app.register_blueprint(debug_bp)
app.register_blueprint(api_bp)
app.register_blueprint(admin_tools_bp)

# Debug
if config.DEBUG:
    init_debug(app)

app.context_processor(inject_globals)

# Filtre de neutralisation du CSS personnalisé (anti-XSS, cf. base.html)
from core.security import sanitize_css as _sanitize_css
app.jinja_env.filters['safe_css'] = _sanitize_css

# =============================================================================
# ANALYSE AUTOMATIQUE DES LOGS AU DÉMARRAGE
# =============================================================================
def _run_startup_analysis():
    """Exécuter l'analyse automatique des logs au démarrage."""
    try:
        from core.log_analyzer import analyze_logs_on_startup
        
        # Exécuter en arrière-plan pour ne pas bloquer le démarrage
        import threading
        thread = threading.Thread(target=analyze_logs_on_startup, daemon=True)
        thread.start()
        
        logger.info("Analyse automatique des logs démarrée en arrière-plan")
        
    except Exception as e:
        logger.error(f"Erreur initialisation analyse logs: {e}")

# Lancer l'analyse après initialisation
_run_startup_analysis()

# Démarrer le watchdog de surveillance continue
try:
    from core.watchdog import start_watchdog
    start_watchdog(interval_seconds=300)
except Exception as e:
    logger.error(f"Erreur démarrage watchdog: {e}")


# =============================================================================
# PROTECTION CSRF GLOBALE (constat É3 de AUDIT_2026-07-20.md)
# Auparavant la validation CSRF était appliquée route par route ; 24 routes
# mutatives l'avaient oubliée. On la centralise ici : toute requête modifiant
# l'état doit présenter un jeton valide (champ de formulaire csrf_token, en-tête
# X-CSRFToken, ou champ csrf_token d'un corps JSON). Le jeton est injecté
# automatiquement côté client par le wrapper fetch de base.html.
# =============================================================================
from flask import request, jsonify
from core.security import validate_csrf_token

# Endpoints exemptés de CSRF (aucun pour l'instant). Utiliser le nom d'endpoint
# Flask (blueprint.fonction). Réservé à d'éventuelles intégrations sans session.
_CSRF_EXEMPT_ENDPOINTS = set()


@app.before_request
def _global_csrf_protection():
    if request.method not in ('POST', 'PUT', 'DELETE', 'PATCH'):
        return None
    if request.endpoint in _CSRF_EXEMPT_ENDPOINTS:
        return None

    token = (request.form.get('csrf_token')
             or request.headers.get('X-CSRFToken')
             or request.headers.get('X-CSRF-Token'))
    if not token and request.is_json:
        token = (request.get_json(silent=True) or {}).get('csrf_token')

    if validate_csrf_token(token):
        return None

    logger.warning(
        f"CSRF refusé: {request.method} {request.path} "
        f"(endpoint={request.endpoint}, ip={request.remote_addr})"
    )
    if (request.is_json
            or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
            or (request.path or '').startswith('/api/')):
        return jsonify({'success': False, 'error': 'Token CSRF invalide ou manquant'}), 403
    from flask import render_template as _rt
    try:
        return _rt('error.html', error_code=403,
                   error_message="Token CSRF invalide ou manquant.",
                   connected=False), 403
    except Exception:
        return "Token CSRF invalide ou manquant.", 403


@app.after_request
def after_request(response):
    if config.DEBUG:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return add_security_headers(response)


# Gestion des erreurs
@app.errorhandler(404)
def not_found_error(error):
    from routes.core import is_connected
    logger.error(f"404 Error: {session.get('ad_username', 'anonymous')}")
    return render_template('error.html', error_code=404, error_message="Page non trouvée",
                         error_details=str(error), connected=is_connected()), 404


@app.errorhandler(500)
def internal_error(error):
    from routes.core import is_connected
    logger.error(f"500 Error: {session.get('ad_username', 'anonymous')} - {str(error)}", exc_info=True)
    return render_template('error.html', error_code=500, error_message="Erreur interne du serveur",
                         error_details=str(error), connected=is_connected()), 500


@app.errorhandler(Exception)
def handle_exception(error):
    from routes.core import is_connected
    logger.error(f"Unhandled Exception: {type(error).__name__}: {str(error)}", exc_info=True)
    if config.DEBUG:
        import traceback
        return render_template('error.html', error_code=500,
                             error_message=f"{type(error).__name__}: {str(error)}",
                             error_details=traceback.format_exc(),
                             connected=is_connected()), 500
    return render_template('error.html', error_code=500,
                         error_message="Une erreur inattendue s'est produite",
                         connected=is_connected()), 500


def run_server():
    """Point d'entrée principal."""
    import platform
    from waitress import serve
    
    print("\n" + "="*60)
    print("Interface Web Microsoft Active Directory")
    print("="*60)
    print(f"Plateforme: {platform.system()} ({platform.release()})")
    print(f"Écoute sur: http://{config.HOST}:{config.PORT}")
    print("="*60 + "\n")
    
    serve(app, host=config.HOST, port=config.PORT, threads=8)


if __name__ == '__main__':
    run_server()
