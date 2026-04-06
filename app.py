"""
Interface Web Multi-Plateforme pour Microsoft Active Directory.
Version modulaire avec Blueprints.
"""

# IMPORTANT: OpenSSL MD4/NTLM init (DOIT ÊTRE LE PREMIER IMPORT)
import _openssl_init

from flask import Flask, session, redirect, url_for, render_template
from config import get_config
from security import add_security_headers
from session_crypto import init_crypto
from context_processor import inject_globals
from debug_utils import init_debug, logger

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
app.config['PERMANENT_SESSION_LIFETIME'] = config.SESSION_TIMEOUT

# Debug mode
if config.DEBUG:
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.jinja_env.auto_reload = True

# Session cookie
from security import get_secure_session_config
secure_session = get_secure_session_config()
app.config['SESSION_COOKIE_HTTPONLY'] = secure_session['SESSION_COOKIE_HTTPONLY']
app.config['SESSION_COOKIE_SAMESITE'] = secure_session['SESSION_COOKIE_SAMESITE']

# Initialisation
config.init_directories()
init_crypto(config.SECRET_KEY)

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
