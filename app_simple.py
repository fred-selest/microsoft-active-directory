"""
Interface Web Multi-Plateforme pour Microsoft Active Directory.
Version simplifiée avec Blueprints.
"""
import os
import platform
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session

from config import get_config
from security import generate_csrf_token, validate_csrf_token, add_security_headers, get_secure_session_config, check_rate_limit, record_login_attempt
from translations import Translator
from audit import log_action, ACTIONS
from alerts import get_alert_counts
from session_crypto import init_crypto, encrypt_password

# Import des blueprints
from routes.core import (get_ad_connection, decode_ldap_value, is_connected,
                         require_connection, get_user_role_from_groups, ROLE_PERMISSIONS)
from routes.users import users_bp
from routes.groups import groups_bp
from routes.computers import computers_bp
from routes.tools import tools_bp
from routes.admin import admin_bp

app = Flask(__name__)
config = get_config()

# Configuration Flask
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['DEBUG'] = config.DEBUG
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=config.SESSION_TIMEOUT)

secure_session = get_secure_session_config()
app.config['SESSION_COOKIE_HTTPONLY'] = secure_session['SESSION_COOKIE_HTTPONLY']
app.config['SESSION_COOKIE_SAMESITE'] = secure_session['SESSION_COOKIE_SAMESITE']

config.init_directories()
init_crypto(config.SECRET_KEY)

# Enregistrer les blueprints
app.register_blueprint(users_bp)
app.register_blueprint(groups_bp)
app.register_blueprint(computers_bp)
app.register_blueprint(tools_bp)
app.register_blueprint(admin_bp)

# Cache mise à jour
_update_cache = {'last_check': 0, 'result': None}


@app.context_processor
def inject_globals():
    """Injecter les variables globales dans les templates."""
    import time

    # Mise à jour
    if _update_cache['result'] is None or (time.time() - _update_cache['last_check']) > 300:
        try:
            from updater_fast import check_for_updates_fast
            _update_cache['result'] = check_for_updates_fast()
            _update_cache['last_check'] = time.time()
        except:
            _update_cache['result'] = {'update_available': False, 'error': 'check_failed'}

    lang = session.get('language', 'fr')
    translator = Translator(lang)

    try:
        from settings_manager import load_settings, get_menu_items, get_dropdown_items
        settings = load_settings()
        menu_items = get_menu_items()
        dropdown_items = get_dropdown_items()
    except:
        settings, menu_items, dropdown_items = {}, [], {}

    def has_permission(permission):
        if not config.RBAC_ENABLED:
            return True
        user_role = session.get('user_role', config.DEFAULT_ROLE)
        return permission in ROLE_PERMISSIONS.get(user_role, [])

    try:
        alert_counts = get_alert_counts()
    except:
        alert_counts = {'total': 0}

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
        'menu_items': menu_items,
        'dropdown_items': dropdown_items,
        'feature_settings': settings.get('features', {})
    }


@app.after_request
def after_request(response):
    return add_security_headers(response)


# === ROUTES PRINCIPALES ===

@app.route('/')
def index():
    """Page d'accueil."""
    if is_connected():
        return redirect(url_for('dashboard'))
    return render_template('index.html', system_info={
        'os': platform.system(),
        'hostname': platform.node()
    }, connected=False)


@app.route('/connect', methods=['GET', 'POST'])
def connect():
    """Connexion au serveur AD."""
    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token invalide.', 'error')
            return render_template('connect.html', connected=is_connected())

        ip = request.remote_addr
        allowed, remaining = check_rate_limit(ip)
        if not allowed:
            flash(f'Trop de tentatives. Réessayez dans {remaining}s.', 'error')
            return render_template('connect.html', connected=is_connected())

        server = request.form.get('server')
        username = request.form.get('username')
        password = request.form.get('password')
        use_ssl = request.form.get('use_ssl') == 'on'
        port = request.form.get('port', '')
        base_dn = request.form.get('base_dn', '')

        port = int(port) if port else None
        conn, error = get_ad_connection(server, username, password, use_ssl, port)

        if conn:
            record_login_attempt(ip, success=True)
            session['ad_server'] = server
            session['ad_username'] = username
            session['ad_password'] = encrypt_password(password)
            session['ad_use_ssl'] = use_ssl
            session['ad_port'] = port
            session['ad_base_dn'] = base_dn

            if not base_dn and conn.server.info and conn.server.info.naming_contexts:
                session['ad_base_dn'] = str(conn.server.info.naming_contexts[0])

            user_role, debug_info = get_user_role_from_groups(conn, username, debug=True)
            session['user_role'] = user_role
            conn.unbind()

            log_action(ACTIONS['LOGIN'], username, {'server': server, 'role': user_role}, True, ip)
            flash(f'Connexion réussie! Role: {user_role}', 'success')

            if debug_info.get('groups'):
                flash(f'Groupes: {", ".join(debug_info["groups"][:5])}', 'info')
            if debug_info.get('error'):
                flash(f'Erreur: {debug_info["error"]}', 'warning')

            return redirect(url_for('dashboard'))
        else:
            record_login_attempt(ip, success=False)
            log_action(ACTIONS['LOGIN'], username, {'error': error}, False, ip)
            flash(f'Erreur: {error}', 'error')

    return render_template('connect.html', connected=is_connected())


@app.route('/disconnect')
def disconnect():
    """Déconnexion."""
    log_action(ACTIONS['LOGOUT'], session.get('ad_username', 'unknown'), {}, True, request.remote_addr)
    session.clear()
    flash('Déconnecté.', 'success')
    return redirect(url_for('index'))


@app.route('/toggle-dark-mode')
def toggle_dark_mode():
    """Basculer mode sombre."""
    session['dark_mode'] = not session.get('dark_mode', False)
    return redirect(request.referrer or url_for('index'))


@app.route('/dashboard')
@require_connection
def dashboard():
    """Tableau de bord."""
    from ldap3 import SUBTREE
    conn, error = get_ad_connection()
    stats = {'total_users': 0, 'active_users': 0, 'disabled_users': 0,
             'total_groups': 0, 'total_ous': 0}

    if conn:
        base_dn = session.get('ad_base_dn', '')
        try:
            # Compter utilisateurs
            conn.search(base_dn, '(&(objectClass=user)(objectCategory=person))',
                       SUBTREE, attributes=['userAccountControl'])
            for e in conn.entries:
                stats['total_users'] += 1
                uac = e.userAccountControl.value if hasattr(e, 'userAccountControl') else 512
                if int(uac or 512) & 2:
                    stats['disabled_users'] += 1
                else:
                    stats['active_users'] += 1

            # Compter groupes
            conn.search(base_dn, '(objectClass=group)', SUBTREE, attributes=['cn'])
            stats['total_groups'] = len(conn.entries)

            # Compter OUs
            conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['name'])
            stats['total_ous'] = len(conn.entries)
        except:
            pass
        conn.unbind()

    return render_template('dashboard.html', stats=stats, connected=is_connected())


# === OUS ===
@app.route('/ous')
@require_connection
def ous():
    """Liste des OUs."""
    from ldap3 import SUBTREE
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    ou_list = []

    try:
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'description', 'distinguishedName'])
        for e in conn.entries:
            ou_list.append({
                'name': decode_ldap_value(e.name),
                'description': decode_ldap_value(e.description),
                'dn': decode_ldap_value(e.distinguishedName)
            })
        conn.unbind()
    except Exception as ex:
        flash(f'Erreur: {str(ex)}', 'error')

    return render_template('ous.html', ous=ou_list, connected=is_connected())


@app.route('/audit')
@require_connection
def audit_logs():
    """Logs d'audit."""
    from audit import get_audit_logs
    page = request.args.get('page', 1, type=int)
    logs = get_audit_logs(page=page, per_page=50)
    return render_template('audit.html', logs=logs, page=page, connected=is_connected())


@app.route('/search')
@require_connection
def global_search():
    """Recherche globale."""
    query = request.args.get('q', '')
    return render_template('search.html', query=query, results=[], connected=is_connected())


if __name__ == '__main__':
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
