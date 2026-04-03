"""
Interface Web Multi-Plateforme pour Microsoft Active Directory.
Version simplifiée avec Blueprints.
"""

# IMPORTANT: OpenSSL MD4/NTLM init (DOIT ÊTRE LE PREMIER IMPORT)
import _openssl_init

import os
import hashlib
import platform
from pathlib import Path
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from ad_detect import get_local_domain, detect_ad_config
from config import get_config
from security import generate_csrf_token, validate_csrf_token, add_security_headers, get_secure_session_config, check_rate_limit, record_login_attempt
from translations import Translator
from audit import log_action, ACTIONS
from alerts import get_alert_counts
from session_crypto import init_crypto, encrypt_password
from routes.core import (get_ad_connection, decode_ldap_value, is_connected,
                         require_connection, require_permission, get_user_role_from_groups, 
                         get_user_permissions, ROLE_PERMISSIONS)
from routes.users import users_bp
from routes.groups import groups_bp
from routes.computers import computers_bp
from routes.tools import tools_bp
from routes.admin import admin_bp
from routes.ous import ous_bp
from routes.debug import debug_bp
from features import require_feature, is_feature_enabled
from debug_utils import init_debug, logger
from context_processor import inject_globals

app = Flask(__name__)
config = get_config()

# Répertoire de base
BASE_DIR = Path(__file__).parent.resolve()

# Configuration Flask
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['DEBUG'] = config.DEBUG
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=config.SESSION_TIMEOUT)

# Désactiver cache templates en mode debug
if config.DEBUG:
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    app.jinja_env.auto_reload = True

# Flask Debug Toolbar
if config.DEBUG:
    app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
    app.config['DEBUG_TB_PANELS'] = [
        'flask_debugtoolbar.panels.versions.VersionDebugPanel',
        'flask_debugtoolbar.panels.timer.TimerDebugPanel',
        'flask_debugtoolbar.panels.headers.HeaderDebugPanel',
        'flask_debugtoolbar.panels.request_vars.RequestVarsDebugPanel',
        'flask_debugtoolbar.panels.config_vars.ConfigVarsDebugPanel',
        'flask_debugtoolbar.panels.template.TemplateDebugPanel',
        'flask_debugtoolbar.panels.sqlalchemy.SQLAlchemyDebugPanel',
        'flask_debugtoolbar.panels.logging.LoggingPanel',
        'flask_debugtoolbar.panels.route.RouteDebugPanel',
        'flask_debugtoolbar.panels.profiler.ProfilerDebugPanel',
    ]
    
    try:
        from flask_debugtoolbar import DebugToolbarExtension
        toolbar = DebugToolbarExtension(app)
        logger.info("✅ Flask Debug Toolbar activée")
    except ImportError:
        logger.warning("⚠️ Flask Debug Toolbar non installé")

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
app.register_blueprint(ous_bp)
app.register_blueprint(debug_bp)

# Initialiser le debug
if config.DEBUG:
    init_debug(app)

app.context_processor(inject_globals)


@app.after_request
def after_request(response):
    # Disable cache en mode debug
    if config.DEBUG:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return add_security_headers(response)


# === GESTION DES ERREURS AUTOMATIQUE ===

@app.errorhandler(404)
def not_found_error(error):
    """Gérer automatiquement les erreurs 404."""
    logger.error(f"404 Error: {request.url} - User: {session.get('ad_username', 'anonymous')}")
    return render_template('error.html', 
                         error_code=404,
                         error_message="Page non trouvée",
                         error_details=str(error),
                         connected=is_connected()), 404


@app.errorhandler(500)
def internal_error(error):
    """Gérer automatiquement les erreurs 500."""
    logger.error(f"500 Error: {request.url} - User: {session.get('ad_username', 'anonymous')} - {str(error)}", exc_info=True)
    return render_template('error.html',
                         error_code=500,
                         error_message="Erreur interne du serveur",
                         error_details=str(error),
                         connected=is_connected()), 500


@app.errorhandler(Exception)
def handle_exception(error):
    """Gérer toutes les exceptions non capturées."""
    logger.error(f"Unhandled Exception: {request.url} - {type(error).__name__}: {str(error)}", exc_info=True)
    # En mode debug, afficher les détails
    if config.DEBUG:
        import traceback
        return render_template('error.html',
                             error_code=500,
                             error_message=f"{type(error).__name__}: {str(error)}",
                             error_details=traceback.format_exc(),
                             connected=is_connected()), 500
    return render_template('error.html',
                         error_code=500,
                         error_message="Une erreur inattendue s'est produite",
                         connected=is_connected()), 500


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

        server = request.form.get('server', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password')
        use_ssl = request.form.get('use_ssl') == 'on'
        port = request.form.get('port', '')
        base_dn = request.form.get('base_dn', '')
        domain = request.form.get('domain', '').strip()

        # Préfixer le domaine si besoin
        if domain and '\\' not in username and '@' not in username:
            username = f"{domain}\\{username}"

        # Serveur manquant : essayer auto-détection
        if not server:
            ad_cfg = detect_ad_config()
            server = ad_cfg.get('server', '')
            if not server:
                full_domain = get_local_domain() or ''
                server = full_domain if full_domain else domain

        if not server:
            flash('Adresse du serveur AD requise. Veuillez la saisir dans les options avancées.', 'error')
            ad_cfg2 = detect_ad_config()
            detected_domain2 = ad_cfg2['domain'].split('.')[0].upper() if ad_cfg2.get('domain') else domain
            return render_template('connect.html', connected=is_connected(),
                                   auto_domain=detected_domain2, auto_detected=False,
                                   server='', port=389,
                                   base_dn=ad_cfg2.get('base_dn', ''), use_ssl=False)

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

            # Rôle utilisateur
            user_role, debug_info = get_user_role_from_groups(conn, username, debug=True)
            session['user_role'] = user_role

            # Permissions granulaires
            from routes.core import get_user_permissions
            user_permissions = get_user_permissions(conn, username)
            session['user_permissions'] = user_permissions

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

    # GET : pré-remplir les champs via auto-détection
    ad_cfg = detect_ad_config()
    detected_domain = ad_cfg['domain'].split('.')[0].upper() if ad_cfg.get('domain') else ''
    auto_detected = ad_cfg.get('auto_detected', False) and bool(ad_cfg.get('server', ''))
    return render_template('connect.html', connected=is_connected(),
                           auto_domain=detected_domain,
                           auto_detected=auto_detected,
                           server=ad_cfg.get('server', ''),
                           port=ad_cfg.get('port', 389),
                           base_dn=ad_cfg.get('base_dn', ''),
                           use_ssl=ad_cfg.get('use_ssl', False))


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
    from dashboard_widgets import get_dashboard_widgets
    
    conn, error = get_ad_connection()
    stats = {'total_users': 0, 'active_users': 0, 'disabled_users': 0,
             'total_groups': 0, 'empty_groups': 0, 'total_ous': 0}
    critical_alerts = []
    widgets = {
        'alerts': [],
        'score_evolution': {'current': 0, 'trend': 'stable', 'last_audit': ''},
        'quick_stats': {'total_audits': 0, 'avg_score': 0, 'best_score': 0, 'critical_count': 0, 'warning_count': 0},
        'recent_actions': []
    }

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

            # Compter groupes et groupes vides
            conn.search(base_dn, '(objectClass=group)', SUBTREE, attributes=['cn', 'member'])
            stats['total_groups'] = len(conn.entries)
            for e in conn.entries:
                members = e.member.values if hasattr(e, 'member') and e.member else []
                if not members:
                    stats['empty_groups'] += 1

            # Compter OUs
            conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['name'])
            stats['total_ous'] = len(conn.entries)
            
            # Récupérer widgets
            widgets = get_dashboard_widgets()
            
            # Alertes critiques
            critical_alerts = widgets.get('alerts', [])
        except:
            pass
        conn.unbind()

    return render_template('dashboard.html', 
                         stats=stats, 
                         widgets=widgets,
                         critical_alerts=critical_alerts,
                         connected=is_connected())


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
    tree = None

    try:
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'description', 'distinguishedName'])
        
        ous_data = []
        for e in conn.entries:
            ou_data = {
                'name': decode_ldap_value(e.name),
                'description': decode_ldap_value(e.description),
                'dn': decode_ldap_value(e.distinguishedName),
                'type': 'ou'
            }
            ou_list.append(ou_data)
            ous_data.append(ou_data)
        
        # Construire l'arborescence
        tree = build_ou_tree(ous_data, base_dn)
        
        conn.unbind()
    except Exception as ex:
        flash(f'Erreur: {str(ex)}', 'error')

    return render_template('ous.html', ous=ou_list, tree=tree, connected=is_connected())


def build_ou_tree(ous, base_dn):
    """
    Construire une arborescence à partir d'une liste plate d'OUs.
    """
    # Racine virtuelle
    root = {
        'name': base_dn.split(',')[0].replace('DC=', '') if base_dn else 'Domaine',
        'dn': base_dn,
        'type': 'domain',
        'children': []
    }
    
    # Trier les OUs par nombre de composants DN (les plus courts en premier)
    sorted_ous = sorted(ous, key=lambda x: x['dn'].count(','))
    
    # Ajouter chaque OU au bon endroit dans l'arbre
    for ou in sorted_ous:
        add_ou_to_tree(root, ou)
    
    return root


def add_ou_to_tree(node, ou):
    """Ajouter une OU à l'arborescence."""
    ou_dn = ou['dn']
    node_dn = node['dn']
    
    # Si l'OU est directement enfant du noeud
    if ou_dn.endswith(',' + node_dn) and ou_dn.count(',') == node_dn.count(',') + 1:
        node['children'].append({
            'name': ou['name'],
            'dn': ou['dn'],
            'type': 'ou',
            'children': []
        })
        return True
    
    # Sinon, chercher dans les enfants
    for child in node['children']:
        if add_ou_to_tree(child, ou):
            return True
    
    return False


@app.route('/audit')
@require_connection
def audit_logs():
    """Logs d'audit."""
    from audit import get_audit_logs
    page = request.args.get('page', 1, type=int)
    logs = get_audit_logs(limit=50)
    return render_template('audit.html', logs=logs, page=page, connected=is_connected())


# @app.route('/search')  # DÉSACTIVÉ - Fonctionnalité non implémentée
# @require_connection
# def global_search():
#     """Recherche globale."""
#     query = request.args.get('q', '')
#     return render_template('search.html', query=query, results=[], connected=is_connected())


# === MISE A JOUR ===
@app.route('/update')
def update_page():
    """Page de mise à jour."""
    try:
        from updater import check_for_updates_fast
        update_info = check_for_updates_fast()
    except Exception as e:
        update_info = {
            'update_available': False,
            'current_version': 'Erreur',
            'latest_version': None,
            'error': str(e)
        }
    return render_template('update.html', update_info=update_info, connected=is_connected())


@app.route('/api/health')
def api_health():
    """Endpoint de health check pour Docker/Kubernetes."""
    from updater import get_current_version
    return jsonify({
        'status': 'healthy',
        'version': get_current_version(),
        'platform': platform.system()
    })


@app.route('/api/system-info')
def api_system_info():
    """Endpoint pour les informations système complètes."""
    from updater import get_current_version
    from routes.core import get_ad_connection

    # Vérifier la connexion AD
    ad_connected = False
    ad_error = None
    if is_connected():
        try:
            conn, error = get_ad_connection()
            if conn:
                ad_connected = True
                conn.unbind()
            else:
                ad_error = str(error)
        except Exception as e:
            ad_error = str(e)

    # Vérifier le support MD4/NTLM
    md4_supported = True
    try:
        import hashlib
        hashlib.new('md4')
    except ValueError:
        md4_supported = False

    return jsonify({
        'version': get_current_version(),
        'platform': platform.system(),
        'platform_release': platform.release(),
        'hostname': platform.node(),
        'python_version': platform.python_version(),
        'ad_connected': ad_connected,
        'ad_error': ad_error,
        'md4_supported': md4_supported
    })


@app.route('/diagnostic')
@require_connection
def diagnostic_page():
    """Page de diagnostic et dépannage."""
    return render_template('diagnostic.html', connected=is_connected())


@app.route('/api/diagnostic')
def api_diagnostic():
    """API de diagnostic automatique."""
    from diagnostic import run_full_diagnostic
    from ldap3 import SUBTREE
    
    # Récupérer les infos de connexion AD si disponible
    server = session.get('ad_server', 'localhost')
    port = session.get('ad_port', 389)
    
    # Exécuter le diagnostic
    results = run_full_diagnostic(server, port)
    
    # Ajouter des checks supplémentaires si connecté
    if is_connected():
        try:
            from routes.core import get_ad_connection
            conn, error = get_ad_connection()
            if conn:
                # Tester une recherche simple
                try:
                    conn.search(session.get('ad_base_dn', ''), 
                               '(objectClass=domain)', 
                               SUBTREE, 
                               attributes=['name'])
                    if conn.entries:
                        results['checks'].append({
                            'name': 'Recherche AD',
                            'passed': True,
                            'message': 'Recherche LDAP fonctionnelle'
                        })
                    else:
                        results['checks'].append({
                            'name': 'Recherche AD',
                            'passed': False,
                            'message': 'Aucun résultat de recherche'
                        })
                except Exception as e:
                    results['checks'].append({
                        'name': 'Recherche AD',
                        'passed': False,
                        'message': f'Erreur de recherche: {str(e)}'
                    })
                conn.unbind()
        except Exception as e:
            results['checks'].append({
                'name': 'Connexion AD',
                'passed': False,
                'message': f'Impossible de se connecter: {str(e)}'
            })
            results['errors'].append(f'Connexion AD: {str(e)}')
    
    return jsonify(results)


@app.route('/api/password-audit')
@require_connection
def api_password_audit():
    """API d'audit des mots de passe."""
    from password_audit import run_password_audit
    from audit_history import save_audit
    from auto_alerts import send_critical_alerts
    from audit import log_action, ACTIONS

    conn, error = get_ad_connection()
    if not conn:
        return jsonify({'error': error}), 500

    base_dn = session.get('ad_base_dn', '')
    domain_name = session.get('ad_domain', 'Domaine AD')
    max_age = 90  # Jours

    audit_result = run_password_audit(conn, base_dn, max_age)
    
    # Sauvegarder dans l'historique
    save_audit(audit_result, domain_name)
    
    # Envoyer les alertes critiques automatiquement
    try:
        send_critical_alerts(audit_result)
    except Exception as e:
        logger.warning(f"Erreur envoi alertes automatiques: {e}")

    # Journaliser l'audit
    log_action(
        ACTIONS['OTHER'],
        session.get('ad_username', 'unknown'),
        {'action': 'password_audit', 'issues_found': audit_result['summary']['total_issues']},
        True
    )

    conn.unbind()
    return jsonify(audit_result)


# === ALERTES ===

@app.route('/alerts')
@require_connection
@require_permission('admin')
def alerts_page():
    """Page des alertes."""
    from alerts import get_alerts, get_alert_counts, run_full_alert_check
    
    # Vérifier si on doit lancer une vérification
    run_check = request.args.get('check', 'false').lower() == 'true'
    
    if run_check:
        conn, error = get_ad_connection()
        if conn:
            base_dn = session.get('ad_base_dn', '')
            run_full_alert_check(conn, base_dn)
            conn.unbind()
    
    # Récupérer les alertes
    alert_type = request.args.get('type', '')
    severity = request.args.get('severity', '')
    acknowledged = request.args.get('acknowledged', '')
    
    # Filtres
    filters = {}
    if alert_type:
        filters['alert_type'] = alert_type
    if severity:
        filters['severity'] = severity
    if acknowledged:
        filters['acknowledged'] = acknowledged == 'true'
    
    alerts_list = get_alerts(limit=100, **filters)
    counts = get_alert_counts()
    
    return render_template('alerts.html',
                         alert_data=counts,
                         alerts=alerts_list,
                         current_type=alert_type,
                         current_severity=severity,
                         connected=is_connected())


@app.route('/api/alerts')
@require_connection
@require_permission('admin')
def api_get_alerts():
    """API pour récupérer les alertes."""
    from alerts import get_alerts, get_alert_counts
    
    limit = request.args.get('limit', 50, type=int)
    alert_type = request.args.get('type', '')
    severity = request.args.get('severity', '')
    
    alerts_list = get_alerts(limit=limit, alert_type=alert_type, severity=severity)
    counts = get_alert_counts()
    
    return jsonify({
        'alerts': alerts_list,
        'counts': counts,
        'total': len(alerts_list)
    })


@app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
@require_connection
@require_permission('admin')
def api_acknowledge_alert(alert_id):
    """API pour acquitter une alerte."""
    from alerts import acknowledge_alert
    
    user = session.get('ad_username', 'unknown')
    success = acknowledge_alert(alert_id, user)
    
    if success:
        log_action(
            ACTIONS['OTHER'],
            user,
            {'action': 'acknowledge_alert', 'alert_id': alert_id},
            True
        )
        return jsonify({'success': True, 'message': 'Alerte acquittée'})
    else:
        return jsonify({'success': False, 'error': 'Alerte introuvable'}), 404


@app.route('/api/alerts/<alert_id>/delete', methods=['POST'])
@require_connection
@require_permission('admin')
def api_delete_alert(alert_id):
    """API pour supprimer une alerte."""
    from alerts import delete_alert
    
    delete_alert(alert_id)
    
    log_action(
        ACTIONS['OTHER'],
        session.get('ad_username', 'unknown'),
        {'action': 'delete_alert', 'alert_id': alert_id},
        True
    )
    
    return jsonify({'success': True, 'message': 'Alerte supprimée'})


@app.route('/api/alerts/check', methods=['POST'])
@require_connection
@require_permission('admin')
def api_check_alerts():
    """API pour lancer une vérification des alertes."""
    from alerts import run_full_alert_check, get_alert_counts
    
    conn, error = get_ad_connection()
    if not conn:
        return jsonify({'error': error}), 500
    
    base_dn = session.get('ad_base_dn', '')
    results = run_full_alert_check(conn, base_dn)
    conn.unbind()
    
    counts = get_alert_counts()
    
    return jsonify({
        'success': True,
        'results': results,
        'counts': counts
    })


@app.route('/api/check-update')
def api_check_update():
    """API pour vérifier les mises à jour."""
    try:
        from updater import check_for_updates_fast
        return jsonify(check_for_updates_fast())
    except Exception as e:
        return jsonify({'update_available': False, 'error': str(e)})


@app.route('/api/perform-update', methods=['POST'])
def api_perform_update():
    """API pour effectuer une mise à jour incrémentale."""
    try:
        import threading
        from updater import check_for_updates_fast, perform_fast_update, restart_server, update_dependencies

        info = check_for_updates_fast()
        if not info['update_available']:
            return jsonify({'success': False, 'message': 'Aucune mise à jour disponible'})

        result = perform_fast_update(silent=True)

        if result['success']:
            update_dependencies(silent=True)

            def delayed_restart():
                import time
                time.sleep(2)
                restart_server(silent=True)
                os._exit(0)

            threading.Thread(target=delayed_restart, daemon=True).start()

            return jsonify({
                'success': True,
                'message': f'Mise à jour réussie ({result["files_updated"]} fichiers). Redémarrage...',
                'restarting': True
            })
        else:
            return jsonify({'success': False, 'message': 'Erreur: ' + str(result.get('errors', []))[:200]})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


# === DIAGNOSTIC ET ERREURS ===

@app.route('/errors')
@require_connection
@require_permission('admin')
def error_logs():
    """Afficher les erreurs récentes."""
    from audit import get_audit_logs
    
    # Lire les logs d'erreurs
    error_logs = []
    log_files = ['logs/server.log', 'logs/service_error.log']
    
    for log_file in log_files:
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    # Filtrer les lignes avec ERROR ou Exception
                    for line in lines[-500:]:  # Dernières 500 lignes
                        if 'ERROR' in line or 'Exception' in line or 'Traceback' in line:
                            error_logs.append({
                                'file': log_file,
                                'line': line.strip(),
                                'timestamp': datetime.now().isoformat()
                            })
        except Exception as e:
            logger.warning(f"Could not read {log_file}: {e}")
    
    # Trier par timestamp (plus récent en premier)
    error_logs.reverse()
    
    return render_template('errors.html', 
                         error_logs=error_logs[:100],  # Limiter à 100 erreurs
                         connected=is_connected())


@app.route('/api/errors')
@require_connection
@require_permission('admin')
def api_error_logs():
    """API pour récupérer les erreurs récentes."""
    import os
    
    error_logs = []
    log_files = ['logs/server.log', 'logs/service_error.log', 'logs/audit.log']
    
    for log_file in log_files:
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for line in lines[-200:]:
                        if 'ERROR' in line or 'Exception' in line or 'Traceback' in line:
                            error_logs.append({
                                'file': log_file,
                                'line': line.strip(),
                                'timestamp': datetime.now().isoformat()
                            })
        except Exception as e:
            error_logs.append({'file': 'system', 'line': str(e), 'timestamp': datetime.now().isoformat()})
    
    error_logs.reverse()
    return jsonify({'errors': error_logs[:50], 'total': len(error_logs)})


# === CORRECTION PROTOCOLES OBSOLÈTES ===

@app.route('/api/fix-protocol', methods=['POST'])
@require_connection
@require_permission('admin')
def fix_protocol():
    """API pour appliquer les corrections de protocoles."""
    import subprocess
    import os
    
    data = request.get_json() or {}
    protocol = data.get('protocol', '')
    
    scripts = {
        'smbv1': 'scripts/fix_smbv1.ps1',
        'ntlm': 'scripts/fix_ntlm.ps1',
        'ldap_signing': 'scripts/fix_ldap_signing.ps1',
        'channel_binding': 'scripts/fix_channel_binding.ps1'
    }
    
    if protocol not in scripts:
        return jsonify({'success': False, 'error': f'Protocole inconnu: {protocol}'}), 400
    
    script_path = os.path.join(BASE_DIR, scripts[protocol])
    
    if not os.path.exists(script_path):
        return jsonify({'success': False, 'error': f'Script introuvable: {script_path}'}), 404
    
    try:
        # Exécuter le script PowerShell
        ps_command = ['powershell.exe', '-ExecutionPolicy', 'Bypass', '-File', script_path]
        
        proc = subprocess.Popen(
            ps_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = proc.communicate(timeout=60)
        
        if proc.returncode == 0:
            # Journaliser l'action
            log_action(
                ACTIONS['OTHER'],
                session.get('ad_username', 'system'),
                {'action': 'fix_protocol', 'protocol': protocol, 'script': scripts[protocol]},
                True
            )
            
            return jsonify({
                'success': True,
                'message': f'Correction {protocol} appliquée avec succès',
                'output': stdout[:2000] if stdout else ''
            })
        else:
            return jsonify({
                'success': False,
                'error': stderr[:500] if stderr else 'Erreur inconnue'
            }), 500
            
    except subprocess.TimeoutExpired:
        proc.kill()
        return jsonify({'success': False, 'error': 'Timeout - Le script a pris trop de temps'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def run_server():
    """
    Démarrer le serveur web avec support multi-plateforme.
    Utilise Waitress sur Windows, Gunicorn sur Linux, ou le serveur intégré Flask pour le développement.
    """
    import sys
    from config import IS_WINDOWS

    host = config.HOST
    port = config.PORT

    # Mode silencieux si AD_SILENT est défini ou si pas de console
    silent_mode = os.environ.get('AD_SILENT', '').lower() == 'true'

    # Détecter si on a une console (pour pythonw.exe)
    try:
        if sys.stdout is None or not hasattr(sys.stdout, 'write'):
            silent_mode = True
    except:
        silent_mode = True

    if not silent_mode:
        print(f"\n{'='*50}")
        print(f"Interface Web Microsoft Active Directory")
        print(f"{'='*50}")
        print(f"Plateforme: {platform.system()} ({platform.release()})")
        print(f"Écoute sur: http://{host}:{port}")
        print(f"Accès depuis n'importe quel appareil: http://<votre-ip>:{port}")
        print(f"{'='*50}\n")

    if IS_WINDOWS and not config.DEBUG:
        # Utiliser Waitress sur Windows (serveur WSGI de production, démarrage rapide)
        try:
            from waitress import serve
            if not silent_mode:
                print("Démarrage avec Waitress (serveur de production Windows)...")
            serve(app, host=host, port=port)
            return
        except ImportError:
            print("[AVERTISSEMENT] Waitress non disponible, bascule sur le serveur Flask")

    # Serveur Flask (développement ou Linux)
    app.run(host=host, port=port, debug=config.DEBUG, use_reloader=config.DEBUG)


if __name__ == '__main__':
    run_server()
