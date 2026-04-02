"""
Blueprint de debug pour AD Web Interface.
Routes de débogage pour le développement.
"""

from flask import Blueprint, render_template, jsonify, session, request, flash, redirect, url_for
from routes.core import require_connection, is_connected, require_permission
import sys
import os

debug_bp = Blueprint('debug', __name__, url_prefix='/_debug')


def require_admin(f):
    """Décorateur pour exiger le rôle admin."""
    from functools import wraps
    from flask import session
    from config import get_config
    
    config = get_config()
    
    @wraps(f)
    def decorated(*args, **kwargs):
        if not config.RBAC_ENABLED:
            return f(*args, **kwargs)
        
        user_role = session.get('user_role', config.DEFAULT_ROLE)
        if user_role != 'admin':
            flash('Accès réservé aux administrateurs.', 'error')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated


@debug_bp.route('/')
@require_connection
@require_admin
def debug_dashboard():
    """Page de debug principale."""
    from debug_utils import get_debug_info, log_session_data, check_feature_flags
    from flask import current_app

    # Récupérer les infos de debug
    debug_data = get_debug_info()
    session_data = log_session_data()
    feature_flags = check_feature_flags()

    # Ajouter le nombre de routes (convertir en liste sérialisable)
    routes = []
    for rule in current_app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'rule': str(rule),
            'methods': sorted(list(rule.methods - {'HEAD', 'OPTIONS'}))
        })
    debug_data['routes'] = routes
    debug_data['routes_count'] = len(routes)

    return render_template('debug/dashboard.html',
                         debug_data=debug_data,
                         session_data=session_data,
                         feature_flags=feature_flags,
                         connected=is_connected())


@debug_bp.route('/api')
@require_connection
@require_admin
def debug_api():
    """API de debug - retourne les infos en JSON."""
    from debug_utils import get_debug_info
    return jsonify(get_debug_info())


@debug_bp.route('/routes')
@require_connection
@require_admin
def debug_routes():
    """Liste toutes les routes enregistrées."""
    from flask import current_app

    routes = []
    for rule in current_app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods - {'HEAD', 'OPTIONS'}),
            'rule': str(rule),
        })

    # Trier par endpoint
    routes.sort(key=lambda x: x['endpoint'])

    return jsonify({
        'total_routes': len(routes),
        'routes': routes
    })


@debug_bp.route('/templates')
@require_connection
@require_admin
def debug_templates():
    """Liste tous les templates."""
    import os
    from pathlib import Path

    templates_dir = Path(__file__).parent.parent / 'templates'
    templates = []

    for template_file in templates_dir.glob('**/*.html'):
        rel_path = template_file.relative_to(templates_dir)
        templates.append({
            'name': str(rel_path),
            'size': template_file.stat().st_size,
        })

    templates.sort(key=lambda x: x['name'])

    return jsonify({
        'total_templates': len(templates),
        'templates': templates
    })


@debug_bp.route('/session')
@require_connection
@require_admin
def debug_session():
    """Affiche le contenu de la session."""
    session_data = dict(session)

    # Masquer les données sensibles
    if 'ad_password' in session_data:
        session_data['ad_password'] = '***ENCRYPTED***'

    return jsonify({
        'session_keys': list(session_data.keys()),
        'session_data': session_data,
        'session_length': len(session_data)
    })


@debug_bp.route('/config')
@require_connection
@require_admin
def debug_config():
    """Affiche la configuration."""
    from config import get_config
    config = get_config()
    
    config_data = {
        'DEBUG': config.DEBUG,
        'HOST': config.HOST,
        'PORT': config.PORT,
        'RBAC_ENABLED': config.RBAC_ENABLED,
        'DEFAULT_ROLE': config.DEFAULT_ROLE,
        'SESSION_TIMEOUT': config.SESSION_TIMEOUT,
        'ITEMS_PER_PAGE': config.ITEMS_PER_PAGE,
        'FEATURE_FLAGS': {
            'users': config.FEATURE_USERS_ENABLED,
            'groups': config.FEATURE_GROUPS_ENABLED,
            'computers': config.FEATURE_COMPUTERS_ENABLED,
            'laps': config.FEATURE_LAPS_ENABLED,
            'bitlocker': config.FEATURE_BITLOCKER_ENABLED,
            'recycle_bin': config.FEATURE_RECYCLE_BIN_ENABLED,
            'locked_accounts': config.FEATURE_LOCKED_ACCOUNTS_ENABLED,
            'audit_logs': config.FEATURE_AUDIT_LOGS_ENABLED,
            'diagnostic': config.FEATURE_DIAGNOSTIC_ENABLED,
            'password_policy': config.FEATURE_PASSWORD_POLICY_ENABLED,
            'password_audit': config.FEATURE_PASSWORD_AUDIT_ENABLED,
        }
    }
    
    return jsonify(config_data)


@debug_bp.route('/logs')
@require_connection
@require_admin
def debug_logs():
    """Affiche les derniers logs."""
    import os

    lines = request.args.get('lines', 50, type=int)
    log_type = request.args.get('type', 'debug')  # debug, error, audit

    log_files = {
        'debug': 'logs/debug.log',
        'error': 'logs/server.log',
        'audit': 'logs/audit.log',
        'service': 'logs/service.log',
    }

    log_file = log_files.get(log_type, 'logs/debug.log')

    if not os.path.exists(log_file):
        return jsonify({'error': f'Log file not found: {log_file}'}), 404

    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
            recent_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines

        return jsonify({
            'file': log_file,
            'total_lines': len(all_lines),
            'returned_lines': len(recent_lines),
            'logs': [line.strip() for line in recent_lines]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@debug_bp.route('/test/<page_name>')
@require_connection
@require_admin
def debug_test_page(page_name):
    """Teste une page spécifique."""
    from flask import url_for

    # Mapping des pages
    pages = {
        'dashboard': 'dashboard',
        'users': 'users.list_users',
        'groups': 'groups.list_groups',
        'computers': 'computers.list_computers',
        'ous': 'ous',
        'laps': 'tools.laps_passwords',
        'bitlocker': 'tools.bitlocker_keys',
        'recycle-bin': 'tools.recycle_bin',
        'locked-accounts': 'tools.locked_accounts',
        'audit': 'audit_logs',
        'admin': 'admin.admin_page',
        'password-policy': 'tools.password_policy',
    }

    if page_name not in pages:
        return jsonify({
            'error': f'Page not found: {page_name}',
            'available_pages': list(pages.keys())
        }), 404

    endpoint = pages[page_name]

    try:
        # Tester la construction de l'URL
        url = url_for(endpoint)

        return jsonify({
            'success': True,
            'page': page_name,
            'endpoint': endpoint,
            'url': url,
            'status': '✅ OK'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'page': page_name,
            'endpoint': endpoint,
            'error': str(e),
            'status': '❌ ERROR'
        }), 500


@debug_bp.route('/all-pages')
@require_connection
@require_admin
def debug_all_pages():
    """Teste toutes les pages et retourne les erreurs."""
    from flask import url_for
    import requests
    
    base_url = f"http://localhost:{request.host.split(':')[1]}"
    
    pages = [
        ('/', 'Accueil'),
        ('/dashboard', 'Dashboard'),
        ('/users', 'Utilisateurs'),
        ('/groups', 'Groupes'),
        ('/computers', 'Ordinateurs'),
        ('/ous', 'OUs'),
        ('/laps', 'LAPS'),
        ('/bitlocker', 'BitLocker'),
        ('/recycle-bin', 'Corbeille'),
        ('/locked-accounts', 'Comptes verrouillés'),
        ('/audit', 'Audit'),
        ('/admin', 'Admin'),
        ('/password-policy', 'Password Policy'),
    ]
    
    results = []
    
    for path, name in pages:
        try:
            resp = requests.get(base_url + path, cookies=request.cookies, timeout=5)
            status = '✅' if resp.status_code == 200 else '⚠️'
            results.append({
                'page': name,
                'path': path,
                'status_code': resp.status_code,
                'status': status,
                'error': None
            })
        except Exception as e:
            results.append({
                'page': name,
                'path': path,
                'status_code': None,
                'status': '❌',
                'error': str(e)
            })
    
    return jsonify({
        'total_pages': len(results),
        'success': sum(1 for r in results if r['status'] == '✅'),
        'errors': sum(1 for r in results if r['status'] == '❌'),
        'results': results
    })
