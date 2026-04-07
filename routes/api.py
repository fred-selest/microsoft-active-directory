# -*- coding: utf-8 -*-
"""
Blueprint pour les routes API.
Contient toutes les routes /api/*
"""
from flask import Blueprint, jsonify, request, session
import platform

from .core import get_ad_connection, is_connected, require_connection, require_permission
from core.features import require_feature

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/health')
def api_health():
    """Endpoint de health check pour Docker/Kubernetes."""
    from core.updater import get_current_version
    return jsonify({
        'status': 'healthy',
        'version': get_current_version(),
        'platform': platform.system()
    })


@api_bp.route('/system-info')
def api_system_info():
    """Endpoint pour les informations système complètes."""
    from core.updater import get_current_version

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


@api_bp.route('/diagnostic')
def api_diagnostic():
    """API de diagnostic automatique."""
    from core.diagnostic import run_full_diagnostic
    from ldap3 import SUBTREE

    server = session.get('ad_server', 'localhost')
    port = session.get('ad_port', 389)

    results = run_full_diagnostic(server, port)

    if is_connected():
        try:
            conn, error = get_ad_connection()
            if conn:
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


@api_bp.route('/password-audit')
@require_connection
def api_password_audit():
    """API d'audit des mots de passe."""
    from password_audit import run_password_audit
    from core.audit_history import save_audit
    from core.auto_alerts import send_critical_alerts
    from core.audit import log_action, ACTIONS
    from core.debug_utils import logger

    conn, error = get_ad_connection()
    if not conn:
        return jsonify({'error': error}), 500

    base_dn = session.get('ad_base_dn', '')
    domain_name = session.get('ad_domain', 'Domaine AD')
    max_age = 90

    audit_result = run_password_audit(conn, base_dn, max_age)
    save_audit(audit_result, domain_name)

    try:
        send_critical_alerts(audit_result)
    except Exception as e:
        logger.warning(f"Erreur envoi alertes automatiques: {e}")

    log_action(
        ACTIONS['OTHER'],
        session.get('ad_username', 'unknown'),
        {'action': 'password_audit', 'issues_found': audit_result['summary']['total_issues']},
        True
    )

    conn.unbind()
    return jsonify(audit_result)


@api_bp.route('/password-audit/quick-fix', methods=['POST'])
@require_connection
@require_permission('admin')
def api_password_audit_quick_fix():
    """API pour appliquer des corrections rapides sur l'audit MDP."""
    from ldap3 import MODIFY_REPLACE

    data = request.get_json() if request.is_json else request.form
    fix_type = data.get('fix_type')
    accounts = data.get('accounts', [])

    conn, error = get_ad_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Connexion échouée'}), 500

    base_dn = session.get('ad_base_dn', '')
    results = {'success': False, 'message': '', 'modified': 0, 'total': 0}

    try:
        if fix_type == 'force_password_change':
            if not accounts:
                from password_audit import check_weak_passwords
                weak_accounts = check_weak_passwords(conn, base_dn)
                accounts = [{'dn': acc.get('dn'), 'username': acc.get('username')} for acc in weak_accounts]

            results['total'] = len(accounts)
            modified = 0

            for account in accounts:
                if account.get('dn'):
                    conn.modify(account['dn'], {
                        'pwdLastSet': [(MODIFY_REPLACE, [0])]
                    })
                    if conn.result['result'] == 0:
                        modified += 1

            results = {
                'success': True,
                'message': f'{modified}/{results["total"]} compte(s) modifié(s).',
                'modified': modified,
                'total': results['total']
            }

        elif fix_type == 'enable_password_expiry_admin':
            if not accounts:
                from password_audit import check_admin_weak_passwords
                admin_accounts = check_admin_weak_passwords(conn, base_dn)
                accounts = [{'dn': acc.get('dn'), 'username': acc.get('username')} for acc in admin_accounts]

            results['total'] = len(accounts)
            modified = 0

            for account in accounts:
                if account.get('dn'):
                    conn.modify(account['dn'], {
                        'pwdLastSet': [(MODIFY_REPLACE, [0])]
                    })
                    if conn.result['result'] == 0:
                        modified += 1

            results = {
                'success': True,
                'message': f'{modified}/{results["total"]} compte(s) admin modifié(s).',
                'modified': modified,
                'total': results['total']
            }

    except Exception as e:
        results = {'success': False, 'message': str(e), 'modified': 0, 'total': 0}

    finally:
        conn.unbind()

    return jsonify(results)


@api_bp.route('/alerts')
def api_get_alerts():
    """API pour récupérer les alertes."""
    from core.alerts import get_all_alerts
    alert_type = request.args.get('type', 'all')
    alerts = get_all_alerts(alert_type)
    return jsonify({'alerts': alerts})


@api_bp.route('/alerts/<alert_id>/acknowledge', methods=['POST'])
def api_acknowledge_alert(alert_id):
    """API pour acquitter une alerte."""
    from core.alerts import acknowledge_alert
    success = acknowledge_alert(alert_id)
    if success:
        return jsonify({'success': True, 'message': 'Alerte acquittée'})
    return jsonify({'success': False, 'message': 'Alerte introuvable'}), 404


@api_bp.route('/alerts/<alert_id>/delete', methods=['POST'])
def api_delete_alert(alert_id):
    """API pour supprimer une alerte."""
    from core.alerts import delete_alert
    success = delete_alert(alert_id)
    if success:
        return jsonify({'success': True, 'message': 'Alerte supprimée'})
    return jsonify({'success': False, 'message': 'Alerte introuvable'}), 404


@api_bp.route('/alerts/check', methods=['POST'])
def api_check_alerts():
    """API pour vérifier les alertes."""
    from core.alerts import run_full_alert_check
    from core.audit import log_action, ACTIONS

    results = run_full_alert_check()
    log_action(ACTIONS['OTHER'], session.get('ad_username', 'system'),
              {'action': 'alert_check', 'results': results}, True)

    return jsonify(results)


@api_bp.route('/check-update')
def api_check_update():
    """API pour vérifier les mises à jour."""
    from core.updater import check_for_updates_fast
    update_info = check_for_updates_fast()
    return jsonify(update_info)


@api_bp.route('/perform-update', methods=['POST'])
def api_perform_update():
    """API pour effectuer une mise à jour."""
    import threading
    import time
    from core.updater import perform_update_fast

    def delayed_restart():
        time.sleep(2)
        import sys
        import os
        os.execl(sys.executable, sys.executable, 'run.py')

    try:
        result = perform_update_fast()
        if result.get('success'):
            threading.Thread(target=delayed_restart).start()
            return jsonify({'success': True, 'message': 'Mise à jour en cours, redémarrage...'})
        return jsonify(result), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/errors')
def api_error_logs():
    """API pour récupérer les logs d'erreurs."""
    import os
    from pathlib import Path

    error_log_path = Path('logs/server.log')
    errors = []

    if error_log_path.exists():
        try:
            with open(error_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                errors = [line.strip() for line in lines if 'ERROR' in line or 'Exception' in line]
                errors = errors[-100:]  # 100 dernières erreurs
        except:
            errors = ['Impossible de lire les logs']

    return jsonify({'errors': errors, 'count': len(errors)})


@api_bp.route('/security-fix', methods=['POST'])
@require_connection
@require_permission('admin')
def api_security_fix():
    """API pour appliquer des corrections de sécurité."""
    from core.security_audit import apply_security_fix
    from core.audit import log_action, ACTIONS

    data = request.get_json() if request.is_json else request.form
    fix_type = data.get('fix_type', '')
    params = data.get('params', {})

    try:
        result = apply_security_fix(fix_type, params)
        log_action(ACTIONS['OTHER'], session.get('ad_username'),
                  {'action': 'security_fix', 'type': fix_type, 'result': result}, True)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/permissions', methods=['POST'])
@require_connection
@require_permission('admin')
def api_permissions():
    """API pour sauvegarder les permissions d'un groupe."""
    from core.granular_permissions import set_group_permissions
    from core.audit import log_action, ACTIONS

    data = request.get_json() if request.is_json else request.form
    group_name = data.get('group_name')
    permissions = data.get('permissions', [])

    if not group_name:
        return jsonify({'success': False, 'error': 'Nom du groupe requis'}), 400

    try:
        result = set_group_permissions(group_name, permissions)
        log_action(ACTIONS['OTHER'], session.get('ad_username'),
                  {'action': 'set_permissions', 'group': group_name}, True)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/permissions/<group_name>', methods=['DELETE'])
@require_connection
@require_permission('admin')
def api_delete_permissions(group_name):
    """API pour supprimer les permissions d'un groupe."""
    from core.granular_permissions import delete_group_permissions
    from core.audit import log_action, ACTIONS

    try:
        result = delete_group_permissions(group_name)
        log_action(ACTIONS['OTHER'], session.get('ad_username'),
                  {'action': 'delete_permissions', 'group': group_name}, True)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
