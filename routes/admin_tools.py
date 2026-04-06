# -*- coding: utf-8 -*-
"""
Blueprint pour les routes d'administration et outils.
Contient: update, diagnostic, alerts, errors, security-audit, permissions
"""
from flask import Blueprint, render_template, session, flash
from .core import require_connection, require_permission, get_ad_connection

admin_tools_bp = Blueprint('admin_tools', __name__, url_prefix='/')


@admin_tools_bp.route('/update')
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
    return render_template('update.html', update_info=update_info, connected=False)


@admin_tools_bp.route('/diagnostic')
@require_connection
def diagnostic_page():
    """Page de diagnostic et dépannage."""
    return render_template('diagnostic.html', connected=True)


@admin_tools_bp.route('/alerts')
@require_connection
def alerts_page():
    """Page des alertes."""
    return render_template('alerts.html', connected=True)


@admin_tools_bp.route('/errors')
@require_connection
def error_logs():
    """Page des logs d'erreurs."""
    import os
    from pathlib import Path

    error_log_path = Path('logs/server.log')
    errors = []

    if error_log_path.exists():
        try:
            with open(error_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                errors = [line.strip() for line in lines if 'ERROR' in line or 'Exception' in line]
                errors = errors[-50:]
        except:
            errors = ['Impossible de lire les logs']

    return render_template('errors.html', errors=errors, connected=True)


@admin_tools_bp.route('/security-audit')
@require_connection
@require_permission('admin')
def security_audit():
    """Audit de sécurité."""
    from security_audit import check_security_issues

    conn, error = get_ad_connection()
    if not conn:
        from flask import flash
        flash(f'Erreur: {error}', 'error')
        return render_template('security_audit.html', issues=[], connected=True)

    try:
        issues = check_security_issues(conn, session.get('ad_base_dn', ''))
        conn.unbind()
        return render_template('security_audit.html', issues=issues, connected=True)
    except Exception as e:
        from flask import flash
        flash(f'Erreur: {str(e)}', 'error')
        return render_template('security_audit.html', issues=[], connected=True)


@admin_tools_bp.route('/permissions')
@require_connection
@require_permission('admin')
def permissions_page():
    """Page de gestion des permissions."""
    from granular_permissions import get_all_groups_with_permissions, get_available_permissions, get_permission_categories

    groups = get_all_groups_with_permissions()
    all_permissions = get_available_permissions()
    categories = get_permission_categories()

    return render_template('admin.html',
                         groups=groups,
                         permissions=all_permissions,
                         categories=categories,
                         connected=True)
