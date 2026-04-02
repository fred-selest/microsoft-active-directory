"""Routes diverses : alertes, modèles, favoris, API docs."""
from flask import redirect, url_for, flash

from . import tools_bp
from ..core import require_connection, require_permission


@tools_bp.route('/alerts')
@require_connection
def alerts():
    flash('Fonctionnalité alertes disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))


@tools_bp.route('/templates')
@require_connection
def user_templates():
    flash('Fonctionnalité modèles disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))


@tools_bp.route('/favorites')
@require_connection
def favorites():
    flash('Fonctionnalité favoris disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))


@tools_bp.route('/api-docs')
@require_connection
@require_permission('admin')
def api_documentation():
    flash('Documentation API disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))
