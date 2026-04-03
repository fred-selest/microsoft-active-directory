"""Routes diverses : modèles, favoris, API docs."""
from flask import redirect, url_for, flash, request

from . import tools_bp
from ..core import require_connection, require_permission


# NOTE: La route /alerts est définie dans routes/tools.py


@tools_bp.route('/templates')
@require_connection
def user_templates():
    flash('Fonctionnalité modèles disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))


@tools_bp.route('/templates/create', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def create_user_template():
    flash('Création de modèles disponible dans la version complète.', 'info')
    return redirect(url_for('tools.user_templates'))


@tools_bp.route('/templates/<template_id>/edit', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def edit_user_template(template_id):
    flash('Modification de modèles disponible dans la version complète.', 'info')
    return redirect(url_for('tools.user_templates'))


@tools_bp.route('/templates/<template_id>/delete', methods=['POST'])
@require_connection
@require_permission('write')
def delete_user_template(template_id):
    flash('Suppression de modèles disponible dans la version complète.', 'info')
    return redirect(url_for('tools.user_templates'))


@tools_bp.route('/favorites')
@require_connection
def favorites():
    flash('Fonctionnalité favoris disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))


@tools_bp.route('/favorites/toggle', methods=['POST'])
@require_connection
def toggle_favorite():
    flash('Gestion des favoris disponible dans la version complète.', 'info')
    return redirect(request.referrer or url_for('dashboard'))


@tools_bp.route('/api-docs')
@require_connection
@require_permission('admin')
def api_documentation():
    flash('Documentation API disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))


@tools_bp.route('/api-docs/generate-key', methods=['POST'])
@require_connection
@require_permission('admin')
def generate_api_key_route():
    flash('Génération de clé API disponible dans la version complète.', 'info')
    return redirect(url_for('tools.api_documentation'))


@tools_bp.route('/api-docs/revoke-key', methods=['POST'])
@require_connection
@require_permission('admin')
def revoke_api_key_route():
    flash('Révocation de clé API disponible dans la version complète.', 'info')
    return redirect(url_for('tools.api_documentation'))
