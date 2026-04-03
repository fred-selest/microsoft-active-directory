"""Routes sauvegardes d'objets AD."""
from flask import render_template, redirect, url_for, flash

from . import tools_bp
from ..core import is_connected, require_connection, require_permission


@tools_bp.route('/backups')
@require_connection
@require_permission('admin')
def backups():
    """Liste des sauvegardes d'objets AD."""
    from backup import get_backups
    backup_list = get_backups(limit=100)
    return render_template('backups.html', backups=backup_list, connected=is_connected())


@tools_bp.route('/backups/<filename>')
@require_connection
@require_permission('admin')
def view_backup(filename):
    """Voir le détail d'une sauvegarde."""
    from backup import get_backup_content
    backup = get_backup_content(filename)
    if not backup:
        flash('Sauvegarde introuvable.', 'error')
        return redirect(url_for('tools.backups'))
    return render_template('backup_detail.html', backup=backup, connected=is_connected())
