"""
Blueprint pour l'administration.
"""
import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app

from .core import is_connected, require_connection, require_permission
from security import validate_csrf_token

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route('/')
@require_connection
@require_permission('admin')
def admin_page():
    """Page d'administration."""
    try:
        from settings_manager import load_settings
        settings = load_settings()
    except Exception as e:
        flash(f'Erreur chargement: {str(e)}', 'error')
        settings = {
            'site': {'title': 'AD Web Interface', 'logo': '', 'footer': '', 'theme_color': '#0078d4'},
            'menu': {'items': [], 'dropdown_items': []},
            'features': {'dark_mode': True, 'language_switch': False, 'update_check': True, 'pwa_enabled': True},
            'security': {'session_timeout': 30, 'max_login_attempts': 5, 'require_https': False}
        }
    return render_template('admin.html', settings=settings, connected=is_connected())


@admin_bp.route('/save/general', methods=['POST'])
@require_connection
@require_permission('admin')
def save_general():
    """Sauvegarder les paramètres généraux."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('admin.admin_page'))

    from settings_manager import load_settings, save_settings

    settings = load_settings()
    settings['site']['title'] = request.form.get('site_title', 'AD Web Interface')
    settings['site']['footer'] = request.form.get('footer', '')
    settings['site']['theme_color'] = request.form.get('theme_color', '#0078d4')

    # Upload logo
    if 'logo' in request.files:
        file = request.files['logo']
        if file and file.filename:
            ext = file.filename.rsplit('.', 1)[-1].lower()
            if ext in {'png', 'jpg', 'jpeg', 'svg'}:
                logo_filename = f'logo.{ext}'
                logo_path = os.path.join(current_app.static_folder, 'images', logo_filename)
                os.makedirs(os.path.dirname(logo_path), exist_ok=True)
                file.save(logo_path)
                settings['site']['logo'] = logo_filename
                flash('Logo mis à jour!', 'success')

    if save_settings(settings):
        flash('Paramètres enregistrés!', 'success')
    else:
        flash('Erreur de sauvegarde.', 'error')

    return redirect(url_for('admin.admin_page'))


@admin_bp.route('/save/features', methods=['POST'])
@require_connection
@require_permission('admin')
def save_features():
    """Sauvegarder les paramètres de fonctionnalités."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('admin.admin_page'))

    from settings_manager import load_settings, save_settings

    settings = load_settings()
    settings['features']['dark_mode'] = request.form.get('dark_mode') == 'on'
    settings['features']['language_switch'] = request.form.get('language_switch') == 'on'
    settings['features']['update_check'] = request.form.get('update_check') == 'on'
    settings['features']['pwa_enabled'] = request.form.get('pwa_enabled') == 'on'

    if save_settings(settings):
        flash('Fonctionnalités enregistrées!', 'success')
    else:
        flash('Erreur de sauvegarde.', 'error')

    return redirect(url_for('admin.admin_page'))


@admin_bp.route('/save/security', methods=['POST'])
@require_connection
@require_permission('admin')
def save_security():
    """Sauvegarder les paramètres de sécurité."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('admin.admin_page'))

    from settings_manager import load_settings, save_settings

    settings = load_settings()
    settings['security']['session_timeout'] = int(request.form.get('session_timeout', 30))
    settings['security']['max_login_attempts'] = int(request.form.get('max_login_attempts', 5))
    settings['security']['require_https'] = request.form.get('require_https') == 'on'

    if save_settings(settings):
        flash('Sécurité enregistrée!', 'success')
    else:
        flash('Erreur de sauvegarde.', 'error')

    return redirect(url_for('admin.admin_page'))


@admin_bp.route('/reset', methods=['POST'])
@require_connection
@require_permission('admin')
def reset_settings():
    """Réinitialiser les paramètres."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('admin.admin_page'))

    from settings_manager import reset_to_defaults

    if reset_to_defaults():
        flash('Paramètres réinitialisés!', 'success')
    else:
        flash('Erreur de réinitialisation.', 'error')

    return redirect(url_for('admin.admin_page'))
