"""
Blueprint pour l'administration.
"""
import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from werkzeug.utils import secure_filename

from routes.core import is_connected, require_connection, require_permission
from core.security import validate_csrf_token

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route('/')
@require_connection
@require_permission('admin')
def admin_page():
    """Page d'administration."""
    try:
        from core.settings_manager import load_settings
        settings = load_settings()
    except Exception as e:
        flash(f'Erreur chargement: {str(e)}', 'error')
        settings = {
            'site': {'title': 'AD Web Interface', 'logo': '', 'footer': '', 'theme_color': '#0078d4'},
            'menu': {'items': [], 'dropdown_items': []},
            'features': {'dark_mode': True, 'language_switch': False, 'update_check': True, 'pwa_enabled': True},
            'security': {'session_timeout': 30, 'max_login_attempts': 5, 'require_https': False},
            'smtp': {'enabled': False, 'server': '', 'port': 587, 'use_tls': True, 'use_auth': True, 'username': '', 'password': '', 'from_email': '', 'from_name': 'AD Web Interface'}
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

    from core.settings_manager import load_settings, save_settings

    settings = load_settings()
    settings['site']['title'] = request.form.get('site_title', 'AD Web Interface')
    settings['site']['footer'] = request.form.get('footer', '')
    settings['site']['theme_color'] = request.form.get('theme_color', '#0078d4')

    # Upload logo
    if 'logo' in request.files:
        file = request.files['logo']
        if file and file.filename:
            # Sécuriser le nom de fichier
            original_filename = secure_filename(file.filename)
            ext = original_filename.rsplit('.', 1)[-1].lower() if '.' in original_filename else ''

            # Valider l'extension
            ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'svg', 'gif', 'webp'}
            if ext in ALLOWED_EXTENSIONS:
                logo_filename = f'logo.{ext}'
                logo_path = os.path.join(current_app.static_folder, 'images', logo_filename)
                os.makedirs(os.path.dirname(logo_path), exist_ok=True)
                file.save(logo_path)
                settings['site']['logo'] = logo_filename
                flash('Logo mis à jour!', 'success')
            else:
                flash(f'Extension non autorisée: .{ext}. Formats acceptés: {", ".join(ALLOWED_EXTENSIONS)}', 'error')

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

    from core.settings_manager import load_settings, save_settings

    settings = load_settings()
    settings['features']['dark_mode'] = request.form.get('dark_mode') == 'on'
    settings['features']['language_switch'] = request.form.get('language_switch') == 'on'
    settings['features']['update_check'] = request.form.get('update_check') == 'on'
    settings['features']['pwa_enabled'] = request.form.get('pwa_enabled') == 'on'
    settings['features']['show_footer'] = request.form.get('show_footer') == 'on'
    settings['features']['users_column_chooser'] = request.form.get('users_column_chooser') == 'on'

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

    from core.settings_manager import load_settings, save_settings

    settings = load_settings()
    settings['security']['session_timeout'] = int(request.form.get('session_timeout', 30))
    settings['security']['max_login_attempts'] = int(request.form.get('max_login_attempts', 5))
    settings['security']['require_https'] = request.form.get('require_https') == 'on'

    if save_settings(settings):
        flash('Sécurité enregistrée!', 'success')
    else:
        flash('Erreur de sauvegarde.', 'error')

    return redirect(url_for('admin.admin_page'))


@admin_bp.route('/save/smtp', methods=['POST'])
@require_connection
@require_permission('admin')
def save_smtp_settings():
    """Sauvegarder les paramètres SMTP."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('admin.admin_page'))

    from core.settings_manager import load_settings, save_settings

    settings = load_settings()
    settings['smtp']['enabled'] = request.form.get('smtp_enabled') == 'on'
    settings['smtp']['server'] = request.form.get('smtp_server', '').strip()
    settings['smtp']['port'] = int(request.form.get('smtp_port', 587))
    settings['smtp']['use_tls'] = request.form.get('smtp_use_tls') == 'on'
    settings['smtp']['use_auth'] = request.form.get('smtp_use_auth') == 'on'
    settings['smtp']['username'] = request.form.get('smtp_username', '').strip()
    settings['smtp']['password'] = request.form.get('smtp_password', '').strip()
    settings['smtp']['from_email'] = request.form.get('smtp_from_email', '').strip()
    settings['smtp']['from_name'] = request.form.get('smtp_from_name', 'AD Web Interface').strip()

    if save_settings(settings):
        flash('Configuration SMTP enregistrée!', 'success')
    else:
        flash('Erreur de sauvegarde.', 'error')

    return redirect(url_for('admin.admin_page'))


@admin_bp.route('/test/smtp', methods=['POST'])
@require_connection
@require_permission('admin')
def test_smtp():
    """Tester l'envoi d'email SMTP."""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from core.updater import get_current_version
    
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('admin.admin_page'))

    from core.settings_manager import load_settings
    settings = load_settings()
    smtp = settings.get('smtp', {})

    try:
        # Créer le message
        msg = MIMEMultipart()
        msg['From'] = f"{smtp.get('from_name', 'AD Web Interface')} <{smtp.get('from_email', '')}>"
        msg['To'] = request.form.get('test_email', '').strip()
        msg['Subject'] = '[AD Web Interface] Test de configuration SMTP'

        body = """
        <html>
        <body>
            <h2>✅ Test SMTP réussi!</h2>
            <p>Ceci est un email de test envoyé depuis l'interface Web Active Directory.</p>
            <p><strong>Configuration:</strong></p>
            <ul>
                <li>Serveur: {server}</li>
                <li>Port: {port}</li>
                <li>TLS: {tls}</li>
            </ul>
            <p>Si vous recevez cet email, la configuration SMTP est correcte.</p>
            <hr>
            <p><small>AD Web Interface v{version}</small></p>
        </body>
        </html>
        """.format(
            server=smtp.get('server', 'N/A'),
            port=smtp.get('port', 'N/A'),
            tls='Oui' if smtp.get('use_tls') else 'Non',
            version=get_current_version()
        )

        msg.attach(MIMEText(body, 'html', 'utf-8'))

        # Connexion au serveur SMTP
        server = smtplib.SMTP(smtp.get('server', ''), smtp.get('port', 587))
        server.set_debuglevel(0)

        if smtp.get('use_tls'):
            server.starttls()

        if smtp.get('use_auth') and smtp.get('username') and smtp.get('password'):
            server.login(smtp.get('username', ''), smtp.get('password', ''))

        server.send_message(msg)
        server.quit()

        flash(f'Email de test envoyé avec succès à {msg["To"]}!', 'success')

    except smtplib.SMTPAuthenticationError:
        flash('Erreur: Authentification SMTP échouée. Vérifiez username/password.', 'error')
    except smtplib.SMTPConnectError:
        flash(f'Erreur: Connexion au serveur SMTP échouée. Vérifiez serveur:port', 'error')
    except smtplib.SMTPException as e:
        flash(f'Erreur SMTP: {str(e)}', 'error')
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')

    return redirect(url_for('admin.admin_page'))


@admin_bp.route('/reset', methods=['POST'])
@require_connection
@require_permission('admin')
def reset_settings():
    """Réinitialiser les paramètres."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('admin.admin_page'))

    from core.settings_manager import reset_settings as reset_to_defaults

    if reset_to_defaults():
        flash('Paramètres réinitialisés!', 'success')
    else:
        flash('Erreur de réinitialisation.', 'error')

    return redirect(url_for('admin.admin_page'))


@admin_bp.route('/save/menu', methods=['POST'])
@require_connection
@require_permission('admin')
def save_menu():
    """Sauvegarder les paramètres de menu."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('admin.admin_page'))

    from core.settings_manager import load_settings, save_settings

    settings = load_settings()

    # Mettre à jour les items du menu principal
    if 'menu' not in settings:
        settings['menu'] = {'items': [], 'dropdown_items': []}

    for item in settings['menu'].get('items', []):
        item_id = item.get('id', '')
        item['enabled'] = request.form.get(f'menu_{item_id}_enabled') == 'on'
        item['label'] = request.form.get(f'menu_{item_id}_label', item.get('label', ''))
        item['order'] = int(request.form.get(f'menu_{item_id}_order', item.get('order', 1)))

    # Mettre à jour les items dropdown
    for item in settings['menu'].get('dropdown_items', []):
        item_id = item.get('id', '')
        item['enabled'] = request.form.get(f'dropdown_{item_id}_enabled') == 'on'
        item['label'] = request.form.get(f'dropdown_{item_id}_label', item.get('label', ''))
        item['order'] = int(request.form.get(f'dropdown_{item_id}_order', item.get('order', 1)))

    if save_settings(settings):
        flash('Menu enregistré!', 'success')
    else:
        flash('Erreur de sauvegarde.', 'error')

    return redirect(url_for('admin.admin_page'))


@admin_bp.route('/export')
@require_connection
@require_permission('admin')
def export_settings():
    """Exporter les paramètres en JSON."""
    import json
    from flask import Response
    from core.settings_manager import load_settings

    settings = load_settings()

    return Response(
        json.dumps(settings, indent=2, ensure_ascii=False),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=ad_settings.json'}
    )


@admin_bp.route('/save/password', methods=['POST'])
@require_connection
@require_permission('admin')
def save_password_settings():
    """Sauvegarder les paramètres de mot de passe par défaut."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('admin.admin_page'))

    from core.settings_manager import load_settings, save_settings

    settings = load_settings()
    
    # Paramètres de mot de passe
    settings['password']['default_password'] = request.form.get('default_password', '')
    settings['password']['password_complexity'] = request.form.get('password_complexity', 'high')
    settings['password']['password_length'] = int(request.form.get('password_length', 16))
    settings['password']['exclude_ambiguous_chars'] = request.form.get('exclude_ambiguous_chars') == 'on'
    settings['password']['must_change_at_next_login'] = request.form.get('must_change_at_next_login') == 'on'
    
    save_settings(settings)
    flash('Paramètres de mot de passe sauvegardés.', 'success')
    
    return redirect(url_for('admin.admin_page'))


@admin_bp.route('/generate-password', methods=['POST'])
@require_connection
@require_permission('admin')
def api_generate_password():
    """Générer un nouveau mot de passe par défaut."""
    from core.settings_manager import generate_new_default_password
    from flask import jsonify
    
    complexity = request.form.get('complexity', 'high')
    length = int(request.form.get('length', 16))
    exclude_ambiguous = request.form.get('exclude_ambiguous') == 'on'
    
    try:
        password = generate_new_default_password(
            complexity=complexity,
            length=length,
            exclude_ambiguous=exclude_ambiguous
        )
        
        return jsonify({
            'success': True,
            'password': password,
            'message': 'Nouveau mot de passe généré et sauvegardé.'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin_bp.route('/check-password-strength', methods=['POST'])
@require_connection
@require_permission('admin')
def api_check_password_strength():
    """Vérifier la force d'un mot de passe."""
    from core.password_generator import check_password_complexity
    from flask import jsonify
    
    password = request.form.get('password', '')
    
    if not password:
        return jsonify({
            'success': False,
            'error': 'Mot de passe requis'
        }), 400
    
    result = check_password_complexity(password)
    
    return jsonify({
        'success': True,
        'complexity': result
    })
