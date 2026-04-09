# -*- coding: utf-8 -*-
"""
Blueprint pour les routes principales (main).
Contient: index, connect, disconnect, dashboard, ous, audit, toggle-dark-mode
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE
from datetime import datetime

from .core import (get_ad_connection, decode_ldap_value, is_connected,
                   require_connection, get_user_role_from_groups)
from core.security import validate_csrf_token, check_rate_limit, record_attempt
from core.session_crypto import encrypt_password
from core.audit import log_action, ACTIONS
from core.ad_detect import get_local_domain, detect_ad_config

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Page d'accueil."""
    import platform
    if is_connected():
        return redirect(url_for('main.dashboard'))
    return render_template('index.html', system_info={
        'os': platform.system(),
        'hostname': platform.node()
    }, connected=False)


@main_bp.route('/connect', methods=['GET', 'POST'])
def connect():
    """Connexion au serveur AD."""
    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token invalide.', 'error')
            return render_template('connect.html', connected=is_connected(),
                                   show_fix_ldaps=False)

        ip = request.remote_addr
        allowed, remaining, attempts_left = check_rate_limit(ip)
        if not allowed:
            flash(f'Trop de tentatives. Réessayez dans {remaining}s.', 'error')
            return render_template('connect.html', connected=is_connected(),
                                   show_fix_ldaps=False)

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
                                   show_fix_ldaps=False,
                                   auto_domain=detected_domain2, auto_detected=False,
                                   server='', port=389,
                                   base_dn=ad_cfg2.get('base_dn', ''), use_ssl=False)

        port = int(port) if port else None
        conn, error = get_ad_connection(server, username, password, use_ssl, port)

        if conn:
            record_attempt(ip, success=True, action='login')
            session['ad_server'] = server
            session['ad_username'] = username
            session['ad_password'] = encrypt_password(password)
            session['ad_use_ssl'] = use_ssl
            session['ad_port'] = port
            session['ad_base_dn'] = base_dn

            if not base_dn and conn.server.info and conn.server.info.naming_contexts:
                session['ad_base_dn'] = str(conn.server.info.naming_contexts[0])

            # Rôle utilisateur (pour compatibilité)
            user_role, debug_info = get_user_role_from_groups(conn, username, debug=True)
            session['user_role'] = user_role

            # Sauvegarder les groupes de l'utilisateur (pour permissions granulaires)
            session['user_groups'] = debug_info.get('groups', [])

            # Rendre la session permanente pour conserver la connexion
            session.permanent = True

            # Stocker l'heure de connexion pour calculer la durée de session
            session['_login_time'] = datetime.now().isoformat()

            conn.unbind()

            log_action(ACTIONS['LOGIN'], username, {'server': server, 'role': user_role}, True, ip)

            # Afficher la page de succès de connexion au lieu de rediriger
            return render_template('login_success.html',
                                   username=username,
                                   user_role=user_role,
                                   user_groups=debug_info.get('groups', []),
                                   ad_server=server,
                                   now=datetime.now())
        else:
            record_attempt(ip, success=False, action='login')
            log_action(ACTIONS['LOGIN'], username, {'error': error}, False, ip)

            # Analyser l'erreur pour proposer une correction automatique
            error_lower = (error or '').lower()
            show_fix_ldaps = any(kw in error_lower for kw in [
                'strongerauthrequired',
                'channel binding',
                '10054',
                'forcibly closed',
                'connection reset',
            ])

            # Stocker les infos pour le formulaire de reconnexion après correction
            session['_connect_server'] = server
            session['_connect_username'] = username
            session['_connect_password'] = encrypt_password(password)
            session['_connect_domain'] = domain
            session['_connect_base_dn'] = base_dn

            flash(f'Erreur: {error}', 'error')
            return render_template('connect.html', connected=is_connected(),
                                   show_fix_ldaps=show_fix_ldaps,
                                   auto_domain=domain or detected_domain,
                                   auto_detected=auto_detected,
                                   server=server, port=port or 389,
                                   base_dn=base_dn, use_ssl=use_ssl)

    # GET : pré-remplir les champs via auto-détection
    ad_cfg = detect_ad_config()
    detected_domain = ad_cfg['domain'].split('.')[0].upper() if ad_cfg.get('domain') else ''
    auto_detected = ad_cfg.get('auto_detected', False) and bool(ad_cfg.get('server', ''))

    suggest_ssl = request.args.get('suggest_ssl', '0') == '1'
    use_ssl = True if suggest_ssl else ad_cfg.get('use_ssl', False)
    port = 636 if suggest_ssl else ad_cfg.get('port', 389)

    return render_template('connect.html', connected=is_connected(),
                           show_fix_ldaps=False,
                           auto_domain=detected_domain,
                           auto_detected=auto_detected,
                           server=ad_cfg.get('server', ''),
                           port=port,
                           base_dn=ad_cfg.get('base_dn', ''),
                           use_ssl=use_ssl)


@main_bp.route('/connect/fix-ldap-channel-binding', methods=['POST'])
def fix_ldap_channel_binding():
    """Executer le script de correction LDAP channel binding."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('main.connect'))

    import subprocess
    import os
    import logging

    logger = logging.getLogger('fix_ldap_cb')
    script_path = os.path.join(os.path.dirname(__file__), '..', 'scripts', 'fix_ldap_channel_binding.ps1')

    if not os.path.exists(script_path):
        flash('Script de correction introuvable.', 'error')
        return redirect(url_for('main.connect'))

    try:
        logger.info(f"Execution du script de correction LDAP: {script_path}")
        result = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path],
            capture_output=True,
            text=True,
            timeout=120
        )

        stdout = result.stdout or ''
        stderr = result.stderr or ''

        logger.info(f"Fix LDAP: returncode={result.returncode}")
        logger.info(f"Fix LDAP: stdout={stdout[:500]}")

        if 'SUCCESS' in stdout:
            flash('Correction LDAP appliquee avec succes! Reessayez de vous connecter.', 'success')
        elif 'PARTIAL' in stdout:
            flash('Correction partiellement appliquee. Redemarrez le service AD DS manuellement, puis reessayez.', 'warning')
        else:
            error_msg = stderr if stderr else stdout
            if 'Access is denied' in error_msg or 'access denied' in error_msg.lower():
                flash('Erreur de permissions. Executez ce script en tant qu\'Administrateur.', 'error')
            else:
                flash(f'Erreur lors de la correction: {error_msg[:300]}', 'error')

    except subprocess.TimeoutExpired:
        logger.error("Fix LDAP: Timeout")
        flash('Timeout lors de l\'execution du script.', 'error')
    except Exception as e:
        logger.error(f"Fix LDAP: Exception={e}", exc_info=True)
        flash(f'Erreur: {str(e)}', 'error')

    return redirect(url_for('main.connect'))


@main_bp.route('/disconnect')
def disconnect():
    """Déconnexion."""
    username = session.get('ad_username', 'unknown')

    # Calculer la durée de session si disponible
    session_start = session.get('_login_time')
    if session_start:
        try:
            login_time = datetime.fromisoformat(session_start)
            duration = datetime.now() - login_time
            hours, remainder = divmod(int(duration.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            session_duration = f"{hours}h {minutes}min"
        except (ValueError, TypeError):
            session_duration = "N/A"
    else:
        session_duration = "N/A"

    log_action(ACTIONS['LOGOUT'], username, {'session_duration': session_duration}, True, request.remote_addr)

    # Sauvegarder le nom d'utilisateur pour la page de déconnexion
    session.clear()
    session['_logged_out_user'] = username

    # Afficher la page de déconnexion au lieu de rediriger
    return render_template('logged_out.html',
                           username=username,
                           session_duration=session_duration,
                           now=datetime.now(),
                           quick_reconnect=False)


@main_bp.route('/toggle-dark-mode')
def toggle_dark_mode():
    """Basculer mode sombre."""
    session['dark_mode'] = not session.get('dark_mode', False)
    return redirect(request.referrer or url_for('main.index'))


@main_bp.route('/dashboard')
@require_connection
def dashboard():
    """Tableau de bord."""
    from core.dashboard_widgets import get_dashboard_widgets

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
            conn.search(base_dn, '(objectClass=group)', SUBTREE, attributes=['cn', 'member', 'groupType'])
            stats['total_groups'] = len(conn.entries)
            
            # Groupes spéciaux qui n'ont pas de membres directs mais utilisent primaryGroupID
            special_group_patterns = [
                'domain users', 'utilisateurs du domaine',
                'domain computers', 'ordinateurs du domaine',
                'domain controllers', 'contrôleurs de domaine',
                'domain guests', 'invités du domaine',
                'enterprise admins', 'administrateurs de l\'entreprise',
                'schema admins', 'administrateurs du schéma',
                'protected users', 'utilisateurs protégés'
            ]
            
            for e in conn.entries:
                cn_lower = str(e.cn).lower() if e.cn else ''
                members = e.member.values if hasattr(e, 'member') and e.member else []
                
                # Vérifier si c'est un groupe spécial
                is_special = any(pattern in cn_lower for pattern in special_group_patterns)
                
                # Un groupe est considéré vide seulement s'il n'a pas de membres ET n'est pas spécial
                if not members and not is_special:
                    stats['empty_groups'] += 1

            # Compter OUs
            conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['name'])
            stats['total_ous'] = len(conn.entries)

            # Récupérer widgets
            widgets = get_dashboard_widgets()

            # Alertes critiques
            critical_alerts = widgets.get('alerts', [])
        except Exception as e:
            print(f"Dashboard error: {e}")
            pass
        conn.unbind()

    return render_template('dashboard.html',
                         stats=stats,
                         widgets=widgets,
                         critical_alerts=critical_alerts,
                         connected=is_connected())


@main_bp.route('/audit')
@require_connection
def audit_logs():
    """Logs d'audit."""
    from core.audit import get_audit_logs
    page = request.args.get('page', 1, type=int)
    logs = get_audit_logs(limit=50)
    return render_template('audit.html', logs=logs, page=page, connected=is_connected())
