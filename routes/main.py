# -*- coding: utf-8 -*-
"""
Blueprint pour les routes principales (main).
Contient: index, connect, disconnect, dashboard, ous, audit, toggle-dark-mode
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE
from datetime import datetime, timedelta
import logging

from .core import (get_ad_connection, decode_ldap_value, is_connected,
                   require_connection, get_user_role_from_groups)
from security import validate_csrf_token, check_rate_limit, record_attempt
from session_crypto import encrypt_password
from audit import log_action, ACTIONS
from ad_detect import get_local_domain, detect_ad_config

main_bp = Blueprint('main', __name__)
logger = logging.getLogger(__name__)


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
            return render_template('connect.html', connected=is_connected())

        ip = request.remote_addr
        allowed, remaining, attempts_left = check_rate_limit(ip)
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
        
        # DEBUG: Log SSL parameters
        logger.info(f"DEBUG LOGIN FORM: use_ssl={use_ssl}, port={port}, server={server}")
        
        # Si SSL coché mais port vide ou 389, forcer port 636
        if use_ssl and (not port or port == '389'):
            port = '636'
            logger.info(f"DEBUG: SSL coché, port forcé à 636")

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
    from dashboard_widgets import get_dashboard_widgets

    conn, error = get_ad_connection()
    stats = {'total_users': 0, 'active_users': 0, 'disabled_users': 0,
             'total_groups': 0, 'empty_groups': 0, 'total_ous': 0,
             'locked_accounts': 0, 'inactive_accounts': 0, 'inactive_computers': 0,
             'admin_accounts': 0}
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

            # Compter groupes et groupes vides (exclure groupes système)
            # Groupes système à exclure (primaryGroupToken)
            SYSTEM_GROUP_TOKENS = [
                513, 514, 515, 516, 498, 521, 522, 525, 526, 527,
                548, 549, 550, 551, 552, 553, 556, 557, 558, 559, 560, 562, 568, 569, 571, 573, 579, 580, 582,
                1102, 1103, 1104, 1114, 1118, 1121, 1124, 1125, 1126, 1129, 1153, 1154,
            ]
            conn.search(base_dn, '(objectClass=group)', SUBTREE, attributes=['cn', 'member', 'primaryGroupToken'])
            stats['total_groups'] = len(conn.entries)
            for e in conn.entries:
                # Exclure groupes système
                is_system = False
                token_attr = getattr(e, 'primaryGroupToken', None)
                if token_attr and token_attr.value:
                    try:
                        if int(str(token_attr.value)) in SYSTEM_GROUP_TOKENS:
                            is_system = True
                    except:
                        pass
                # Vérifier membres
                members = e.member.values if hasattr(e, 'member') and e.member else []
                if not is_system and not members:
                    stats['empty_groups'] += 1

            # Compter OUs
            conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['name'])
            stats['total_ous'] = len(conn.entries)

            # Comptes verrouillés
            conn.search(base_dn, '(&(objectClass=user)(lockoutTime>=1))', SUBTREE, attributes=['cn'])
            stats['locked_accounts'] = len(conn.entries)

            # Comptes inactifs (> 90 jours)
            conn.search(base_dn, '(objectClass=user)', SUBTREE, attributes=['lastLogon'])
            now = datetime.now()
            for e in conn.entries:
                last_logon_attr = getattr(e, 'lastLogon', None)
                if last_logon_attr and last_logon_attr.value:
                    try:
                        val = int(str(last_logon_attr.value))
                        if val == 0:
                            stats['inactive_accounts'] += 1
                        else:
                            logon_date = datetime.fromtimestamp(val / 10000000 - 11644473600)
                            if (now - logon_date).days > 90:
                                stats['inactive_accounts'] += 1
                    except:
                        pass

            # Ordinateurs inactifs (> 30 jours)
            conn.search(base_dn, '(objectClass=computer)', SUBTREE, attributes=['lastLogonTimestamp'])
            for e in conn.entries:
                last_logon_attr = getattr(e, 'lastLogonTimestamp', None)
                if last_logon_attr and last_logon_attr.value:
                    try:
                        val = int(str(last_logon_attr.value))
                        if val > 0:
                            logon_date = datetime.fromtimestamp(val / 10000000 - 11644473600)
                            if (now - logon_date).days > 30:
                                stats['inactive_computers'] += 1
                    except:
                        pass

            # Comptes Domain Admins
            conn.search(base_dn, '(&(objectClass=user)(memberof=CN=Domain Admins,CN=Users,' + base_dn + '))', SUBTREE, attributes=['cn'])
            stats['admin_accounts'] = len(conn.entries)

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


    """Construire une arborescence à partir d'une liste plate d'OUs."""
    root = {
        'name': base_dn.split(',')[0].replace('DC=', '') if base_dn else 'Domaine',
        'dn': base_dn,
        'type': 'domain',
        'children': []
    }

    sorted_ous = sorted(ous, key=lambda x: x['dn'].count(','))

    for ou in sorted_ous:
        add_ou_to_tree(root, ou)

    return root


@main_bp.route('/audit')
@require_connection
def audit_logs():
    """Logs d'audit."""
    from audit import get_audit_logs
    page = request.args.get('page', 1, type=int)
    logs = get_audit_logs(limit=50)
    return render_template('audit.html', logs=logs, page=page, connected=is_connected())
