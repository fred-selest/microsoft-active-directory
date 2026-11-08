# -*- coding: utf-8 -*-
"""
Blueprint pour les routes d'administration et outils.
Contient: update, diagnostic, alerts, errors, security-audit, permissions
"""
import time
from flask import Blueprint, render_template, session, flash
from .core import require_connection, require_permission, get_ad_connection

admin_tools_bp = Blueprint('admin_tools', __name__, url_prefix='/')

# Cache des releases GitHub (30 min) pour eviter les requetes repetitives
_release_cache = {'data': None, 'time': 0, 'ttl': 1800}


def _get_github_headers():
    """Headers GitHub API avec token si disponible (reduit rate limit de 60/h a 5000/h)."""
    import os
    headers = {'User-Agent': 'AD-WebInterface/1.0'}
    token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GITHUB_API_TOKEN')
    if not token:
        env_file = None
        try:
            from pathlib import Path
            env_file = Path(__file__).resolve().parent.parent / '.env'
            if env_file.exists():
                for line in env_file.read_text(encoding='utf-8').splitlines():
                    line = line.strip()
                    if line.startswith('GITHUB_TOKEN=') and not line.startswith('#'):
                        token = line.split('=', 1)[1].strip().strip('"').strip("'")
                        break
        except Exception:
            pass
    if token:
        headers['Authorization'] = f'token {token}'
    return headers


@admin_tools_bp.route('/update')
@require_connection
@require_permission('system:update')
def update_page():
    """Page de mise à jour."""
    import os
    import platform
    import subprocess
    import json
    from datetime import datetime

    try:
        from core.updater import check_for_updates_fast, get_update_statistics, PROJECT_ROOT, MANIFEST_FILE
        update_info = check_for_updates_fast()

        # Statistiques de mise a jour (si update disponible)
        update_stats = None
        if update_info.get('update_available'):
            update_stats, stats_err = get_update_statistics()
    except Exception as e:
        update_info = {
            'update_available': False,
            'current_version': 'Erreur',
            'latest_version': None,
            'error': str(e)
        }
        update_stats = None

    # Watchdog status
    watchdog_active = False
    try:
        from core import watchdog
        watchdog_active = watchdog._watchdog_status.get('started', False)
    except Exception:
        pass

    # Manifeste local
    manifest_info = None
    try:
        if MANIFEST_FILE.exists():
            m_data = json.loads(MANIFEST_FILE.read_text(encoding='utf-8'))
            manifest_info = {
                'files_count': len(m_data),
                'updated_at': datetime.fromtimestamp(
                    os.path.getmtime(str(MANIFEST_FILE))
                ).strftime('%d/%m/%Y %H:%M')
            }
    except Exception:
        pass

    # Sync check result (uniquement si difference de version)
    sync_info = None
    try:
        from core.updater import check_for_updates_fast, get_remote_version
        remote_ver, _ = get_remote_version()
        current_ver = update_info.get('current_version', '')
        # N'afficher le sync_check que si les versions different
        if remote_ver and remote_ver != current_ver:
            sync_script = PROJECT_ROOT / 'scripts' / 'sync_check.ps1'
            if sync_script.exists():
                result = subprocess.run(
                    ['powershell', '-ExecutionPolicy', 'Bypass', '-File', str(sync_script)],
                    capture_output=True, text=True, timeout=30, cwd=str(PROJECT_ROOT)
                )
                output = result.stdout.strip()
                sync_info = {'output': output[-500:] if output else '', 'local': current_ver, 'remote': remote_ver}
    except subprocess.TimeoutExpired:
        # Graceful handling du timeout - pas d'erreur 500
        flash('La vérification de synchronisation a mis trop de temps. Réessayez plus tard.', 'warning')
    except Exception as e:
        # Logger l'erreur silencieusement - pas de crash de la page
        import logging
        logging.getLogger('admin_tools').debug(f"Sync check failed: {e}")
        pass

    # Informations système
    sys_info = {
        'python_version': platform.python_version(),
        'os_version': platform.system() + ' ' + platform.release(),
        'hostname': platform.node(),
        'service_running': _is_service_running(),
        'server_pid': os.getpid(),
        'watchdog_active': watchdog_active,
    }

    # Fetch changelog depuis GitHub (dernières releases)
    releases = _fetch_github_releases()

    return render_template(
        'update.html',
        update_info=update_info,
        update_stats=update_stats,
        sys_info=sys_info,
        releases=releases,
        manifest_info=manifest_info,
        sync_info=sync_info,
        connected=True
    )


def _is_service_running():
    """Verifier si le service Windows tourne.
    Methode 1: sc query
    Methode 2 (fallback): verifier si le process python venv tourne.
    """
    import os
    import subprocess

    # Methode 1: sc query
    try:
        result = subprocess.run(
            ['sc', 'query', 'ADWebInterface'],
            capture_output=True, text=True, timeout=5
        )
        if 'RUNNING' in result.stdout:
            return True
    except Exception:
        pass

    # Methode 2: verifier si le process courant est le service
    try:
        import psutil
        my_pid = os.getpid()
        proc = psutil.Process(my_pid)
        if 'ADWebInterface' in proc.name() or 'python' in proc.name().lower():
            # Verifier si le parent est le service WinSW
            parent = proc.parent()
            if parent and 'ADWebInterface' in parent.name():
                return True
            # Sinon, on est dans un process python qui sert l'app → service actif
            return True
    except Exception:
        pass

    # Fallback: si on est ici, l'app repond → le service tourne
    return True


def _fetch_github_releases(limit=5):
    """
    Recuperer les dernieres releases GitHub avec cache 30 min.
    Un SEUL appel API (endpoint /releases inclut tag, notes et date).
    Avec GITHUB_TOKEN : 5000 req/h au lieu de 60.
    """
    import urllib.request
    import json as json_mod
    from datetime import datetime

    # Verifier le cache
    now = time.time()
    if _release_cache['data'] is not None and (now - _release_cache['time']) < _release_cache['ttl']:
        return _release_cache['data']

    releases = []
    try:
        # Un seul appel : /releases inclut tag_name, body (notes), published_at (date)
        url = f"https://api.github.com/repos/fred-selest/microsoft-active-directory/releases?per_page={limit}"
        req = urllib.request.Request(url, headers=_get_github_headers())
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json_mod.loads(r.read().decode('utf-8'))

        for rel in data:
            tag_name = rel.get('tag_name', '')
            version = tag_name.lstrip('v') if tag_name.startswith('v') else tag_name

            date_str = '—'
            pub_date = rel.get('published_at')
            if pub_date:
                try:
                    dt = datetime.strptime(pub_date, '%Y-%m-%dT%H:%M:%SZ')
                    date_str = dt.strftime('%d/%m/%Y')
                except Exception:
                    pass

            releases.append({
                'tag': tag_name,
                'version': version,
                'date': date_str,
                'notes': rel.get('body'),
            })

    except Exception:
        pass

    _release_cache['data'] = releases
    _release_cache['time'] = now
    return releases


@admin_tools_bp.route('/diagnostic')
@require_connection
@require_permission('admin:diagnostic')
def diagnostic_page():
    """Page de diagnostic et dépannage."""
    return render_template('diagnostic.html', connected=True)


@admin_tools_bp.route('/scripts')
@require_connection
@require_permission('system:execute_script')
def scripts_page():
    """Page de gestion des scripts PowerShell."""
    return render_template('scripts.html', connected=True)


@admin_tools_bp.route('/log-analysis')
@require_connection
@require_permission('admin:log_analysis')
def log_analysis_page():
    """Page d'analyse automatique des logs."""
    return render_template('log_analysis.html', connected=True)


@admin_tools_bp.route('/alerts')
@require_connection
def alerts_page():
    """Page des alertes enrichie."""
    from datetime import datetime
    from core.account_stats import (compute_account_alerts, ACCOUNT_WARNING_DAYS,
                                    INACTIVE_DAYS, PASSWORD_WARNING_DAYS)

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return render_template('alerts.html', alert_data={}, alerts=[], connected=True)

    alerts = []
    alert_data = {}
    try:
        alert_data = compute_account_alerts(conn, session.get('ad_base_dn', ''))
    except Exception as e:
        flash(f'Erreur lors de la récupération des alertes: {str(e)}', 'error')
    finally:
        conn.unbind()

    date = datetime.now().strftime('%d/%m/%Y %H:%M')

    def add(count, title, message, severity, threshold=0):
        if alert_data.get(count, 0) > threshold:
            alerts.append({'title': title.format(n=alert_data[count]), 'message': message,
                           'severity': severity, 'date': date})

    add('locked_accounts', '{n} compte(s) verrouillé(s)',
        'Des comptes sont actuellement verrouillés suite à des tentatives de connexion échouées.',
        'warning')
    add('password_expiring', '{n} mot(s) de passe expirant',
        f'Des mots de passe expirent dans moins de {PASSWORD_WARNING_DAYS} jours. '
        'Notifiez les utilisateurs.', 'warning')
    add('expiring_accounts', '{n} compte(s) expirant',
        f'Des comptes atteignent leur date d\'expiration dans moins de {ACCOUNT_WARNING_DAYS} jours.',
        'warning')
    add('privileged_accounts', '{n} compte(s) administrateur du domaine',
        'Comptes actifs membres (directs ou imbriqués) des Admins du domaine ou des '
        'Administrateurs de l\'entreprise. Limitez les accès administrateurs.',
        'critical', threshold=3)
    add('inactive_accounts', '{n} compte(s) inactif(s)',
        f'Ces comptes actifs n\'ont pas été utilisés depuis plus de {INACTIVE_DAYS} jours.',
        'info', threshold=10)
    add('disabled_accounts', '{n} compte(s) désactivé(s)',
        'Des comptes utilisateurs sont désactivés. Vérifiez s\'ils doivent être supprimés.',
        'info', threshold=5)
    add('empty_groups', '{n} groupe(s) vide(s)',
        'Certains groupes n\'ont aucun membre. Vérifiez leur pertinence.',
        'info', threshold=5)

    return render_template('alerts.html', alert_data=alert_data, alerts=alerts, connected=True)


@admin_tools_bp.route('/errors')
@require_connection
@require_permission('admin:log_analysis')
def error_logs():
    """Page des logs d'erreurs."""
    import os
    from pathlib import Path
    from .core import is_connected

    error_log_path = Path('logs/server.log')
    errors = []

    if error_log_path.exists():
        try:
            with open(error_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                errors = [line.strip() for line in lines if 'ERROR' in line or 'Exception' in line]
                errors = errors[-50:]
        except Exception as e:
            errors = [f'Erreur de lecture: {str(e)}']
    else:
        errors = ['Fichier de logs introuvable. Vérifiez que le service tourne.']

    return render_template('errors.html', errors=errors, connected=is_connected())


@admin_tools_bp.route('/security-audit')
@require_connection
@require_permission('admin:security_audit')
def security_audit():
    """Audit de sécurité."""
    from core.security_audit import check_security_issues

    conn, error = get_ad_connection()
    if not conn:
        from flask import flash
        flash(f'Erreur: {error}', 'error')
        return render_template('security_audit.html', issues=[], stats={'critical': 0, 'high': 0, 'warning': 0, 'fixable': 0}, connected=True)

    try:
        issues = check_security_issues(conn, session.get('ad_base_dn', ''))
        conn.unbind()

        # Calculer les statistiques
        stats = {
            'critical': len([i for i in issues if i.get('severity') == 'critical']),
            'high': len([i for i in issues if i.get('severity') == 'high']),
            'warning': len([i for i in issues if i.get('severity') == 'warning']),
            'fixable': len([i for i in issues if i.get('fixable', False)])
        }

        return render_template('security_audit.html', issues=issues, stats=stats, connected=True)
    except Exception as e:
        from flask import flash
        flash(f'Erreur: {str(e)}', 'error')
        return render_template('security_audit.html', issues=[], stats={'critical': 0, 'high': 0, 'warning': 0, 'fixable': 0}, connected=True)


@admin_tools_bp.route('/permissions')
@require_connection
@require_permission('admin:permissions')
def permissions_page():
    """Page de gestion des permissions."""
    from core.granular_permissions import get_all_groups_with_permissions, get_available_permissions, get_permission_categories

    groups = get_all_groups_with_permissions()
    all_permissions = get_available_permissions()
    categories = get_permission_categories()

    return render_template('permissions.html',
                         groups=groups,
                         permissions=all_permissions,
                         categories=categories,
                         connected=True)
