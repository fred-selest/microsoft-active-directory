# -*- coding: utf-8 -*-
"""
Journal du domaine : photos de l'état de l'annuaire, changements entre deux
photos, annulation. La logique est dans core/domain_history.py.

Une photo est prise :
- à la demande ;
- automatiquement à la première visite du jour d'un administrateur (avec
  ses identifiants de session) ;
- chaque nuit si un compte de lecture dédié est configuré (son mot de passe
  est chiffré comme ceux des sessions).
"""
import logging
import threading
import time
from datetime import datetime

from flask import (Blueprint, current_app, flash, jsonify, redirect, render_template, request,
                   session, url_for)

from ..core import (get_ad_connection, is_connected, require_connection,
                    require_permission)
from core import domain_history as dh
from core.audit import log_action

logger = logging.getLogger(__name__)

history_bp = Blueprint('history', __name__, url_prefix='/history')

_state = {'day': None, 'scheduler': False, 'last_error': None}


def _enabled():
    from core.features import is_feature_enabled
    return is_feature_enabled('history')


@history_bp.before_request
def _feature_gate():
    if not _enabled():
        return render_template('feature_disabled.html', feature_name='history',
                               connected=is_connected()), 503
    return None


def _settings():
    from core.settings_manager import load_settings
    raw = load_settings().get('history') or {}
    service = raw.get('service') or {}
    try:
        hour = max(0, min(int(raw.get('hour', 2)), 23))
    except (TypeError, ValueError):
        hour = 2
    return {'auto_daily': raw.get('auto_daily', True) is not False, 'notify': raw.get('notify', True) is not False,
            'hour': hour, 'service': service if service.get('username') and service.get('password_enc') else {}}


def _share_credentials(username, password, base_dn):
    if '\\' not in username and '@' not in username:
        domain = '.'.join(p.strip().split('=', 1)[1] for p in base_dn.split(',')
                          if p.strip().upper().startswith('DC='))
        username = f'{username}@{domain}' if domain else username
    return username, password


def run_snapshot(app, creds, by, notify=True):
    """Prend une photo hors requête HTTP (thread). creds : identifiants en clair."""
    try:
        return _run_snapshot(app, creds, by, notify)
    finally:
        _state['pending'] = False


def _run_snapshot(app, creds, by, notify):
    try:
        with app.test_request_context('/'):
            conn, error = get_ad_connection(creds['server'], creds['username'], creds['password'],
                                            creds.get('use_ssl', False), creds.get('port'))
            if not conn:
                raise dh.HistoryError(f'Connexion impossible : {error}')
            try:
                name, events = dh.take_snapshot(
                    conn, creds['base_dn'], by,
                    _share_credentials(creds['username'], creds['password'], creds['base_dn']))
            finally:
                conn.unbind()
            if notify:
                dh.notify(events, name)
        _state['last_error'] = None
        logger.info('Photo du domaine %s : %d changement(s)', name, len(events))
        return name
    except dh.HistoryError as e:
        _state['last_error'] = str(e)
        logger.warning('Photo du domaine impossible : %s', e)
    except Exception:
        _state['last_error'] = 'Erreur inattendue (voir le journal du serveur).'
        logger.exception('Photo du domaine interrompue')
    return None


def _session_creds():
    from core.session_crypto import decrypt_password
    return {'server': session.get('ad_server'), 'username': session.get('ad_username'),
            'password': decrypt_password(session.get('ad_password')),
            'use_ssl': session.get('ad_use_ssl', False), 'port': session.get('ad_port'),
            'base_dn': session.get('ad_base_dn', '')}


def _start(creds, by, notify):
    app = current_app._get_current_object()
    _state['pending'] = True        # visible tout de suite, avant que le thread ne prenne le verrou
    threading.Thread(target=run_snapshot, args=(app, creds, by, notify),
                     name='domain-snapshot', daemon=True).start()


def _today_done():
    today = datetime.now().strftime('%Y%m%d')
    return any(s['name'].startswith(today) for s in dh.list_snapshots()[:3])


def _scheduler(app):
    """Photo nocturne avec le compte de lecture configuré."""
    from core.session_crypto import decrypt_password
    while True:
        time.sleep(600)
        try:
            with app.app_context():
                cfg = _settings()
            service = cfg['service']
            if not service or datetime.now().hour < cfg['hour'] or _today_done():
                continue
            creds = dict(service, password=decrypt_password(service['password_enc']))
            run_snapshot(app, creds, 'planification', cfg['notify'])
        except Exception:
            logger.exception('Planification des photos')


@history_bp.before_app_request
def _daily():
    """Première visite du jour d'un administrateur : photo en arrière-plan."""
    app = current_app
    if app.config.get('TESTING') and not app.config.get('HISTORY_AUTO_IN_TESTS'):
        return None
    if not _state['scheduler']:
        _state['scheduler'] = True
        if not app.config.get('TESTING'):
            threading.Thread(target=_scheduler, args=(app._get_current_object(),),
                             name='domain-snapshot-scheduler', daemon=True).start()
    today = datetime.now().strftime('%Y%m%d')
    if _state['day'] == today or request.endpoint in (None, 'static') or not is_connected():
        return None
    if not _enabled() or not _settings()['auto_daily']:
        return None
    from core.granular_permissions import has_permission
    if not has_permission(session.get('user_groups', []), 'history:snapshot',
                          username=session.get('ad_username'), user_dn=session.get('user_dn')):
        return None
    _state['day'] = today
    if not _today_done():
        try:
            _start(_session_creds(), session.get('ad_username', ''), _settings()['notify'])
        except Exception:
            logger.exception('Photo quotidienne')
    return None


# --- Pages -------------------------------------------------------------------

@history_bp.route('/')
@require_connection
@require_permission('history:read')
def timeline():
    snapshots = dh.list_snapshots()
    names = [s['name'] for s in snapshots]
    new_name = request.args.get('b') if request.args.get('b') in names else (names[0] if names else None)
    old_name = request.args.get('a') if request.args.get('a') in names else None
    if new_name and not old_name:
        index = names.index(new_name)
        old_name = names[index + 1] if index + 1 < len(names) else None
    events, error = [], None
    if old_name and new_name:
        if old_name > new_name:
            old_name, new_name = new_name, old_name
        try:
            events = dh.diff(dh.load(old_name), dh.load(new_name))
        except dh.HistoryError as e:
            error = str(e)
    counts = {sev: sum(1 for e in events if e['severity'] == sev) for sev in ('critical', 'warning', 'info')}
    by_name = {s['name']: s for s in snapshots}
    return render_template('history.html', snapshots=snapshots, events=events, counts=counts, error=error,
                           old=by_name.get(old_name), new=by_name.get(new_name), sections=dh.SECTIONS,
                           revert_labels=dh.REVERT_LABELS, direct=dh.DIRECT_REVERTS,
                           running=dh._LOCK.locked() or _state.get('pending', False),
                           latest=snapshots[0] if snapshots else None, last_error=_state['last_error'],
                           cfg=_settings(), connected=is_connected())


@history_bp.route('/api/status')
@require_connection
@require_permission('history:read')
def api_status():
    """Photo en cours ? Nom de la dernière photo (la page se recharge quand il change)."""
    snapshots = dh.list_snapshots()
    return jsonify({'running': dh._LOCK.locked() or _state.get('pending', False),
                    'latest': snapshots[0]['name'] if snapshots else None,
                    'error': _state['last_error']})


@history_bp.route('/snapshot', methods=['POST'])
@require_connection
@require_permission('history:snapshot')
def snapshot():
    if dh._LOCK.locked() or _state.get('pending'):
        flash('Une photo est déjà en cours.', 'warning')
    else:
        _start(_session_creds(), session.get('ad_username', ''), False)
        log_action('domain_snapshot', session.get('ad_username'), {}, True, request.remote_addr)
        flash('Photo du domaine lancée : la page affichera ses changements dès qu\'elle sera terminée.', 'success')
    return redirect(url_for('history.timeline'))


@history_bp.route('/revert', methods=['POST'])
@require_connection
@require_permission('history:revert')
def revert():
    old_name, new_name, event_id = (request.form.get(k, '') for k in ('a', 'b', 'event'))
    back = redirect(url_for('history.timeline', a=old_name, b=new_name))
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur : {error}', 'error')
        return back
    try:
        event = dh.revert(conn, session.get('ad_base_dn', ''), old_name, new_name, event_id)
        log_action('domain_revert', session.get('ad_username'),
                   {'event': event['title'], 'detail': event['detail'], 'op': event['revert']['op']},
                   True, request.remote_addr)
        flash(f'Annulé : {event["title"]}. La prochaine photo le confirmera.', 'success')
    except dh.HistoryError as e:
        log_action('domain_revert', session.get('ad_username'), {'event': event_id, 'error': str(e)},
                   False, request.remote_addr)
        flash(str(e), 'error')
    finally:
        conn.unbind()
    return back


@history_bp.route('/settings', methods=['POST'])
@require_connection
@require_permission('admin:settings')
def settings():
    from core.session_crypto import encrypt_password
    from core.settings_manager import set_setting
    current = _settings()
    try:
        hour = max(0, min(int(request.form.get('hour', 2)), 23))
    except (TypeError, ValueError):
        hour = 2
    service = current['service']
    username = request.form.get('service_username', '').strip()
    password = request.form.get('service_password', '')
    if request.form.get('remove_service') == 'on' or not username:
        service = {}
    elif password or username != service.get('username'):
        if not password:
            flash('Indiquez le mot de passe du compte de lecture.', 'error')
            return redirect(url_for('history.timeline') + '#reglages')
        creds = {'server': session.get('ad_server'), 'username': username, 'password': password,
                 'use_ssl': session.get('ad_use_ssl', False), 'port': session.get('ad_port'),
                 'base_dn': session.get('ad_base_dn', '')}
        conn, error = get_ad_connection(creds['server'], username, password, creds['use_ssl'], creds['port'])
        if not conn:
            flash(f'Compte de lecture refusé par l\'annuaire : {error}', 'error')
            return redirect(url_for('history.timeline') + '#reglages')
        conn.unbind()
        service = {k: v for k, v in creds.items() if k != 'password'}
        service['password_enc'] = encrypt_password(password)
    set_setting('history', {'auto_daily': request.form.get('auto_daily') == 'on',
                            'notify': request.form.get('notify') == 'on', 'hour': hour, 'service': service})
    log_action('domain_history_settings', session.get('ad_username'),
               {'service': service.get('username', '')}, True, request.remote_addr)
    flash('Réglages du journal enregistrés.', 'success')
    return redirect(url_for('history.timeline') + '#reglages')
