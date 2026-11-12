# -*- coding: utf-8 -*-
"""
Microsoft 365 rapproché de l'annuaire : licences, synchronisation, comptes
présents d'un seul côté, taille des boîtes. Lecture seule ; la logique est
dans core/m365.py.
"""
from flask import Blueprint, jsonify, render_template, request, session

from ..core import (get_ad_connection, is_connected, require_connection,
                    require_permission)
from core import m365

m365_bp = Blueprint('m365', __name__, url_prefix='/m365')


@m365_bp.before_request
def _feature_gate():
    from core.features import is_feature_enabled
    if not is_feature_enabled('m365'):
        return render_template('feature_disabled.html', feature_name='m365',
                               connected=is_connected()), 503
    return None


def _fail(error, status=400):
    return jsonify({'success': False, 'error': str(error)}), status


@m365_bp.route('/')
@require_connection
@require_permission('m365:read')
def index():
    from core import exchange as ex
    return render_template('m365.html', status=m365.status(), cfg=ex.get_config(), connected=is_connected())


@m365_bp.route('/api/overview')
@require_connection
@require_permission('m365:read')
def api_overview():
    """Licences, synchronisation et écarts entre l'AD et Microsoft 365."""
    try:
        data = m365.fetch(refresh=request.args.get('refresh') == '1')
    except m365.M365Error as e:
        return _fail(e)
    conn, error = get_ad_connection()
    if not conn:
        return _fail(error, 502)
    try:
        ad_users = m365.read_ad_users(conn, session.get('ad_base_dn', ''))
    finally:
        conn.unbind()
    return jsonify({'success': True, **m365.compare(data, ad_users)})


@m365_bp.route('/api/user')
@require_connection
@require_permission('m365:read')
def api_user():
    """Ce que Microsoft 365 sait d'un compte (affiché sur sa fiche)."""
    try:
        data = m365.fetch()
    except m365.M365Error as e:
        return _fail(e)
    return jsonify({'success': True, 'user': m365.user_status(data, request.args.get('upn', ''),
                                                              request.args.get('anchor', ''))})


def _stats_json(state):
    return jsonify({'success': True, 'status': state['status'], 'error': state['error'],
                    'at': state['at'], 'mailboxes': state['data']})


@m365_bp.route('/api/mailboxes')
@require_connection
@require_permission('m365:read')
def api_mailboxes():
    """État du relevé de taille des boîtes (sans le lancer)."""
    return _stats_json(m365.mailbox_stats())


@m365_bp.route('/api/mailboxes/start', methods=['POST'])
@require_connection
@require_permission('m365:read')
def api_mailboxes_start():
    """Lance le relevé (long : une requête par boîte) en arrière-plan."""
    if m365.status() == 'none':
        return _fail('La liaison Microsoft 365 n\'est pas configurée.')
    data = request.get_json(silent=True) or {}
    return _stats_json(m365.mailbox_stats(start=True, refresh=bool(data.get('refresh'))))
