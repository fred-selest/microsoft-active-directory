# -*- coding: utf-8 -*-
"""
Boîtes aux lettres partagées Exchange Online : liste, accès, création.
La logique est dans core/exchange.py.
"""
from flask import Blueprint, jsonify, render_template, request, session

from ..core import (get_ad_connection, is_connected, require_connection,
                    require_permission)
from core import exchange as ex
from core.audit import log_action

mailboxes_bp = Blueprint('mailboxes', __name__, url_prefix='/mailboxes')


@mailboxes_bp.before_request
def _feature_gate():
    from core.features import is_feature_enabled
    if not is_feature_enabled('m365'):
        return render_template('feature_disabled.html', feature_name='m365',
                               connected=is_connected()), 503
    return None


def _audit(action, details, ok=True):
    log_action(action, session.get('ad_username'), details, ok, request.remote_addr)


def _fail(error, status=400):
    return jsonify({'success': False, 'error': str(error)}), status


@mailboxes_bp.route('/')
@require_connection
@require_permission('m365:mailboxes_read')
def index():
    return render_template('mailboxes.html', cfg=ex.get_config(), connected=is_connected())


@mailboxes_bp.route('/api/list')
@require_connection
@require_permission('m365:mailboxes_read')
def api_list():
    try:
        return jsonify({'success': True, **ex.list_mailboxes(refresh=request.args.get('refresh') == '1')})
    except ex.ExchangeError as e:
        return _fail(e)


@mailboxes_bp.route('/api/members')
@require_connection
@require_permission('m365:mailboxes_read')
def api_members():
    try:
        return jsonify({'success': True, 'members': ex.members(request.args.get('mailbox', ''))})
    except ex.ExchangeError as e:
        return _fail(e)


def _change(action, func):
    data = request.get_json(silent=True) or {}
    mailbox, who = data.get('mailbox', ''), data.get('user', '')
    full, send = data.get('full_access', True), data.get('send_as', True)
    conn = None
    try:
        user = who
        if action == 'mailbox_grant':
            # Ajout : le compte est choisi dans l'annuaire, on en déduit son adresse M365.
            conn, error = get_ad_connection()
            if not conn:
                return _fail(error, 502)
            user = ex.user_address(conn, session.get('ad_base_dn', ''), who)
        mailbox, user = func(mailbox, user, bool(full), bool(send))
        _audit(action, {'mailbox': mailbox, 'user': user, 'full_access': bool(full), 'send_as': bool(send)})
        return jsonify({'success': True, 'members': ex.members(mailbox), 'user': user})
    except ex.ExchangeError as e:
        _audit(action, {'mailbox': mailbox, 'user': who, 'error': str(e)}, False)
        return _fail(e)
    finally:
        if conn:
            conn.unbind()


@mailboxes_bp.route('/api/grant', methods=['POST'])
@require_connection
@require_permission('m365:mailboxes_manage')
def api_grant():
    return _change('mailbox_grant', ex.grant)


@mailboxes_bp.route('/api/revoke', methods=['POST'])
@require_connection
@require_permission('m365:mailboxes_manage')
def api_revoke():
    return _change('mailbox_revoke', ex.revoke)


@mailboxes_bp.route('/api/create', methods=['POST'])
@require_connection
@require_permission('m365:mailboxes_create')
def api_create():
    data = request.get_json(silent=True) or {}
    try:
        address = ex.create(data.get('name', ''), data.get('alias', ''), data.get('domain', ''))
        _audit('mailbox_create', {'address': address, 'name': data.get('name', '')})
        return jsonify({'success': True, 'address': address})
    except ex.ExchangeError as e:
        _audit('mailbox_create', {'alias': data.get('alias', ''), 'error': str(e)}, False)
        return _fail(e)
