# -*- coding: utf-8 -*-
"""
Plusieurs domaines : changement de domaine actif, déconnexion d'un domaine,
page « Domaines » (forêt, approbations, contrôleurs, vue consolidée des
domaines connectés). La logique est dans core/domains.py et core/forest.py.
"""
import logging

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

from ..core import (get_ad_connection, is_connected, require_connection,
                    require_permission)
from core import domains as dom
from core import forest as fo
from core.audit import log_action

logger = logging.getLogger(__name__)

domains_bp = Blueprint('domains', __name__, url_prefix='/domains')


def _safe_next(target):
    """
    Page où revenir après un changement de domaine : une page de ce site qui
    ne désigne pas un objet précis (un DN de l'ancien domaine n'existe pas dans
    le nouveau). Sinon le tableau de bord.
    """
    target = str(target or '')
    if not target.startswith('/') or target.startswith('//') or '\\' in target:
        return url_for('main.dashboard')
    path = target.split('?', 1)[0]
    if '=' in path or '%3D' in path.upper() or path.startswith(('/connect', '/disconnect')) or \
            (path.startswith('/domains/') and path != '/domains/'):
        return url_for('main.dashboard')
    return target


@domains_bp.route('/switch', methods=['POST'])
@require_connection
def switch():
    data = request.get_json(silent=True) if request.is_json else request.form
    key = (data or {}).get('key', '')
    target = _safe_next((data or {}).get('next') or (request.referrer or '').split(request.host, 1)[-1])
    try:
        key = dom.activate(key)
    except dom.DomainError as e:
        if request.is_json:
            return jsonify({'success': False, 'error': str(e)}), 400
        flash(str(e), 'error')
        return redirect(url_for('main.dashboard'))
    log_action('domain_switch', session.get('ad_username'), {'domain': key}, True, request.remote_addr)
    if request.is_json:
        return jsonify({'success': True, 'domain': key, 'next': target})
    flash(f'Domaine actif : {key} (connecté en tant que {session.get("ad_username")}).', 'info')
    return redirect(target)


@domains_bp.route('/<key>/disconnect', methods=['POST'])
@require_connection
def disconnect(key):
    try:
        dom.forget(key)
    except dom.DomainError as e:
        flash(str(e), 'error')
        return redirect(url_for('domains.index'))
    log_action('domain_disconnect', session.get('ad_username'), {'domain': key}, True, request.remote_addr)
    if not is_connected():
        return redirect(url_for('main.disconnect'))
    flash(f'Domaine {key} déconnecté. Domaine actif : {dom.active_key()}.', 'info')
    return redirect(url_for('domains.index'))


@domains_bp.route('/')
@require_connection
@require_permission('domains:read')
def index():
    connected = dom.connected()
    keys = {d['key'] for d in connected}
    known = [d for d in dom.known() if d['key'] not in keys]
    return render_template('domains.html', domain_rows=connected, known=known, connected=True)


@domains_bp.route('/known/<key>/forget', methods=['POST'])
@require_connection
@require_permission('domains:read')
def forget_known(key):
    dom.forget_known(key.lower())
    flash(f'{key} retiré des domaines mémorisés.', 'info')
    return redirect(url_for('domains.index'))


@domains_bp.route('/api/forest')
@require_connection
@require_permission('domains:read')
def api_forest():
    conn, error = get_ad_connection()
    if not conn:
        return jsonify({'success': False, 'error': error}), 502
    try:
        data = fo.read(conn, session.get('ad_base_dn', ''))
    except Exception as e:
        logger.exception('Lecture de la forêt impossible')
        return jsonify({'success': False, 'error': f'Lecture de la forêt impossible : {e}'}), 502
    finally:
        conn.unbind()
    keys = {d['key'] for d in dom.connected()}
    for d in data['domains']:
        d['connected'] = d['dns'] in keys
        d['connect_url'] = url_for('main.connect', add=1, server=d['dns'], domain=d['netbios'], base_dn=d['base_dn'])
    for t in data['trusts']:
        partner = t['partner'].lower()
        t['connected'] = partner in keys
        t['connect_url'] = url_for('main.connect', add=1, server=partner, domain=t['netbios'],
                                   base_dn=dom.base_dn_of(partner))
    return jsonify({'success': True, **data, 'findings': fo.findings(data)})


@domains_bp.route('/api/summary')
@require_connection
@require_permission('domains:read')
def api_summary():
    """Chiffres clés de chaque domaine connecté (en parallèle)."""
    results = dom.for_each(lambda conn, base_dn, key: fo.summary(conn, base_dn))
    rows = []
    for d in dom.connected():
        r = results.get(d['key'], {})
        rows.append({'key': d['key'], 'username': d['username'], 'active': d['active'], 'ok': r.get('ok', False),
                     'error': r.get('error', ''), **(r.get('result') or {})})
    return jsonify({'success': True, 'domains': rows})
