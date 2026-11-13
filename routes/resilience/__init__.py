# -*- coding: utf-8 -*-
"""
Résistance au rançongiciel : chemins vers les droits d'administration,
partages ouverts à tous, sauvegardes. Lecture seule ; la logique est dans
core/resilience.py.
"""
import logging
import time

from flask import Blueprint, jsonify, render_template, request, session

from ..core import (get_ad_connection, is_connected, require_connection,
                    require_permission)
from core import folders as fs
from core import resilience as rs
from core.audit import log_action

logger = logging.getLogger(__name__)

resilience_bp = Blueprint('resilience', __name__, url_prefix='/resilience')


def _fail(error, status=400):
    return jsonify({'success': False, 'error': str(error)}), status


@resilience_bp.route('/')
@require_connection
@require_permission('tools:resilience')
def index():
    return render_template('resilience.html', shares=fs.get_folder_settings()['roots'], connected=is_connected())


@resilience_bp.route('/api/directory')
@require_connection
@require_permission('tools:resilience')
def api_directory():
    """Constats tirés de l'annuaire (quelques secondes)."""
    conn, error = get_ad_connection()
    if not conn:
        return _fail(error, 502)
    try:
        result = rs.analyse_directory(rs.read_directory(conn, session.get('ad_base_dn', '')))
    except Exception as e:                       # annuaire injoignable : message lisible plutôt qu'une erreur 500
        logger.exception('Analyse de l\'annuaire impossible')
        return _fail(f'Analyse de l\'annuaire impossible : {e}', 502)
    finally:
        conn.unbind()
    return jsonify({'success': True, **result})


@resilience_bp.route('/api/scan', methods=['POST'])
@require_connection
@require_permission('tools:resilience')
def api_scan():
    """Lance en arrière-plan la lecture des partages et de l'état des sauvegardes."""
    data = request.get_json(silent=True) or {}
    credentials = fs._credentials()
    owner = session.get('ad_username')
    try:
        job_id = fs.start_job(owner, ('resilience',), lambda: rs.scan_server(credentials),
                              refresh=bool(data.get('refresh')))
    except fs.FolderError as e:
        return _fail(e, 429)
    log_action('resilience_scan', owner, {}, True, request.remote_addr)
    return jsonify({'success': True, 'job': job_id}), 202


@resilience_bp.route('/api/scan/<job_id>')
@require_connection
@require_permission('tools:resilience')
def api_scan_status(job_id):
    job = fs.get_scan_job(job_id, session.get('ad_username'))
    if not job:
        return _fail('Analyse introuvable ou expirée.', 404)
    if job['status'] == 'running':
        return jsonify({'success': True, 'status': 'running', 'elapsed': int(time.time() - job['created'])})
    if job['status'] == 'error':
        return _fail(job['error'], 500)
    return jsonify({'success': True, 'status': 'done', **job['result']})
