# -*- coding: utf-8 -*-
"""
Stratégies de groupe : liste, rattachements (OU, groupes, utilisateurs),
stratégies reçues par un objet, gestion des liens, sauvegarde et
restauration. La logique est dans core/gpo.py.
"""
from flask import (Blueprint, flash, jsonify, redirect, render_template, request,
                   session, url_for)

from ..core import (get_ad_connection, is_connected, require_connection,
                    require_permission)
from core import gpo as gp
from core.audit import log_action

import logging
logger = logging.getLogger(__name__)

gpo_bp = Blueprint('gpo', __name__, url_prefix='/gpo')


@gpo_bp.before_request
def _feature_gate():
    from core.features import is_feature_enabled
    if not is_feature_enabled('gpo'):
        return render_template('feature_disabled.html', feature_name='gpo',
                               connected=is_connected()), 503
    return None


def _audit(action, details, ok=True):
    log_action(action, session.get('ad_username'), details, ok, request.remote_addr)


def _base():
    return session.get('ad_base_dn', '')


def _ous(conn):
    from routes.core import paged_search
    base = _base()
    ous = [{'dn': e.entry_dn, 'name': e.entry_dn} for e in
           paged_search(conn, base, '(objectClass=organizationalUnit)', attributes=['name'])]
    ous.sort(key=lambda o: o['dn'].lower())
    return [{'dn': base, 'name': f'{base} (tout le domaine)'}] + ous


@gpo_bp.route('/')
@require_connection
@require_permission('gpo:read')
def list_gpos():
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur : {error}', 'error')
        return redirect(url_for('main.dashboard'))
    try:
        data = gp.load_all(conn, _base())
    except Exception as e:
        flash(f'Lecture des stratégies impossible : {e}', 'error')
        data = {'gpos': [], 'containers': [], 'orphan_links': []}
    finally:
        conn.unbind()
    stats = {'total': len(data['gpos']),
             'unlinked': sum(1 for g in data['gpos'] if not g['links']),
             'disabled': sum(1 for g in data['gpos'] if g['flags'] == 3),
             'issues': sum(1 for g in data['gpos'] if g['issues']) + len(data['orphan_links'])}
    return render_template('gpo_list.html', data=data, stats=stats, backups=gp.list_backups(),
                           connected=is_connected())


@gpo_bp.route('/view/<guid>')
@require_connection
@require_permission('gpo:read')
def view_gpo(guid):
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur : {error}', 'error')
        return redirect(url_for('gpo.list_gpos'))
    try:
        data = gp.load_all(conn, _base())
        gpo = data['by_guid'].get(gp.norm_guid(guid))
        if not gpo:
            flash('Stratégie introuvable.', 'error')
            return redirect(url_for('gpo.list_gpos'))
        ous = _ous(conn)
    except gp.GpoError as e:
        flash(str(e), 'error')
        return redirect(url_for('gpo.list_gpos'))
    finally:
        conn.unbind()
    backups = [b for b in gp.list_backups() if any(g['guid'] == gpo['guid'] for g in b['gpos'])]
    return render_template('gpo_detail.html', gpo=gpo, ous=ous, statuses=gp.GPO_STATUS,
                           backups=backups, connected=is_connected())


@gpo_bp.route('/api/scope/<guid>')
@require_connection
@require_permission('gpo:read')
def api_scope(guid):
    """Utilisateurs et ordinateurs qui reçoivent la stratégie."""
    conn, error = get_ad_connection()
    if not conn:
        return jsonify({'success': False, 'error': error}), 502
    try:
        data = gp.load_all(conn, _base())
        gpo = data['by_guid'].get(gp.norm_guid(guid))
        if not gpo:
            return jsonify({'success': False, 'error': 'Stratégie introuvable.'}), 404
        return jsonify({'success': True, **gp.gpo_scope(conn, _base(), gpo, data)})
    except gp.GpoError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    finally:
        conn.unbind()


@gpo_bp.route('/applied')
@require_connection
@require_permission('gpo:read')
def applied():
    """Stratégies reçues par un utilisateur, un ordinateur ou une OU."""
    from core import folders as fs
    dn = request.args.get('dn', '').strip()
    name = request.args.get('name', '').strip()
    result, error, ous = None, None, []
    conn, err = get_ad_connection()
    if not conn:
        flash(f'Erreur : {err}', 'error')
        return redirect(url_for('gpo.list_gpos'))
    try:
        ous = _ous(conn)
        if name and not dn:
            dn = _find_object(conn, name)
        if dn:
            result = gp.applied_gpos(conn, _base(), dn)
    except (gp.GpoError, fs.FolderError) as e:
        error = str(e)
    except Exception as e:                       # annuaire injoignable, réponse inattendue : pas de page d'erreur 500
        logger.exception('Calcul des stratégies reçues impossible')
        error = f'Lecture des stratégies impossible : {e}'
    finally:
        conn.unbind()
    return render_template('gpo_applied.html', result=result, error=error, dn=dn, name=name, ous=ous,
                           connected=is_connected())


def _find_object(conn, name):
    """DN d'un utilisateur ou d'un ordinateur par son identifiant."""
    from ldap3 import SUBTREE
    from core.security import escape_ldap_filter
    name = name.split('\\')[-1].strip()
    safe = escape_ldap_filter(name)
    conn.search(_base(), f'(&(|(objectClass=user)(objectClass=computer))'
                         f'(|(sAMAccountName={safe})(sAMAccountName={safe}$)))', SUBTREE,
                attributes=['cn'], size_limit=3)
    if len(conn.entries) != 1:
        raise gp.GpoError(f'Utilisateur ou ordinateur introuvable : {name}')
    return conn.entries[0].entry_dn


def _write(action_name, func, back):
    """Exécute une écriture LDAP avec audit et message."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur : {error}', 'error')
        return back
    try:
        message, details = func(conn)
        _audit(action_name, details)
        flash(message, 'success')
    except gp.GpoError as e:
        _audit(action_name, {'error': str(e), **{k: v for k, v in request.form.items()
                                                 if k in ('guid', 'target', 'action')}}, False)
        flash(str(e), 'error')
    finally:
        conn.unbind()
    return back


_LINK_MESSAGES = {'add': 'Stratégie liée', 'remove': 'Lien supprimé', 'enable': 'Lien activé',
                  'disable': 'Lien désactivé', 'enforce': 'Lien marqué « appliqué »',
                  'unenforce': 'Lien non forcé', 'up': 'Priorité augmentée', 'down': 'Priorité diminuée'}


def _back():
    guid = request.form.get('guid', '')
    if request.form.get('back') == 'list' or not guid:
        return redirect(url_for('gpo.list_gpos') + '#ou')
    return redirect(url_for('gpo.view_gpo', guid=guid))


@gpo_bp.route('/link', methods=['POST'])
@require_connection
@require_permission('gpo:manage')
def link():
    guid, target, action = (request.form.get(k, '').strip() for k in ('guid', 'target', 'action'))

    def run(conn):
        dn = gp.change_link(conn, _base(), guid, target, action)
        return f'{_LINK_MESSAGES.get(action, "Lien modifié")} sur {dn}.', \
            {'guid': guid, 'target': dn, 'action': action}
    return _write('gpo_link', run, _back())


@gpo_bp.route('/status', methods=['POST'])
@require_connection
@require_permission('gpo:manage')
def status():
    guid, flags = request.form.get('guid', ''), request.form.get('flags', '')

    def run(conn):
        name = gp.set_status(conn, _base(), guid, flags)
        return f'{name} : {gp.GPO_STATUS[int(flags)].lower()}.', {'guid': guid, 'flags': flags}
    return _write('gpo_status', run, _back())


@gpo_bp.route('/inheritance', methods=['POST'])
@require_connection
@require_permission('gpo:manage')
def inheritance():
    target, block = request.form.get('target', ''), request.form.get('block') == '1'

    def run(conn):
        dn = gp.set_block_inheritance(conn, _base(), target, block)
        return f'Héritage {"bloqué" if block else "rétabli"} sur {dn}.', {'target': dn, 'block': block}
    return _write('gpo_inheritance', run, redirect(url_for('gpo.list_gpos') + '#ou'))


@gpo_bp.route('/backup', methods=['POST'])
@require_connection
@require_permission('gpo:backup')
def backup():
    try:
        result = gp.backup_all(_base(), session.get('ad_username', ''))
        _audit('gpo_backup', result)
        flash(f'{result["count"]} stratégie(s) sauvegardée(s) ({result["name"]}).', 'success')
    except gp.GpoError as e:
        _audit('gpo_backup', {'error': str(e)}, False)
        flash(f'Sauvegarde impossible : {e}', 'error')
    return redirect(url_for('gpo.list_gpos') + '#sauvegardes')


@gpo_bp.route('/restore', methods=['POST'])
@require_connection
@require_permission('gpo:backup')
def restore():
    guid, name = request.form.get('guid', ''), request.form.get('backup', '')
    try:
        gpo_name = gp.restore(_base(), name, guid)
        _audit('gpo_restore', {'guid': guid, 'backup': name})
        flash(f'{gpo_name} restaurée depuis la sauvegarde {name}.', 'success')
    except gp.GpoError as e:
        _audit('gpo_restore', {'guid': guid, 'backup': name, 'error': str(e)}, False)
        flash(f'Restauration impossible : {e}', 'error')
    return _back()
