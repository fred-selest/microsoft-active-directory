# -*- coding: utf-8 -*-
"""
Répertoires partagés : droits NTFS, accès d'un compte, dossiers
partagés AGDLP et dossiers personnels.

Le travail sur les fichiers est fait par core/folders.py, sous l'identité de
l'administrateur connecté.
"""
import logging
import time

from flask import (Blueprint, flash, jsonify, redirect, render_template, request,
                   session, url_for)

from ..core import (get_ad_connection, is_connected, require_connection,
                    require_permission)
from core import folders as fs
from core.audit import log_action

logger = logging.getLogger(__name__)

folders_bp = Blueprint('folders', __name__, url_prefix='/folders')


@folders_bp.before_request
def _feature_gate():
    from core.features import is_feature_enabled
    if not is_feature_enabled('folders'):
        return render_template('feature_disabled.html', feature_name='folders',
                               connected=is_connected()), 503
    return None


def _audit(action, details, ok=True):
    log_action(action, session.get('ad_username'), details, ok, request.remote_addr)


def _back(path=None):
    return redirect(url_for('folders.browse', path=path) if path else url_for('folders.browse'))


def _can(permission):
    """Même règle que require_permission, pour adapter une page."""
    from config import get_config
    from core.granular_permissions import has_permission
    if not get_config().RBAC_ENABLED:
        return True
    return has_permission(session.get('user_groups', []), permission,
                          username=session.get('ad_username'), user_dn=session.get('user_dn'))


def _breadcrumb(path, roots):
    """Segments cliquables depuis la racine autorisée qui contient path."""
    root = max((r for r in roots if fs.is_under(path, r)), key=len, default=None)
    if not root:
        return []
    crumbs = [{'name': root, 'path': root}]
    current = root
    for part in path[len(root):].strip('\\').split('\\'):
        if part:
            current = current + '\\' + part
            crumbs.append({'name': part, 'path': current})
    return crumbs


def _ous(conn, base_dn):
    from ldap3 import SUBTREE
    try:
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['name'])
        ous = [{'name': str(e.name.value or ''), 'dn': e.entry_dn} for e in conn.entries]
    except Exception:
        ous = []
    ous.sort(key=lambda o: o['dn'].lower())
    return ous


@folders_bp.route('/')
@require_connection
@require_permission('tools:folders_read')
def browse():
    """Navigation dans les racines autorisées et droits du dossier courant."""
    settings = fs.get_folder_settings()
    path = request.args.get('path', '').strip()
    folder, error = None, None
    if not path and len(settings['roots']) == 1:
        path = settings['roots'][0]
    if path:
        try:
            folder = fs.get_folder(path)
        except fs.FolderError as e:
            error = str(e)

    ous = []
    # Liste des OU : seulement pour le formulaire de création, affiché aux
    # comptes qui ont le droit de créer.
    if folder and _can('tools:folders_create'):
        conn, _ = get_ad_connection()
        if conn:
            ous = _ous(conn, session.get('ad_base_dn', ''))
            conn.unbind()

    return render_template('folders.html', settings=settings, folder=folder, error=error,
                           path=path, levels=fs.LEVELS, applies=fs.APPLIES,
                           breadcrumb=_breadcrumb(folder['path'], settings['roots']) if folder else [],
                           ous=ous, connected=is_connected())


@folders_bp.route('/grant', methods=['POST'])
@require_connection
@require_permission('tools:folders_manage')
def grant():
    path = request.form.get('path', '')
    principal = request.form.get('principal', '')
    level = request.form.get('level', 'read')
    applies = request.form.get('applies', 'all')
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur : {error}', 'error')
        return _back(path)
    try:
        sid, name = fs.find_principal_sid(conn, session.get('ad_base_dn', ''), principal)
        path = fs.grant(path, sid, level, applies)
        _audit('folder_grant', {'path': path, 'principal': name, 'level': level, 'applies': applies})
        flash(f'Droit « {fs.LEVELS[level]["label"]} » accordé à {name}.', 'success')
    except fs.FolderError as e:
        _audit('folder_grant', {'path': path, 'principal': principal, 'error': str(e)}, False)
        flash(str(e), 'error')
    finally:
        conn.unbind()
    return _back(path)


@folders_bp.route('/revoke', methods=['POST'])
@require_connection
@require_permission('tools:folders_manage')
def revoke():
    path = request.form.get('path', '')
    sid = request.form.get('sid', '')
    name = request.form.get('name', sid)
    try:
        path = fs.revoke(path, sid)
        _audit('folder_revoke', {'path': path, 'principal': name, 'sid': sid})
        flash(f'Droits explicites de {name} retirés.', 'success')
    except fs.FolderError as e:
        _audit('folder_revoke', {'path': path, 'sid': sid, 'error': str(e)}, False)
        flash(str(e), 'error')
    return _back(path)


def _members(conn, base_dn, text):
    """DN des comptes listés (identifiants séparés par virgule ou point-virgule)."""
    dns = []
    for name in text.replace(';', ',').replace('\n', ',').split(','):
        if name.strip():
            dns.append(fs.find_principal(conn, base_dn, name)[0])
    return dns


@folders_bp.route('/create', methods=['POST'])
@require_connection
@require_permission('tools:folders_create')
def create_shared():
    """
    Dossier partagé selon AGDLP : groupes DL_<nom>_L / DL_<nom>_M portant
    les droits NTFS, et en option GG_<nom>_L / GG_<nom>_M (membres des DL)
    qui reçoivent les comptes.
    """
    parent = request.form.get('parent', '')
    name = request.form.get('name', '').strip()
    group_base = request.form.get('group_base', '').strip()
    ou_dn = request.form.get('ou', '').strip()
    with_global = request.form.get('with_global') == 'on'
    protect = request.form.get('protect') == 'on'
    reuse = request.form.get('reuse_groups') == 'on'
    base_dn = session.get('ad_base_dn', '')

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur : {error}', 'error')
        return _back(parent)
    created = []          # [(nom, dn)] créés par cette requête
    try:
        fs.check_allowed(parent)
        folder_name = fs.validate_folder_name(name)
        if not ou_dn or not ou_dn.lower().endswith(base_dn.lower()):
            raise fs.FolderError('Choisissez l\'unité d\'organisation des groupes.')
        members = {'read': _members(conn, base_dn, request.form.get('members_read', '')),
                   'modify': _members(conn, base_dn, request.form.get('members_modify', ''))}
        target = parent.rstrip('\\') + '\\' + folder_name

        # 1. Groupes (il faut leurs SID pour poser les droits). Un groupe
        #    existant n'est repris que sur demande explicite : deux dossiers
        #    « Compta » dans des parents différents partageraient sinon leurs
        #    groupes d'accès, et donc leurs membres.
        grants, nesting = [], []
        for level, names in fs.access_group_names(group_base or folder_name, with_global).items():
            label = fs.LEVELS[level]['label']
            dl_dn, dl_sid, new = fs.ensure_group(conn, base_dn, ou_dn, names['dl'],
                                                 fs.GROUP_DOMAIN_LOCAL_SECURITY,
                                                 f'{label} sur {target}', reuse=reuse)
            if new:
                created.append((names['dl'], dl_dn))
            grants.append((dl_sid, level))
            member_group = dl_dn
            if 'gg' in names:
                gg_dn, _, new = fs.ensure_group(conn, base_dn, ou_dn, names['gg'],
                                                fs.GROUP_GLOBAL_SECURITY,
                                                f'Comptes ayant {label.lower()} sur {target}',
                                                reuse=reuse)
                if new:
                    created.append((names['gg'], gg_dn))
                nesting.append((dl_dn, gg_dn))
                member_group = gg_dn
            nesting += [(member_group, m) for m in members[level]]

        # 2. Dossier. En cas d'échec, les groupes créés ci-dessus sont
        #    supprimés et aucune appartenance n'a encore été modifiée.
        try:
            result = fs.create_folder(parent, folder_name, grants, protect=protect)
        except fs.FolderError:
            for _, dn in created:
                conn.delete(dn)
            created = []
            raise

        # 3. Appartenances (GG dans DL, comptes dans GG ou DL).
        for group_dn, member_dn in nesting:
            fs.add_member(conn, group_dn, member_dn)

        names_created = [n for n, _ in created]
        _audit('folder_create', {'path': result['path'], 'groups': names_created,
                                 'protect': protect, 'agdlp': with_global, 'reuse': reuse})
        msg = f'Dossier {result["path"]} créé'
        if names_created:
            msg += f' ; groupes créés : {", ".join(names_created)}'
        flash(msg + '.', 'success')
        return _back(result['path'])
    except fs.FolderError as e:
        names_created = [n for n, _ in created]
        _audit('folder_create', {'parent': parent, 'name': name, 'groups': names_created,
                                 'error': str(e)}, False)
        if names_created:
            flash(f'{e} (groupes créés : {", ".join(names_created)})', 'error')
        else:
            flash(str(e), 'error')
        return _back(parent)
    finally:
        conn.unbind()


@folders_bp.route('/settings', methods=['GET', 'POST'])
@require_connection
@require_permission('admin:settings')
def settings_page():
    settings = fs.get_folder_settings()
    if request.method == 'POST':
        try:
            settings = fs.save_folder_settings(request.form.get('roots', ''),
                                               request.form.get('home_root', ''),
                                               request.form.get('home_drive', 'H:'),
                                               request.form.get('scan_depth', 3))
            _audit('folder_settings', {'roots': settings['roots'], 'home_root': settings['home_root']})
            flash('Paramètres des répertoires enregistrés.', 'success')
            return redirect(url_for('folders.settings_page'))
        except fs.FolderError as e:
            flash(str(e), 'error')
            settings = {'roots': request.form.get('roots', '').split('\n'),
                        'home_root': request.form.get('home_root', ''),
                        'home_drive': request.form.get('home_drive', 'H:'),
                        'scan_depth': request.form.get('scan_depth', 3)}
    return render_template('folder_settings.html', settings=settings, connected=is_connected())


# --- Accès d'un compte -------------------------------------------------------

@folders_bp.route('/access')
@require_connection
@require_permission('tools:folders_read')
def access_page():
    """Dossiers accessibles à un utilisateur ou un groupe (analyse en JS)."""
    return render_template('folder_access.html', dn=request.args.get('dn', ''),
                           settings=fs.get_folder_settings(), connected=is_connected())


@folders_bp.route('/api/access', methods=['POST'])
@require_connection
@require_permission('tools:folders_read')
def api_access():
    data = request.get_json(silent=True) or {}
    dn = (data.get('dn') or '').strip()
    principal = (data.get('principal') or '').strip()
    base_dn = session.get('ad_base_dn', '')
    conn, error = get_ad_connection()
    if not conn:
        return jsonify({'success': False, 'error': error}), 502
    try:
        if not dn:
            dn = fs.find_principal(conn, base_dn, principal)[0]
        elif not dn.lower().endswith(base_dn.lower()):
            raise fs.FolderError('Objet hors du domaine.')
        who = fs.resolve_principal(conn, base_dn, dn)
        conn.unbind()
        conn = None
        prepared = fs.prepare_scan(list(who['sids'].keys()))
        principal_info = {'name': who['name'], 'kind': who['kind'], 'dn': dn,
                          'groups': len(who['sids']) - 1}

        def decorate(result):
            for row in result['found']:
                row['via'] = who['sids'].get(row['sid'], row['name'])
                row['direct'] = row['sid'] == who['sid']
            result['principal'] = principal_info

        job_id = fs.start_scan_job(session.get('ad_username'), prepared, decorate,
                                   key=('access', dn.lower()), refresh=bool(data.get('refresh')))
        _audit('folder_access_scan', {'principal': who['name'], 'dn': dn})
        return jsonify({'success': True, 'job': job_id, 'principal': principal_info}), 202
    except fs.FolderError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:                       # erreur LDAP inattendue : message lisible plutôt qu'une erreur 500
        logger.exception('Analyse des accès impossible')
        return jsonify({'success': False, 'error': f'Analyse impossible : {e}'}), 502
    finally:
        if conn:
            conn.unbind()


@folders_bp.route('/api/access/<job_id>')
@require_connection
@require_permission('tools:folders_read')
def api_access_status(job_id):
    """État d'une analyse lancée par api_access (interrogé par la page)."""
    job = fs.get_scan_job(job_id, session.get('ad_username'))
    if not job:
        return jsonify({'success': False, 'error': 'Analyse introuvable ou expirée.'}), 404
    if job['status'] == 'running':
        return jsonify({'success': True, 'status': 'running',
                        'elapsed': int(time.time() - job['created'])})
    if job['status'] == 'error':
        return jsonify({'success': False, 'status': 'error', 'error': job['error']})
    return jsonify({'success': True, 'status': 'done', **job['result']})


# --- Dossiers personnels -----------------------------------------------------

def provision_home_folder(conn, user_dn):
    """
    Dossier personnel : \\\\racine\\<sAMAccountName> avec droits Modification
    pour le seul utilisateur (plus Administrateurs et Système), et
    homeDirectory / homeDrive renseignés.

    Si le compte a déjà un dossier personnel sous la racine configurée, c'est
    celui-là qui est remis en ordre (droits explicites des autres comptes
    retirés). S'il pointe ailleurs, rien n'est modifié : l'y rediriger
    laisserait l'utilisateur devant un dossier vide, ses données restant à
    l'ancien emplacement.

    Returns:
        str: le chemin du dossier. Raises FolderError.
    """
    from ldap3 import BASE, MODIFY_REPLACE
    settings = fs.get_folder_settings()
    root = settings['home_root']
    if not root:
        raise fs.FolderError('Aucune racine des dossiers personnels n\'est configurée.')
    conn.search(user_dn, '(objectClass=user)', BASE,
                attributes=['sAMAccountName', 'objectSid', 'homeDirectory'])
    if not conn.entries:
        raise fs.FolderError('Utilisateur introuvable.')
    entry = conn.entries[0]
    sam = str(entry.sAMAccountName.value)
    sid = fs.sid_to_str(entry.objectSid)
    current = ''
    if 'homeDirectory' in entry and entry.homeDirectory.value:
        current = str(entry.homeDirectory.value).strip()

    parent, name = root, sam
    if current:
        try:
            current = fs.normalize_unc(current)
        except fs.FolderError:
            current = None
        if not current or not fs.is_under(current, root) or current.lower() == root.lower():
            raise fs.FolderError(
                f'Le dossier personnel actuel ({entry.homeDirectory.value}) n\'est pas sous la racine '
                f'configurée ({root}) : déplacez les données puis modifiez homeDirectory vous-même.')
        parent, name = current.rsplit('\\', 1)

    result = fs.create_folder(parent, name, [(sid, 'modify')], protect=True,
                              extra_roots=[root], allow_existing=True, reset=True)
    conn.modify(user_dn, {'homeDirectory': [(MODIFY_REPLACE, [result['path']])],
                          'homeDrive': [(MODIFY_REPLACE, [settings['home_drive']])]})
    if conn.result.get('result') != 0:
        raise fs.FolderError('Dossier créé, mais homeDirectory n\'a pas pu être renseigné : '
                             f'{conn.result.get("message") or conn.result.get("description")}')
    return result['path']


@folders_bp.route('/home/<path:dn>', methods=['POST'])
@require_connection
@require_permission('tools:home_folders')
def create_home(dn):
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur : {error}', 'error')
        return redirect(url_for('users.edit_user', dn=dn))
    try:
        path = provision_home_folder(conn, dn)
        _audit('home_folder', {'dn': dn, 'path': path})
        flash(f'Dossier personnel {path} prêt (lecteur {fs.get_folder_settings()["home_drive"]}).',
              'success')
    except fs.FolderError as e:
        _audit('home_folder', {'dn': dn, 'error': str(e)}, False)
        flash(str(e), 'error')
    finally:
        conn.unbind()
    return redirect(url_for('users.edit_user', dn=dn))


# --- Découverte des partages et vue d'ensemble --------------------------------

@folders_bp.route('/discover')
@require_connection
@require_permission('tools:folders_read')
def discover():
    """Serveurs du domaine ; leurs partages sont listés à la demande (JS)."""
    servers, error = [], None
    conn, err = get_ad_connection()
    if conn:
        try:
            servers = fs.list_servers(conn, session.get('ad_base_dn', ''))
        except Exception as e:
            error = str(e)
        finally:
            conn.unbind()
    else:
        error = err
    return render_template('folder_discover.html', servers=servers, error=error,
                           settings=fs.get_folder_settings(), can_add=_can('admin:settings'),
                           connected=is_connected())


@folders_bp.route('/api/shares')
@require_connection
@require_permission('tools:folders_read')
def api_shares():
    try:
        return jsonify({'success': True, 'shares': fs.list_shares(request.args.get('server', ''))})
    except fs.FolderError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@folders_bp.route('/api/roots', methods=['POST'])
@require_connection
@require_permission('admin:settings')
def api_add_root():
    """Ajoute un ou plusieurs partages aux partages gérés."""
    data = request.get_json(silent=True) or {}
    paths = data.get('paths') or ([data.get('path')] if data.get('path') else [])
    if not isinstance(paths, list) or not paths or len(paths) > 200:
        return jsonify({'success': False, 'error': 'Aucun partage indiqué.'}), 400
    added = []
    try:
        for path in paths:
            added.append(fs.add_root(str(path)))
    except fs.FolderError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    _audit('folder_roots_add', {'paths': added})
    return jsonify({'success': True, 'added': added, 'roots': fs.get_folder_settings()['roots']})


@folders_bp.route('/overview')
@require_connection
@require_permission('tools:folders_read')
def overview_page():
    """Vue d'ensemble des droits d'un partage ou d'un dossier (analyse en JS)."""
    settings = fs.get_folder_settings()
    path = request.args.get('path', '').strip() or (settings['roots'][0] if settings['roots'] else '')
    error = None
    if path:
        try:
            path = fs.check_allowed(path)
        except fs.FolderError as e:
            error = str(e)
    return render_template('folder_overview.html', path=path, error=error, settings=settings,
                           connected=is_connected())


@folders_bp.route('/api/overview', methods=['POST'])
@require_connection
@require_permission('tools:folders_read')
def api_overview():
    data = request.get_json(silent=True) or {}
    try:
        prepared = fs.prepare_overview(data.get('path', ''), data.get('depth'))
        job_id = fs.start_job(session.get('ad_username'),
                              ('overview', prepared['path'].lower(), prepared['depth']),
                              lambda: fs.rights_overview(prepared), refresh=bool(data.get('refresh')))
        _audit('folder_overview', {'path': prepared['path'], 'depth': prepared['depth']})
        return jsonify({'success': True, 'job': job_id}), 202
    except fs.FolderError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
