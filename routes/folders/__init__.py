# -*- coding: utf-8 -*-
"""
Répertoires partagés : droits NTFS, accès d'un compte, dossiers
partagés AGDLP et dossiers personnels.

Le travail sur les fichiers est fait par core/folders.py, sous l'identité de
l'administrateur connecté.
"""
import logging

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
    if folder:
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
    ou_dn = request.form.get('ou', '').strip()
    with_global = request.form.get('with_global') == 'on'
    protect = request.form.get('protect') == 'on'
    base_dn = session.get('ad_base_dn', '')

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur : {error}', 'error')
        return _back(parent)
    created = []
    try:
        fs.check_allowed(parent)
        folder_name = fs.validate_folder_name(name)
        if not ou_dn or not ou_dn.lower().endswith(base_dn.lower()):
            raise fs.FolderError('Choisissez l\'unité d\'organisation des groupes.')
        members = {'read': _members(conn, base_dn, request.form.get('members_read', '')),
                   'modify': _members(conn, base_dn, request.form.get('members_modify', ''))}
        target = parent.rstrip('\\') + '\\' + folder_name

        grants = []
        for level, names in fs.access_group_names(folder_name, with_global).items():
            label = fs.LEVELS[level]['label']
            dl_dn, dl_sid, new = fs.ensure_group(conn, base_dn, ou_dn, names['dl'],
                                                 fs.GROUP_DOMAIN_LOCAL_SECURITY,
                                                 f'{label} sur {target}')
            if new:
                created.append(names['dl'])
            grants.append((dl_sid, level))
            member_group = dl_dn
            if 'gg' in names:
                gg_dn, _, new = fs.ensure_group(conn, base_dn, ou_dn, names['gg'],
                                                fs.GROUP_GLOBAL_SECURITY,
                                                f'Comptes ayant {label.lower()} sur {target}')
                if new:
                    created.append(names['gg'])
                fs.add_member(conn, dl_dn, gg_dn)
                member_group = gg_dn
            for member_dn in members[level]:
                fs.add_member(conn, member_group, member_dn)

        result = fs.create_folder(parent, folder_name, grants, protect=protect)
        _audit('folder_create', {'path': result['path'], 'groups': created,
                                 'protect': protect, 'agdlp': with_global})
        msg = f'Dossier {result["path"]} créé'
        if created:
            msg += f' ; groupes créés : {", ".join(created)}'
        flash(msg + '.', 'success')
        return _back(result['path'])
    except fs.FolderError as e:
        _audit('folder_create', {'parent': parent, 'name': name, 'groups': created,
                                 'error': str(e)}, False)
        if created:
            flash(f'{e} (groupes déjà créés : {", ".join(created)})', 'error')
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
        result = fs.scan_access(list(who['sids'].keys()))
        for row in result['found']:
            row['via'] = who['sids'].get(row['sid'], row['name'])
            row['direct'] = row['sid'] == who['sid']
        return jsonify({'success': True, 'principal': {'name': who['name'], 'kind': who['kind'],
                                                       'dn': dn, 'groups': len(who['sids']) - 1},
                        **result})
    except fs.FolderError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    finally:
        if conn:
            conn.unbind()


# --- Dossiers personnels -----------------------------------------------------

def provision_home_folder(conn, user_dn):
    """
    Crée \\\\racine\\<sAMAccountName>, droits Modification pour le seul
    utilisateur (plus Administrateurs et Système), et renseigne
    homeDirectory / homeDrive.

    Returns:
        str: le chemin du dossier. Raises FolderError.
    """
    from ldap3 import BASE, MODIFY_REPLACE
    settings = fs.get_folder_settings()
    root = settings['home_root']
    if not root:
        raise fs.FolderError('Aucune racine des dossiers personnels n\'est configurée.')
    conn.search(user_dn, '(objectClass=user)', BASE, attributes=['sAMAccountName', 'objectSid'])
    if not conn.entries:
        raise fs.FolderError('Utilisateur introuvable.')
    entry = conn.entries[0]
    sam = str(entry.sAMAccountName.value)
    sid = fs.sid_to_str(entry.objectSid)
    result = fs.create_folder(root, sam, [(sid, 'modify')], protect=True,
                              extra_roots=[root], allow_existing=True)
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
