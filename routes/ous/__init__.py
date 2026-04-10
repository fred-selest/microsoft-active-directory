"""
Blueprint pour la gestion des unités organisationnelles (OUs).
"""
import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, LEVEL, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException

from routes.core import (get_ad_connection, decode_ldap_value, is_connected,
                   require_connection, require_permission)
from core.security import validate_csrf_token
from core.audit import log_action

logger = logging.getLogger(__name__)

ous_bp = Blueprint('ous', __name__, url_prefix='/ous')


@ous_bp.route('/')
@require_connection
def list_ous():
    """Liste des OUs avec statistiques enrichies."""
    from ldap3 import SUBTREE
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('main.connect'))

    base_dn = session.get('ad_base_dn', '')
    ou_list = []
    tree = None

    try:
        # Récupérer toutes les OUs
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'description', 'distinguishedName'])

        for e in conn.entries:
            ou_dn = decode_ldap_value(e.entry_dn)
            
            # Compter les objets dans chaque OU
            ou_stats = _count_ou_objects(conn, ou_dn)
            
            ou_list.append({
                'name': decode_ldap_value(e.name),
                'description': decode_ldap_value(getattr(e, 'description', None)),
                'dn': ou_dn,
                'users_count': ou_stats['users'],
                'groups_count': ou_stats['groups'],
                'computers_count': ou_stats['computers'],
                'sub_ous_count': ou_stats['sub_ous'],
                'total_objects': ou_stats['total']
            })

        # Construire l'arborescence
        tree = build_ou_tree(base_dn, ou_list)

        conn.unbind()
        return render_template('ous.html', ous=ou_list, tree=tree, connected=is_connected())
    except Exception as ex:
        flash(f'Erreur: {str(ex)}', 'error')
        conn.unbind()
        return render_template('ous.html', ous=[], tree=None, connected=is_connected())


def _count_ou_objects(conn, ou_dn):
    """
    Compter les objets dans une OU.
    Utilise LEVEL pour éviter les problèmes de permissions sur les sous-arborescences.

    Returns:
        dict: {'users': int, 'groups': int, 'computers': int, 'sub_ous': int, 'total': int}
    """
    stats = {'users': 0, 'groups': 0, 'computers': 0, 'sub_ous': 0, 'total': 0}

    try:
        # Compter utilisateurs (niveau direct seulement - plus fiable)
        search_filter = '(&(objectClass=user)(objectCategory=person))'
        conn.search(ou_dn, search_filter, search_scope=LEVEL, attributes=['sAMAccountName'])
        stats['users'] = len(conn.entries)

        # Compter groupes
        conn.search(ou_dn, '(objectClass=group)', search_scope=LEVEL, attributes=['cn'])
        stats['groups'] = len(conn.entries)

        # Compter ordinateurs
        conn.search(ou_dn, '(objectClass=computer)', search_scope=LEVEL, attributes=['cn'])
        stats['computers'] = len(conn.entries)

        # Compter sous-OUs (niveau direct seulement)
        conn.search(ou_dn, '(objectClass=organizationalUnit)', search_scope=LEVEL, attributes=['name'])
        stats['sub_ous'] = len(conn.entries)

        # Total
        stats['total'] = stats['users'] + stats['groups'] + stats['computers']

    except Exception as e:
        # En production, on logge mais on retourne ce qu'on a
        logger.debug(f"Erreur comptage OU: {e}")

    return stats


def build_ou_tree(base_dn, ous):
    """Construire une arborescence à partir d'une liste d'OUs."""
    root = {
        'name': base_dn.split(',')[0].replace('DC=', '') if base_dn else 'Domaine',
        'dn': base_dn,
        'type': 'domain',
        'children': []
    }

    def add_ou_to_tree(parent, ou):
        """Ajouter une OU à l'arborescence."""
        dn_parts = ou['dn'].split(',')
        # Trouver le parent direct
        for i, part in enumerate(dn_parts):
            if part.startswith('OU='):
                ou_name = part[3:]
                # Chercher si cette OU existe déjà dans les enfants
                found = None
                for child in parent['children']:
                    if child['name'] == ou_name:
                        found = child
                        break
                if not found:
                    found = {
                        'name': ou_name,
                        'dn': ou['dn'],
                        'type': 'ou',
                        'children': []
                    }
                    parent['children'].append(found)
                parent = found

    # Trier les OUs par profondeur (nombre de OU= dans le DN)
    sorted_ous = sorted(ous, key=lambda x: x['dn'].count('OU='))

    for ou in sorted_ous:
        add_ou_to_tree(root, ou)

    return root


@ous_bp.route('/create', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def create_ou():
    """Créer une nouvelle OU."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('ous'))

    base_dn = session.get('ad_base_dn', '')

    try:
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'distinguishedName'])
        parent_ous = [{'name': decode_ldap_value(e.name), 'dn': decode_ldap_value(e.entry_dn)}
                      for e in conn.entries]
    except Exception:
        parent_ous = []

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token CSRF invalide.', 'error')
            conn.unbind()
            return render_template('ou_form.html', action='create', parent_ous=parent_ous, connected=is_connected())

        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        parent_ou = request.form.get('parent_ou', '').strip() or base_dn

        if not name:
            flash("Nom de l'OU requis.", 'error')
            conn.unbind()
            return render_template('ou_form.html', action='create', parent_ous=parent_ous, connected=is_connected())

        ou_dn = f"OU={name},{parent_ou}"
        attributes = {'objectClass': ['top', 'organizationalUnit']}
        if description:
            attributes['description'] = description

        try:
            conn.add(ou_dn, attributes=attributes)
            if conn.result['result'] == 0:
                log_action('create_ou', session.get('ad_username'), {'dn': ou_dn}, True, request.remote_addr)
                flash(f'OU {name} créée.', 'success')
                conn.unbind()
                return redirect(url_for('ous'))
            else:
                flash(f'Erreur: {conn.result["description"]}', 'error')
        except Exception as e:
            flash(f'Erreur: {str(e)}', 'error')
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    return render_template('ou_form.html', action='create', parent_ous=parent_ous, connected=is_connected())


@ous_bp.route('/<path:dn>/edit', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def edit_ou(dn):
    """Modifier la description d'une OU."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('ous'))

    base_dn = session.get('ad_base_dn', '')
    ou = None

    try:
        conn.search(base_dn, f'(distinguishedName={dn})', SUBTREE,
                   attributes=['name', 'description', 'distinguishedName'])
        if not conn.entries:
            flash('OU introuvable.', 'error')
            conn.unbind()
            return redirect(url_for('ous'))
        entry = conn.entries[0]
        ou = {
            'name': decode_ldap_value(entry.name),
            'description': decode_ldap_value(getattr(entry, 'description', None)),
            'dn': dn
        }
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
        conn.unbind()
        return redirect(url_for('ous'))

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token CSRF invalide.', 'error')
            return render_template('ou_form.html', action='edit', ou=ou, connected=is_connected())

        description = request.form.get('description', '').strip()
        try:
            changes = {'description': [(MODIFY_REPLACE, [description] if description else [])]}
            conn.modify(dn, changes)
            if conn.result['result'] == 0:
                log_action('edit_ou', session.get('ad_username'), {'dn': dn}, True, request.remote_addr)
                flash('OU modifiée.', 'success')
                conn.unbind()
                return redirect(url_for('ous'))
            else:
                flash(f'Erreur: {conn.result["description"]}', 'error')
        except Exception as e:
            flash(f'Erreur: {str(e)}', 'error')
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    return render_template('ou_form.html', action='edit', ou=ou, connected=is_connected())


@ous_bp.route('/<path:dn>/delete', methods=['POST'])
@require_connection
@require_permission('delete')
def delete_ou(dn):
    """Supprimer une OU."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('ous'))

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('ous'))

    try:
        conn.delete(dn)
        if conn.result['result'] == 0:
            log_action('delete_ou', session.get('ad_username'), {'dn': dn}, True, request.remote_addr)
            flash('OU supprimée.', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
    finally:
        conn.unbind()

    return redirect(url_for('ous'))
