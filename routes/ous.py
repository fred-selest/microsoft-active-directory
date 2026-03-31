"""
Blueprint pour la gestion des unités organisationnelles (OUs).
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException

from .core import (get_ad_connection, decode_ldap_value, is_connected,
                   require_connection, require_permission)
from security import validate_csrf_token
from audit import log_action

ous_bp = Blueprint('ous_bp', __name__, url_prefix='/ous')


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
        parent_ous = [{'name': decode_ldap_value(e.name), 'dn': decode_ldap_value(e.distinguishedName)}
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
            'description': decode_ldap_value(entry.description),
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
