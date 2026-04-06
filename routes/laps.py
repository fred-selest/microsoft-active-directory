# -*- coding: utf-8 -*-
"""
Blueprint pour la gestion complète de LAPS.
"""
import os
import subprocess
import tempfile
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from ldap3 import SUBTREE
from ldap3.core.exceptions import LDAPException

from routes.core import get_ad_connection, decode_ldap_value, is_connected, require_connection, require_permission
from security import escape_ldap_filter

laps_bp = Blueprint('laps_management', __name__, url_prefix='/laps-management')


def run_powershell_script(script_content, params=None):
    """Exécuter un script PowerShell et retourner le résultat."""
    try:
        # Créer un fichier temporaire pour le script
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as f:
            f.write(script_content)
            script_path = f.name
        
        # Construire la commande PowerShell
        cmd = ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path]
        if params:
            for key, value in params.items():
                cmd.append(f'-{key}')
                cmd.append(str(value))
        
        # Exécuter le script
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        # Nettoyer le fichier temporaire
        os.unlink(script_path)
        
        return {
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    except Exception as e:
        return {
            'success': False,
            'stdout': '',
            'stderr': str(e),
            'returncode': -1
        }


@laps_bp.route('/')
@require_connection
@require_permission('admin')
def laps_dashboard():
    """Tableau de bord LAPS."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))
    
    base_dn = session.get('ad_base_dn', '')
    stats = {
        'total_computers': 0,
        'laps_enabled': 0,
        'laps_legacy': 0,
        'laps_windows': 0,
        'expired_passwords': 0
    }
    
    try:
        # Compter les ordinateurs
        conn.search(base_dn, '(objectClass=computer)', SUBTREE, attributes=['cn', 'ms-Mcs-AdmPwd', 'msLAPS-Password'])
        
        stats['total_computers'] = len(conn.entries)
        
        for entry in conn.entries:
            has_legacy = hasattr(entry, 'ms-Mcs-AdmPwd') and entry.ms-Mcs-AdmPwd.value
            has_windows = hasattr(entry, 'msLAPS-Password') and entry.msLAPS-Password.value
            
            if has_legacy or has_windows:
                stats['laps_enabled'] += 1
            
            if has_legacy and not has_windows:
                stats['laps_legacy'] += 1
            elif has_windows:
                stats['laps_windows'] += 1
        
        conn.unbind()
    except Exception as e:
        flash(f'Erreur: {e}', 'error')
    
    return render_template('laps_dashboard.html', stats=stats, connected=is_connected())


@laps_bp.route('/install', methods=['GET', 'POST'])
@require_connection
@require_permission('admin')
def install_laps():
    """Installer LAPS."""
    # Script inline pour éviter les imports
    script = r'''# Installer LAPS sur le domaine
param([string]$LapsPath = "C:\Program Files\AdmPwd\Core\AdmPwd.dll")
Write-Host "Installation LAPS..."
if (Test-Path $LapsPath) { Write-Host "Déjà installé" } else { Write-Host "À installer" }
'''
    
    if request.method == 'POST':
        flash('✅ Installation LAPS (simulation) - Script PowerShell à exécuter manuellement', 'success')
        return redirect(url_for('laps_management.laps_dashboard'))
    
    return render_template('laps_install.html', connected=is_connected())


@laps_bp.route('/extend-schema', methods=['GET', 'POST'])
@require_connection
@require_permission('admin')
def extend_schema():
    """Étendre le schéma pour LAPS."""
    from scripts.laps_management import EXTEND_SCHEMA_PS1
    
    if request.method == 'POST':
        force = request.form.get('force') == 'on'
        params = {'Force': ''} if force else {}
        result = run_powershell_script(EXTEND_SCHEMA_PS1, params)
        
        if result['success']:
            flash('✅ Schéma étendu avec succès !', 'success')
        else:
            flash(f'❌ Erreur: {result["stderr"]}', 'error')
        
        return redirect(url_for('laps_management.laps_dashboard'))
    
    return render_template('laps_extend_schema.html', connected=is_connected())


@laps_bp.route('/verify-schema')
@require_connection
@require_permission('admin')
def verify_schema():
    """Vérifier l'extension du schéma."""
    from scripts.laps_management import VERIFY_SCHEMA_PS1
    
    result = run_powershell_script(VERIFY_SCHEMA_PS1)
    
    return jsonify({
        'success': result['success'],
        'output': result['stdout'],
        'error': result['stderr']
    })


@laps_bp.route('/set-computer-permissions', methods=['GET', 'POST'])
@require_connection
@require_permission('admin')
def set_computer_permissions():
    """Accorder aux ordinateurs le droit de mettre à jour leur mot de passe."""
    from scripts.laps_management import SET_COMPUTER_PERMISSIONS_PS1
    
    if request.method == 'POST':
        computer_ou = request.form.get('computer_ou', '')
        params = {'ComputerOU': computer_ou} if computer_ou else {}
        result = run_powershell_script(SET_COMPUTER_PERMISSIONS_PS1, params)
        
        if result['success']:
            flash('✅ Permissions accordées avec succès !', 'success')
        else:
            flash(f'❌ Erreur: {result["stderr"]}', 'error')
        
        return redirect(url_for('laps_management.laps_dashboard'))
    
    # Récupérer les OUs pour le formulaire
    conn, error = get_ad_connection()
    ous = []
    if conn:
        base_dn = session.get('ad_base_dn', '')
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['name', 'distinguishedName'])
        ous = [{'name': decode_ldap_value(e.name), 'dn': decode_ldap_value(e.distinguishedName)} for e in conn.entries]
        conn.unbind()
    
    return render_template('laps_computer_permissions.html', ous=ous, connected=is_connected())


@laps_bp.route('/set-read-permissions', methods=['GET', 'POST'])
@require_connection
@require_permission('admin')
def set_read_permissions():
    """Accorder les permissions de lecture/réinitialisation."""
    from scripts.laps_management import SET_READ_PERMISSIONS_PS1
    
    if request.method == 'POST':
        group_name = request.form.get('group_name', '')
        reset_password = request.form.get('reset_password') == 'on'
        computer_ou = request.form.get('computer_ou', '')
        
        if not group_name:
            flash('❌ Nom du groupe requis.', 'error')
            return redirect(url_for('laps_management.set_read_permissions'))
        
        params = {'GroupName': group_name}
        if reset_password:
            params['ResetPassword'] = ''
        if computer_ou:
            params['ComputerOU'] = computer_ou
        
        result = run_powershell_script(SET_READ_PERMISSIONS_PS1, params)
        
        if result['success']:
            flash('✅ Permissions accordées avec succès !', 'success')
        else:
            flash(f'❌ Erreur: {result["stderr"]}', 'error')
        
        return redirect(url_for('laps_management.laps_dashboard'))
    
    # Récupérer les groupes et OUs
    conn, error = get_ad_connection()
    groups = []
    ous = []
    if conn:
        base_dn = session.get('ad_base_dn', '')
        conn.search(base_dn, '(objectClass=group)', SUBTREE, attributes=['cn', 'distinguishedName'])
        groups = [{'name': decode_ldap_value(e.cn), 'dn': decode_ldap_value(e.distinguishedName)} for e in conn.entries]
        
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['name', 'distinguishedName'])
        ous = [{'name': decode_ldap_value(e.name), 'dn': decode_ldap_value(e.distinguishedName)} for e in conn.entries]
        conn.unbind()
    
    return render_template('laps_read_permissions.html', groups=groups, ous=ous, connected=is_connected())


@laps_bp.route('/configure-gpo', methods=['GET', 'POST'])
@require_connection
@require_permission('admin')
def configure_gpo():
    """Configurer la GPO LAPS."""
    from scripts.laps_management import CREATE_GPO_LAPS_PS1
    
    if request.method == 'POST':
        gpo_name = request.form.get('gpo_name', 'LAPS Configuration')
        target_ou = request.form.get('target_ou', '')
        password_length = int(request.form.get('password_length', 14))
        password_age = int(request.form.get('password_age', 30))
        admin_account = request.form.get('admin_account', 'Administrator')
        
        params = {
            'GPOName': gpo_name,
            'PasswordLength': password_length,
            'PasswordAge': password_age,
            'AdminAccountName': admin_account
        }
        if target_ou:
            params['TargetOU'] = target_ou
        
        result = run_powershell_script(CREATE_GPO_LAPS_PS1, params)
        
        if result['success']:
            flash('✅ GPO LAPS configurée avec succès !', 'success')
        else:
            flash(f'❌ Erreur: {result["stderr"]}', 'error')
        
        return redirect(url_for('laps_management.laps_dashboard'))
    
    # Récupérer les OUs
    conn, error = get_ad_connection()
    ous = []
    if conn:
        base_dn = session.get('ad_base_dn', '')
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['name', 'distinguishedName'])
        ous = [{'name': decode_ldap_value(e.name), 'dn': decode_ldap_value(e.distinguishedName)} for e in conn.entries]
        conn.unbind()
    
    return render_template('laps_gpo.html', ous=ous, connected=is_connected())


@laps_bp.route('/create-admin', methods=['GET', 'POST'])
@require_connection
@require_permission('admin')
def create_admin():
    """Créer le compte administrateur local."""
    from scripts.laps_management import CREATE_LOCAL_ADMIN_PS1
    
    if request.method == 'POST':
        account_name = request.form.get('account_name', '')
        full_name = request.form.get('full_name', 'Administrateur Local')
        description = request.form.get('description', 'Compte administrateur local géré par LAPS')
        
        if not account_name:
            flash('❌ Nom du compte requis.', 'error')
            return redirect(url_for('laps_management.create_admin'))
        
        params = {
            'AccountName': account_name,
            'FullName': full_name,
            'Description': description
        }
        
        result = run_powershell_script(CREATE_LOCAL_ADMIN_PS1, params)
        
        if result['success']:
            flash('✅ Script généré avec succès !', 'success')
        else:
            flash(f'❌ Erreur: {result["stderr"]}', 'error')
        
        return redirect(url_for('laps_management.laps_dashboard'))
    
    return render_template('laps_create_admin.html', connected=is_connected())


@laps_bp.route('/get-password/<computer_name>')
@require_connection
@require_permission('admin')
def get_password(computer_name):
    """Récupérer un mot de passe LAPS."""
    from scripts.laps_management import GET_LAPS_PASSWORD_PS1
    
    result = run_powershell_script(GET_LAPS_PASSWORD_PS1, {'ComputerName': computer_name})
    
    return jsonify({
        'success': result['success'],
        'output': result['stdout'],
        'error': result['stderr']
    })


@laps_bp.route('/force-rotation/<computer_name>', methods=['POST'])
@require_connection
@require_permission('admin')
def force_rotation(computer_name):
    """Forcer la rotation du mot de passe LAPS."""
    from scripts.laps_management import FORCE_LAPS_ROTATION_PS1
    
    result = run_powershell_script(FORCE_LAPS_ROTATION_PS1, {'ComputerName': computer_name})
    
    if result['success']:
        return jsonify({'success': True, 'message': 'Rotation forcée avec succès !'})
    else:
        return jsonify({'success': False, 'error': result['stderr']}), 500