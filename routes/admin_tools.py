# -*- coding: utf-8 -*-
"""
Blueprint pour les routes d'administration et outils.
Contient: update, diagnostic, alerts, errors, security-audit, permissions, ldaps-setup
"""
from flask import Blueprint, render_template, session, flash, request, jsonify, send_file
from .core import require_connection, require_permission, get_ad_connection

admin_tools_bp = Blueprint('admin_tools', __name__, url_prefix='/')


@admin_tools_bp.route('/update')
def update_page():
    """Page de mise à jour."""
    try:
        from updater import check_for_updates_fast
        update_info = check_for_updates_fast()
    except Exception as e:
        update_info = {
            'update_available': False,
            'current_version': 'Erreur',
            'latest_version': None,
            'error': str(e)
        }
    return render_template('update.html', update_info=update_info, connected=False)


@admin_tools_bp.route('/diagnostic')
@require_connection
def diagnostic_page():
    """Page de diagnostic et dépannage."""
    return render_template('diagnostic.html', connected=True)


@admin_tools_bp.route('/alerts')
@require_connection
def alerts_page():
    """Page des alertes enrichie."""
    from ldap3 import SUBTREE
    from datetime import datetime, timedelta

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return render_template('alerts.html', alert_data={}, alerts=[], connected=True)

    base_dn = session.get('ad_base_dn', '')

    # Statistiques d'alertes
    alert_data = {
        'locked_accounts': 0,
        'disabled_accounts': 0,
        'inactive_accounts': 0,
        'inactive_computers': 0,
        'password_expiring': 0,
        'admin_accounts': 0,
        'empty_groups': 0,
    }

    alerts = []
    now = datetime.now()

    # Groupes système à exclure (primaryGroupToken)
    SYSTEM_GROUP_TOKENS = [
        513, 514, 515, 516, 498, 521, 522, 525, 526, 527,
        548, 549, 550, 551, 552, 553, 556, 557, 558, 559, 560, 562, 568, 569, 571, 573, 579, 580, 582,
        1102, 1103, 1104, 1114, 1118, 1121, 1124, 1125, 1126, 1129, 1153, 1154,
    ]

    try:
        # === 1. COMPTES VERROUILLES ===
        conn.search(base_dn, '(&(objectClass=user)(lockoutTime>=1))', SUBTREE,
                   attributes=['cn', 'sAMAccountName'])
        alert_data['locked_accounts'] = len(conn.entries)
        if alert_data['locked_accounts'] > 0:
            alerts.append({
                'title': f'{alert_data["locked_accounts"]} compte(s) verrouillé(s)',
                'message': 'Des comptes sont verrouillés suite à tentatives échouées.',
                'severity': 'warning',
                'date': now.strftime('%d/%m/%Y %H:%M')
            })

        # === 2. COMPTES DESACTIVES ===
        conn.search(base_dn, '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))', SUBTREE,
                   attributes=['cn', 'sAMAccountName'])
        alert_data['disabled_accounts'] = len(conn.entries)
        if alert_data['disabled_accounts'] > 5:
            alerts.append({
                'title': f'{alert_data["disabled_accounts"]} compte(s) désactivé(s)',
                'message': 'Des comptes sont désactivés. Vérifiez s\'ils doivent être supprimés.',
                'severity': 'info',
                'date': now.strftime('%d/%m/%Y %H:%M')
            })

        # === 3. COMPTES INACTIFS (> 90 jours) ===
        conn.search(base_dn, '(objectClass=user)', SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'lastLogon'])
        for entry in conn.entries:
            last_logon_attr = getattr(entry, 'lastLogon', None)
            if last_logon_attr and last_logon_attr.value:
                try:
                    val = int(str(last_logon_attr.value))
                    if val == 0:
                        alert_data['inactive_accounts'] += 1
                    else:
                        logon_date = datetime.fromtimestamp(val / 10000000 - 11644473600)
                        if (now - logon_date).days > 90:
                            alert_data['inactive_accounts'] += 1
                except:
                    pass
            else:
                alert_data['inactive_accounts'] += 1
        if alert_data['inactive_accounts'] > 10:
            alerts.append({
                'title': f'{alert_data["inactive_accounts"]} compte(s) inactif(s)',
                'message': 'Comptes non utilisés depuis plus de 90 jours.',
                'severity': 'info',
                'date': now.strftime('%d/%m/%Y %H:%M')
            })

        # === 4. ORDINATEURS INACTIFS (> 30 jours) ===
        conn.search(base_dn, '(objectClass=computer)', SUBTREE,
                   attributes=['cn', 'lastLogonTimestamp'])
        for entry in conn.entries:
            last_logon_attr = getattr(entry, 'lastLogonTimestamp', None)
            if last_logon_attr and last_logon_attr.value:
                try:
                    val = int(str(last_logon_attr.value))
                    if val > 0:
                        logon_date = datetime.fromtimestamp(val / 10000000 - 11644473600)
                        if (now - logon_date).days > 30:
                            alert_data['inactive_computers'] += 1
                except:
                    pass
        if alert_data['inactive_computers'] > 5:
            alerts.append({
                'title': f'{alert_data["inactive_computers"]} ordinateur(s) inactif(s)',
                'message': 'Ordinateurs n\'ayant pas contacté le domaine depuis 30+ jours.',
                'severity': 'info',
                'date': now.strftime('%d/%m/%Y %H:%M')
            })

        # === 5. MOTS DE PASSE EXPIRANT (< 14 jours) ===
        conn.search(base_dn, '(objectClass=user)', SUBTREE,
                   attributes=['pwdLastSet', 'userAccountControl'])
        for entry in conn.entries:
            uac_attr = getattr(entry, 'userAccountControl', None)
            if uac_attr and uac_attr.value:
                try:
                    uac = int(str(uac_attr.value))
                    if uac & 65536:  # Password never expires
                        continue
                except:
                    pass
            pwd_attr = getattr(entry, 'pwdLastSet', None)
            if pwd_attr and pwd_attr.value:
                try:
                    val = int(str(pwd_attr.value))
                    if val > 0:
                        pwd_date = datetime.fromtimestamp(val / 10000000 - 11644473600)
                        days = (now - pwd_date).days
                        if 28 < days < 42:  # Expires in ~14 days
                            alert_data['password_expiring'] += 1
                except:
                    pass
        if alert_data['password_expiring'] > 0:
            alerts.append({
                'title': f'{alert_data["password_expiring"]} mot de passe expirant',
                'message': 'Mots de passe expirent dans moins de 14 jours.',
                'severity': 'warning',
                'date': now.strftime('%d/%m/%Y %H:%M')
            })

        # === 6. COMPTES ADMIN ===
        conn.search(base_dn, '(&(objectClass=user)(memberof=CN=Domain Admins,CN=Users,' + base_dn + '))', SUBTREE,
                   attributes=['cn'])
        alert_data['admin_accounts'] = len(conn.entries)
        if alert_data['admin_accounts'] > 3:
            alerts.append({
                'title': f'{alert_data["admin_accounts"]} compte(s) Domain Admins',
                'message': 'Attention: plusieurs comptes avec droits admin.',
                'severity': 'critical',
                'date': now.strftime('%d/%m/%Y %H:%M')
            })

        # === 7. GROUPES VIDES (hors système) ===
        conn.search(base_dn, '(objectClass=group)', SUBTREE,
                   attributes=['cn', 'member', 'primaryGroupToken'])
        for entry in conn.entries:
            # Exclure groupes système
            is_system = False
            token_attr = getattr(entry, 'primaryGroupToken', None)
            if token_attr and token_attr.value:
                try:
                    if int(str(token_attr.value)) in SYSTEM_GROUP_TOKENS:
                        is_system = True
                except:
                    pass
            # Vérifier membres
            has_members = False
            member_attr = getattr(entry, 'member', None)
            if member_attr and member_attr.value:
                if isinstance(member_attr.value, list):
                    has_members = len(member_attr.value) > 0
                elif isinstance(member_attr.value, str):
                    has_members = len(member_attr.value.strip()) > 0
            if not is_system and not has_members:
                alert_data['empty_groups'] += 1
        if alert_data['empty_groups'] > 0:
            alerts.append({
                'title': f'{alert_data["empty_groups"]} groupe(s) vide(s)',
                'message': 'Groupes personnalisés sans membres.',
                'severity': 'info',
                'date': now.strftime('%d/%m/%Y %H:%M')
            })

        conn.unbind()

    except Exception as e:
        flash(f'Erreur lors de la récupération des alertes: {str(e)}', 'error')

    return render_template('alerts.html', alert_data=alert_data, alerts=alerts, connected=True)


@admin_tools_bp.route('/errors')
@require_connection
def error_logs():
    """Page des logs d'erreurs."""
    import os
    from pathlib import Path

    error_log_path = Path('logs/server.log')
    errors = []

    if error_log_path.exists():
        try:
            with open(error_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                errors = [line.strip() for line in lines if 'ERROR' in line or 'Exception' in line]
                errors = errors[-50:]
        except:
            errors = ['Impossible de lire les logs']

    return render_template('errors.html', errors=errors, connected=True)


@admin_tools_bp.route('/security-audit')
@require_connection
@require_permission('admin')
def security_audit():
    """Audit de sécurité."""
    from security_audit import check_security_issues

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return render_template('security_audit.html', issues=[], stats={'critical': 0, 'high': 0, 'warning': 0, 'fixable': 0}, connected=True)

    try:
        issues = check_security_issues(conn, session.get('ad_base_dn', ''))
        conn.unbind()

        # Calculer les statistiques
        stats = {
            'critical': len([i for i in issues if i.get('severity') == 'critical']),
            'high': len([i for i in issues if i.get('severity') == 'high']),
            'warning': len([i for i in issues if i.get('severity') == 'warning']),
            'fixable': len([i for i in issues if i.get('fixable', False)])
        }

        return render_template('security_audit.html', issues=issues, stats=stats, connected=True)
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')
        return render_template('security_audit.html', issues=[], stats={'critical': 0, 'high': 0, 'warning': 0, 'fixable': 0}, connected=True)


@admin_tools_bp.route('/permissions')
@require_connection
@require_permission('admin')
def permissions_page():
    """Page de gestion des permissions."""
    from granular_permissions import get_all_groups_with_permissions, get_available_permissions, get_permission_categories

    groups = get_all_groups_with_permissions()
    all_permissions = get_available_permissions()
    categories = get_permission_categories()

    return render_template('permissions.html',
                         groups=groups,
                         permissions=all_permissions,
                         categories=categories,
                         connected=True)


@admin_tools_bp.route('/ldaps-setup')
@require_connection
@require_permission('admin')
def ldaps_setup_page():
    """Page de configuration LDAPS et certificat SSL."""
    from ldap_certificate import get_certificate_status

    cert_status = get_certificate_status()
    
    # Récupérer le domaine depuis la session
    base_dn = session.get('ad_base_dn', '')
    domain = base_dn.replace('DC=', '').replace(',', '.') if base_dn else 'local.domain'
    server = session.get('ad_server', '')

    return render_template('ldaps_setup.html',
                         cert_status=cert_status,
                         domain=domain,
                         server=server,
                         connected=True)


@admin_tools_bp.route('/api/ldaps-status')
@require_connection
@require_permission('admin')
def api_ldaps_status():
    """API: Statut du certificat LDAPS."""
    from ldap_certificate import get_certificate_status
    
    cert_status = get_certificate_status()
    return jsonify(cert_status)


@admin_tools_bp.route('/api/ldaps-create-certificate', methods=['POST'])
@require_connection
@require_permission('admin')
def api_ldaps_create_certificate():
    """API: Créer un certificat LDAPS auto-signé."""
    from ldap_certificate import create_ldaps_certificate
    
    years = request.form.get('years', 5, type=int)
    
    result = create_ldaps_certificate(years=years)
    
    return jsonify(result)


@admin_tools_bp.route('/api/ldaps-download-script')
@require_connection
@require_permission('admin')
def api_ldaps_download_script():
    """API: Télécharger le script PowerShell d'installation."""
    import os
    import tempfile
    
    # Récupérer le domaine depuis la session
    base_dn = session.get('ad_base_dn', '')
    domain = base_dn.replace('DC=', '').replace(',', '.') if base_dn else 'local.domain'
    server = session.get('ad_server', '')
    
    # Créer le script avec le domaine correct
    script_content = f'''# ==============================================================================
# Installation certificat LDAPS - AD Web Interface
# Executez ce script en PowerShell ADMINISTRATEUR sur le serveur AD ({server})
# ==============================================================================

# Verification des droits admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {{
    Write-Host "ERREUR: Executez ce script en tant qu'Administrateur!" -ForegroundColor Red
    pause
    exit 1
}}

# Domaine: {domain}
$Domain = "{domain}"
$DCName = "$env:COMPUTERNAME.$Domain"
$IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{ $_.InterfaceAlias -notlike '*Loopback*' }} | Select-Object -First 1).IPAddress

Write-Host "=== Installation Certificat LDAPS ===" -ForegroundColor Cyan
Write-Host "Domaine: $Domain"
Write-Host "Serveur: $DCName"
Write-Host "IP: $IP"
Write-Host ""

$DnsNames = @($Domain, $DCName, $IP, $env:COMPUTERNAME, "localhost")

Write-Host "Creation du certificat..." -ForegroundColor Yellow

try {{
    $cert = New-SelfSignedCertificate `
        -DnsName $DnsNames `
        -CertStoreLocation "Cert:\\LocalMachine\\My" `
        -KeyExportPolicy Exportable `
        -Provider "Microsoft RSA SChannel Cryptographic Provider" `
        -NotAfter (Get-Date).AddYears(5) `
        -KeyLength 2048 `
        -HashAlgorithm SHA256
    
    Write-Host "SUCCESS: Certificat cree!" -ForegroundColor Green
    Write-Host "Thumbprint: $($cert.Thumbprint)"
    Write-Host "Expiration: $($cert.NotAfter)"
    
    Write-Host ""
    Write-Host "Redemarrage du service AD..." -ForegroundColor Yellow
    Restart-Service NTDS -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
    
    Write-Host ""
    Write-Host "=== Installation terminee ===" -ForegroundColor Green
    Write-Host "Reconnectez-vous a l'interface web avec SSL active."
    
}} catch {{
    Write-Host "ERROR: $_" -ForegroundColor Red
}}

Read-Host "Appuyez sur Entree pour fermer"
'''
    
    # Créer un fichier temporaire
    script_path = os.path.join(tempfile.gettempdir(), 'install_ldaps_certificate.ps1')
    with open(script_path, 'w', encoding='utf-8') as f:
        f.write(script_content)
    
    return send_file(script_path,
                    as_attachment=True,
                    download_name='install_ldaps_certificate.ps1',
                    mimetype='application/octet-stream')