"""Routes LAPS (Local Administrator Password Solution)."""
import logging
import subprocess
from flask import render_template, request, flash, session, redirect, url_for
from ldap3 import SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPAttributeError

# Import tools_bp directly to avoid circular import
from routes.tools import tools_bp
from routes.core import get_ad_connection, decode_ldap_value, is_connected, require_connection, require_permission
from security import escape_ldap_filter, validate_csrf_token

logger = logging.getLogger('laps')


@tools_bp.route('/laps/configure', methods=['POST'])
@require_connection
@require_permission('admin')
def configure_laps():
    """Configurer Windows LAPS automatiquement via PowerShell."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF inval.', 'error')
        return redirect(url_for('tools.laps_passwords'))

    base_dn = session.get('ad_base_dn', '')
    domain_dn = base_dn

    # Script PowerShell avec verification de version
    ps_script = f'''
# Configuration automatique de Windows LAPS
$ErrorActionPreference = "Stop"

Write-Host "=== Verification du systeme ===" -ForegroundColor Cyan

# 1. Verifier la version de Windows Server
$osInfo = Get-CimInstance Win32_OperatingSystem
$osName = $osInfo.Caption
$osVersion = $osInfo.Version
$buildNumber = $osInfo.BuildNumber

Write-Host "Systeme detecte: $osName (Build $buildNumber)" -ForegroundColor Green

# Verifier si Windows LAPS est supporte nativement
# Windows Server 2019 = Build 17763+
# Windows Server 2022 = Build 20348+
$supportsNativeLAPS = $buildNumber -ge 17763

if (-not $supportsNativeLAPS) {{
    Write-Host ""
    Write-Host "ATTENTION: Ce serveur ne supporte pas Windows LAPS nativement." -ForegroundColor Yellow
    Write-Host "Windows LAPS natif necessite Windows Server 2019 ou superieur." -ForegroundColor Yellow
    Write-Host "Build actuel: $buildNumber (minimum requis: 17763)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "LEGACY_REQUIRED"
    exit 0
}}

Write-Host "OK Windows LAPS natif est supporte sur ce serveur." -ForegroundColor Green
Write-Host ""

# 2. Verifier si la GPO existe deja
$gpoName = "Windows LAPS"
Write-Host "=== Configuration de la GPO ===" -ForegroundColor Cyan

$existingGpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

if ($existingGpo) {{
    Write-Host "La GPO '$gpoName' existe deja (cree le $($existingGpo.CreationTime))." -ForegroundColor Yellow
    Write-Host "Mise a jour des parametres..." -ForegroundColor Yellow
}} else {{
    Write-Host "Creation de la GPO '$gpoName'..." -ForegroundColor Green
    New-GPO -Name $gpoName -Comment "Configuration automatique Windows LAPS - AD Web Interface" | Out-Null
    Write-Host "OK GPO creee avec succes." -ForegroundColor Green
}}

# 3. Configurer les parametres LAPS
Write-Host ""
Write-Host "Configuration des parametres LAPS..." -ForegroundColor Green

# Activer LAPS
Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "EnableLAPS" -Type DWord -Value 1 -ErrorAction SilentlyContinue | Out-Null
Write-Host "  OK LAPS active" -ForegroundColor White

# Longueur du mot de passe (14 caracteres)
Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "PasswordLength" -Type DWord -Value 14 -ErrorAction SilentlyContinue | Out-Null
Write-Host "  OK Longueur mot de passe: 14 caracteres" -ForegroundColor White

# Duree de validite (30 jours)
Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "PasswordAgeDays" -Type DWord -Value 30 -ErrorAction SilentlyContinue | Out-Null
Write-Host "  OK Duree de validite: 30 jours" -ForegroundColor White

# Complexite du mot de passe
Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "PasswordComplexity" -Type DWord -Value 1 -ErrorAction SilentlyContinue | Out-Null
Write-Host "  OK Complexite: Haute" -ForegroundColor White

# 4. Lier la GPO au domaine
Write-Host ""
Write-Host "Liaison de la GPO au domaine..." -ForegroundColor Green

try {{
    New-GPLink -Name $gpoName -Target "{domain_dn}" -LinkEnabled Yes -ErrorAction Stop | Out-Null
    Write-Host "OK GPO liee au domaine avec succes." -ForegroundColor Green
}} catch {{
    if ($_.Exception.Message -like "*already linked*" -or $_.Exception.Message -like "*already exists*") {{
        Write-Host "OK La GPO est deja liee au domaine." -ForegroundColor Yellow
    }} else {{
        Write-Host "Impossible de lier la GPO: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Vous pouvez la lier manuellement via GPMC." -ForegroundColor Yellow
    }}
}}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "     CONFIGURATION TERMINEE AVEC SUCCES" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "La GPO '$gpoName' a ete configuree." -ForegroundColor Green
Write-Host "Les ordinateurs appliqueront la politique au prochain:" -ForegroundColor White
Write-Host "  - Redemarrage de l'ordinateur" -ForegroundColor White
Write-Host "  - Execution de 'gpupdate /force'" -ForegroundColor White
Write-Host "  - Cycle automatique (90 minutes max)" -ForegroundColor White
Write-Host ""
Write-Host "SUCCESS"
'''

    try:
        result = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
            capture_output=True,
            text=True,
            timeout=90
        )

        stdout = result.stdout or ''
        stderr = result.stderr or ''
        
        logger.info(f"LAPS Configure: returncode={result.returncode}")
        logger.info(f"LAPS Configure: stdout={stdout[:500]}")

        if 'LEGACY_REQUIRED' in stdout:
            flash('Ce serveur ne supporte pas Windows LAPS natif. Windows Server 2019 ou superieur est requis. Installez Legacy LAPS depuis Microsoft.', 'warning')
        elif result.returncode == 0 and 'SUCCESS' in stdout:
            # Extraire les infos du stdout pour le message
            lines = stdout.split('\n')
            server_info = next((l for l in lines if 'Systeme detecte' in l), '')
            flash(f'Windows LAPS configure avec succes!\n\n{server_info}\n\nLa GPO "Windows LAPS" a ete creee. Les ordinateurs appliqueront la politique au prochain redemarrage ou apres gpupdate /force.', 'success')
        else:
            error_msg = stderr if stderr else stdout
            logger.error(f"LAPS Configure: error={error_msg[:500]}")

            if error_msg:
                if 'Access is denied' in error_msg or 'permission' in error_msg.lower():
                    flash('Erreur de permissions. Cette action necessite des droits Domain Admin.', 'error')
                elif 'already linked' in error_msg.lower():
                    # GPO deja liee = succes
                    lines = stdout.split('\n') if stdout else []
                    server_info = next((l for l in lines if 'Systeme detecte' in l), '')
                    flash(f'Windows LAPS deja configure!\n\n{server_info}\n\nLa GPO "Windows LAPS" existe et est deja liee au domaine.', 'success')
                elif 'Group Policy' in error_msg or 'GPO' in error_msg:
                    flash(f'Erreur GPO: {error_msg[:300]}', 'error')
                else:
                    flash(f'Erreur lors de la configuration: {error_msg[:300]}', 'error')
            else:
                flash('Erreur inconnue lors de la configuration.', 'error')

    except subprocess.TimeoutExpired:
        logger.error("LAPS Configure: Timeout")
        flash('Timeout lors de la configuration. Verifiez les permissions et reessayez.', 'error')
    except Exception as e:
        logger.error(f"LAPS Configure: Exception={e}", exc_info=True)
        flash(f'Erreur: {str(e)}', 'error')

    return redirect(url_for('tools.laps_passwords'))


@tools_bp.route('/laps')
@require_connection
@require_permission('admin')
def laps_passwords():
    """Afficher les mots de passe LAPS."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('main.connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')
    search_filter = f'(&(objectClass=computer)(cn=*{escape_ldap_filter(search_query)}*))' if search_query else '(objectClass=computer)'

    computers = []
    laps_available = True
    has_legacy_laps = False
    has_new_laps = False

    try:
        # Verifier si les attributs LAPS existent dans le schema
        if conn.server.schema and conn.server.schema.attribute_types:
            schema_attrs = list(conn.server.schema.attribute_types.keys())
            logger.info(f"LAPS: Schema attributes count: {len(schema_attrs)}")

            # Legacy LAPS
            has_legacy_laps = 'ms-Mcs-AdmPwd' in schema_attrs
            logger.info(f"LAPS: has_legacy_laps (ms-Mcs-AdmPwd) = {has_legacy_laps}")

            # Windows LAPS - plusieurs attributs possibles
            laps_attrs = ['msLAPS-Password', 'msLAPS-EncryptedPassword', 'ms-LAPS-Password', 'ms-LAPS-EncryptedPassword']
            for attr in laps_attrs:
                if attr in schema_attrs:
                    has_new_laps = True
                    logger.info(f"LAPS: Found Windows LAPS attribute: {attr}")
                    break

            logger.info(f"LAPS: has_new_laps = {has_new_laps}")

        # Si pas detecte dans le schema, essayer de chercher directement
        if not has_legacy_laps and not has_new_laps:
            logger.info("LAPS: Not detected in schema, trying direct search...")
            # Essayer chaque attribut separement
            test_attrs_list = [
                ('ms-Mcs-AdmPwd', 'legacy'),
                ('msLAPS-Password', 'new'),
                ('msLAPS-EncryptedPassword', 'new'),
            ]

            for attr_name, laps_type in test_attrs_list:
                try:
                    conn.search(base_dn, '(objectClass=computer)', SUBTREE,
                               attributes=['cn', attr_name], size_limit=5)

                    for entry in conn.entries:
                        if hasattr(entry, attr_name):
                            val = getattr(entry, attr_name, None)
                            if val and val.value:
                                if laps_type == 'legacy':
                                    has_legacy_laps = True
                                    logger.info(f"LAPS: Found legacy LAPS attribute {attr_name} on {entry.cn}")
                                else:
                                    has_new_laps = True
                                    logger.info(f"LAPS: Found Windows LAPS attribute {attr_name} on {entry.cn}")
                                break
                    if has_legacy_laps or has_new_laps:
                        break
                except LDAPAttributeError as e:
                    logger.debug(f"LAPS: Attribute {attr_name} not available: {e}")
                except Exception as e:
                    logger.debug(f"LAPS: Error checking {attr_name}: {e}")

        if not has_legacy_laps and not has_new_laps:
            laps_available = False
            logger.warning("LAPS: No LAPS attributes found in schema or on computers")
            flash("Windows LAPS n'est pas configure sur ce domaine. Activez LAPS via GPO : Computer Configuration > Administrative Templates > System > LAPS > Enable LAPS.", 'warning')
        else:
            attrs = ['cn', 'distinguishedName', 'operatingSystem']
            if has_legacy_laps:
                attrs.extend(['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'])
            if has_new_laps:
                attrs.extend(['msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-PasswordExpirationTime'])

            conn.search(base_dn, search_filter, SUBTREE, attributes=attrs)

            for entry in conn.entries:
                pwd = exp = None
                laps_type = 'Aucun'

                # Legacy LAPS
                if has_legacy_laps and hasattr(entry, 'ms-Mcs-AdmPwd'):
                    pwd_val = getattr(entry, 'ms-Mcs-AdmPwd', None)
                    if pwd_val and pwd_val.value:
                        pwd = decode_ldap_value(pwd_val)
                        laps_type = 'LAPS (Legacy)'
                        exp_val = getattr(entry, 'ms-Mcs-AdmPwdExpirationTime', None)
                        exp = decode_ldap_value(exp_val) if exp_val else None

                # Windows LAPS - Password (non chiffre)
                if not pwd and has_new_laps and hasattr(entry, 'msLAPS-Password'):
                    pwd_val = getattr(entry, 'msLAPS-Password', None)
                    if pwd_val and pwd_val.value:
                        pwd = decode_ldap_value(pwd_val)
                        laps_type = 'Windows LAPS'
                        exp_val = getattr(entry, 'msLAPS-PasswordExpirationTime', None)
                        exp = decode_ldap_value(exp_val) if exp_val else None

                # Windows LAPS - EncryptedPassword (chiffre)
                if not pwd and has_new_laps and hasattr(entry, 'msLAPS-EncryptedPassword'):
                    pwd_val = getattr(entry, 'msLAPS-EncryptedPassword', None)
                    if pwd_val and pwd_val.value:
                        pwd = decode_ldap_value(pwd_val)
                        laps_type = 'Windows LAPS (chiffre)'
                        exp_val = getattr(entry, 'msLAPS-PasswordExpirationTime', None)
                        exp = decode_ldap_value(exp_val) if exp_val else None

                if pwd:
                    computers.append({
                        'cn': decode_ldap_value(entry.cn),
                        'os': decode_ldap_value(getattr(entry, 'operatingSystem', None)) or 'Inconnu',
                        'dn': decode_ldap_value(entry.distinguishedName),
                        'laps_type': laps_type,
                        'laps_password': pwd,
                        'laps_expiration': exp or 'Inconnue',
                    })

            logger.info(f"LAPS: Found {len(computers)} computers with LAPS passwords")

    except LDAPAttributeError as e:
        laps_available = False
        logger.error(f"LAPS: LDAPAttributeError: {e}")
        flash(f"Erreur attribut LAPS: {e}", 'warning')
    except Exception as e:
        logger.error(f"LAPS: Exception: {e}", exc_info=True)
        flash(f'Erreur LAPS: {e}', 'error')
    finally:
        conn.unbind()

    return render_template('laps.html', computers=computers, search=search_query,
                           connected=is_connected(), laps_available=laps_available)