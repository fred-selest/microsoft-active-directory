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
    
    # Script PowerShell avec vérification de version
    ps_script = f'''
# Configuration automatique de Windows LAPS
$ErrorActionPreference = "Stop"

Write-Host "=== Vérification du système ===" -ForegroundColor Cyan

# 1. Vérifier la version de Windows Server
$osInfo = Get-CimInstance Win32_OperatingSystem
$osName = $osInfo.Caption
$osVersion = $osInfo.Version
$buildNumber = $osInfo.BuildNumber

Write-Host "Système détecté: $osName (Build $buildNumber)" -ForegroundColor Green

# Vérifier si Windows LAPS est supporté nativement
# Windows Server 2019 = Build 17763+
# Windows Server 2022 = Build 20348+
$supportsNativeLAPS = $buildNumber -ge 17763

if (-not $supportsNativeLAPS) {{
    Write-Host ""
    Write-Host "⚠️ ATTENTION: Ce serveur ne supporte pas Windows LAPS nativement." -ForegroundColor Yellow
    Write-Host "Windows LAPS natif nécessite Windows Server 2019 ou supérieur." -ForegroundColor Yellow
    Write-Host "Build actuel: $buildNumber (minimum requis: 17763)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Options disponibles:" -ForegroundColor Cyan
    Write-Host "1. Installer Legacy LAPS (téléchargement Microsoft)" -ForegroundColor White
    Write-Host "2. Mettre à niveau vers Windows Server 2019+" -ForegroundColor White
    Write-Host ""
    Write-Host "LEGACY_REQUIRED"
    exit 0
}}

Write-Host "✓ Windows LAPS natif est supporté sur ce serveur." -ForegroundColor Green
Write-Host ""

# 2. Vérifier si le schéma AD supporte LAPS
Write-Host "=== Vérification du schéma AD ===" -ForegroundColor Cyan
try {{
    $schema = Get-ADObject -LDAPFilter "(objectClass=*)" -SearchBase (Get-ADRootDSE).schemaNamingContext -Properties * | Where-Object {{ $_.Name -like "*LAPS*" -or $_.Name -like "*AdmPwd*" }}
    
    if ($schema) {{
        Write-Host "Attributs LAPS détectés dans le schéma:" -ForegroundColor Green
        $schema | ForEach-Object {{ Write-Host "  - $($_.Name)" -ForegroundColor White }}
    }} else {{
        Write-Host "ℹ️ Aucun attribut LAPS détecté dans le schéma." -ForegroundColor Yellow
        Write-Host "Les attributs seront créés automatiquement lors de la configuration." -ForegroundColor Yellow
    }}
}} catch {{
    Write-Host "Impossible de vérifier le schéma: $($_.Exception.Message)" -ForegroundColor Yellow
}}

Write-Host ""

# 3. Vérifier si la GPO existe déjà
$gpoName = "Windows LAPS"
Write-Host "=== Configuration de la GPO ===" -ForegroundColor Cyan

$existingGpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

if ($existingGpo) {{
    Write-Host "⚠️ La GPO '$gpoName' existe déjà (créée le $($existingGpo.CreationTime))." -ForegroundColor Yellow
    Write-Host "Mise à jour des paramètres..." -ForegroundColor Yellow
}} else {{
    Write-Host "Création de la GPO '$gpoName'..." -ForegroundColor Green
    New-GPO -Name $gpoName -Comment "Configuration automatique Windows LAPS - AD Web Interface" | Out-Null
    Write-Host "✓ GPO créée avec succès." -ForegroundColor Green
}}

# 4. Configurer les paramètres LAPS
Write-Host ""
Write-Host "Configuration des paramètres LAPS..." -ForegroundColor Green

# Activer LAPS
Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "EnableLAPS" -Type DWord -Value 1 -ErrorAction SilentlyContinue | Out-Null
Write-Host "  ✓ LAPS activé" -ForegroundColor White

# Longueur du mot de passe (14 caractères)
Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "PasswordLength" -Type DWord -Value 14 -ErrorAction SilentlyContinue | Out-Null
Write-Host "  ✓ Longueur mot de passe: 14 caractères" -ForegroundColor White

# Durée de validité (30 jours)
Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "PasswordAgeDays" -Type DWord -Value 30 -ErrorAction SilentlyContinue | Out-Null
Write-Host "  ✓ Durée de validité: 30 jours" -ForegroundColor White

# Complexité du mot de passe (1 = lettres, chiffres, caractères spéciaux)
Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "PasswordComplexity" -Type DWord -Value 1 -ErrorAction SilentlyContinue | Out-Null
Write-Host "  ✓ Complexité: Haute (lettres, chiffres, spéciaux)" -ForegroundColor White

# Nom du compte administrateur (vide = Administrator par défaut)
Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "AdministratorName" -Type String -Value "" -ErrorAction SilentlyContinue | Out-Null

# 5. Lier la GPO au domaine
Write-Host ""
Write-Host "Liaison de la GPO au domaine..." -ForegroundColor Green

# Vérifier si la GPO est déjà liée via Get-GPOReport
$gpoReport = Get-GPOReport -Name $gpoName -ReportType XML
$xml = [xml]$gpoReport
$existingLinks = $xml.GPO.LinksTo | Where-Object {{ $_.SOMName -eq "{domain_dn}" }}

if (-not $existingLinks) {{
    try {{
        New-GPLink -Name $gpoName -Target "{domain_dn}" -LinkEnabled Yes | Out-Null
        Write-Host "✓ GPO liée au domaine avec succès." -ForegroundColor Green
    }} catch {{
        if ($_.Exception.Message -like "*already exists*") {{
            Write-Host "✓ La GPO est déjà liée au domaine." -ForegroundColor Yellow
        }} else {{
            throw $_
        }}
    }}
}} else {{
    Write-Host "✓ La GPO est déjà liée au domaine." -ForegroundColor Yellow
}}

Write-Host ""
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "     CONFIGURATION TERMINÉE AVEC SUCCÈS" -ForegroundColor Green
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "La GPO '$gpoName' a été créée et configurée." -ForegroundColor Green
Write-Host "Les ordinateurs appliqueront la politique au prochain:" -ForegroundColor White
Write-Host "  • Redémarrage de l'ordinateur" -ForegroundColor White
Write-Host "  • Exécution de 'gpupdate /force'" -ForegroundColor White
Write-Host "  • Cycle automatique (90 minutes max)" -ForegroundColor White
Write-Host ""
Write-Host "Pour forcer la mise à jour sur tous les ordinateurs:" -ForegroundColor Yellow
Write-Host "  Invoke-Command -ComputerName (Get-ADComputer -Filter * | Select-Object -ExpandProperty Name) -ScriptBlock {{ gpupdate /force }}" -ForegroundColor White
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
        
        logger.info(f"LAPS Configure: stdout={result.stdout}")
        
        if 'LEGACY_REQUIRED' in result.stdout:
            flash('⚠️ Ce serveur ne supporte pas Windows LAPS natif. Windows Server 2019 ou supérieur est requis. Pour les anciennes versions, installez Legacy LAPS depuis Microsoft.', 'warning')
        elif result.returncode == 0 and 'SUCCESS' in result.stdout:
            # Extraire les infos du stdout pour le message
            lines = result.stdout.split('\n')
            server_info = next((l for l in lines if 'Système détecté' in l), '')
            flash(f'✅ Windows LAPS configuré avec succès!\\n\\n{server_info}\\n\\nLa GPO "Windows LAPS" a été créée. Les ordinateurs appliqueront la politique au prochain redémarrage ou après gpupdate /force.', 'success')
        else:
            error_msg = result.stderr if result.stderr else result.stdout
            logger.error(f"LAPS Configure: error={error_msg}")
            
            if 'Access is denied' in error_msg or 'permission' in error_msg.lower():
                flash('❌ Erreur de permissions. Cette action nécessite des droits Domain Admin.', 'error')
            elif 'Group Policy' in error_msg:
                flash(f'❌ Erreur GPO: {error_msg[:300]}', 'error')
            else:
                flash(f'❌ Erreur lors de la configuration: {error_msg[:300]}', 'error')
                
    except subprocess.TimeoutExpired:
        logger.error("LAPS Configure: Timeout")
        flash('❌ Timeout lors de la configuration. Vérifiez les permissions et réessayez.', 'error')
    except Exception as e:
        logger.error(f"LAPS Configure: Exception={e}", exc_info=True)
        flash(f'❌ Erreur: {str(e)}', 'error')

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
        # Vérifier si les attributs LAPS existent dans le schéma
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

        # Si pas détecté dans le schéma, essayer de chercher directement
        if not has_legacy_laps and not has_new_laps:
            logger.info("LAPS: Not detected in schema, trying direct search...")
            # Essayer chaque attribut séparément
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
            flash("Windows LAPS n'est pas configuré sur ce domaine. Activez LAPS via GPO : Computer Configuration > Administrative Templates > System > LAPS > Enable LAPS.", 'warning')
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

                # Windows LAPS - Password (non chiffré)
                if not pwd and has_new_laps and hasattr(entry, 'msLAPS-Password'):
                    pwd_val = getattr(entry, 'msLAPS-Password', None)
                    if pwd_val and pwd_val.value:
                        pwd = decode_ldap_value(pwd_val)
                        laps_type = 'Windows LAPS'
                        exp_val = getattr(entry, 'msLAPS-PasswordExpirationTime', None)
                        exp = decode_ldap_value(exp_val) if exp_val else None

                # Windows LAPS - EncryptedPassword (chiffré)
                if not pwd and has_new_laps and hasattr(entry, 'msLAPS-EncryptedPassword'):
                    pwd_val = getattr(entry, 'msLAPS-EncryptedPassword', None)
                    if pwd_val and pwd_val.value:
                        pwd = decode_ldap_value(pwd_val)
                        laps_type = 'Windows LAPS (chiffré)'
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
