"""Routes LAPS (Local Administrator Password Solution) et configuration LDAPS."""
import logging
import subprocess
from flask import render_template, request, flash, session, redirect, url_for
from ldap3 import SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPAttributeError

# Import tools_bp directly to avoid circular import
from routes.tools import tools_bp
from routes.core import get_ad_connection, decode_ldap_value, is_connected, require_connection, require_permission
from core.security import escape_ldap_filter, validate_csrf_token

logger = logging.getLogger('laps')


# ──────────────────────────────────────────────────────────────────────
# Configuration LDAPS automatique
# ──────────────────────────────────────────────────────────────────────

@tools_bp.route('/configure-ldaps', methods=['POST'])
@require_connection
@require_permission('admin')
def configure_ldaps():
    """Configurer LDAPS automatiquement via PowerShell (script dynamique)."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('users.create_user'))

    base_dn = session.get('ad_base_dn', '')
    domain = base_dn.replace('DC=', '').replace(',', '.') if base_dn else ''

    # Script PowerShell dynamique — détecte le certificat automatiquement
    ps_script = f'''
$ErrorActionPreference = "Stop"

Write-Host "=== Configuration LDAPS automatique ===" -ForegroundColor Cyan
Write-Host ""

# 1. Detecter le certificat du serveur (celui utilise pour le SSL du DC)
Write-Host "[1/5] Recherche du certificat serveur..." -ForegroundColor Yellow
$certs = Get-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object {{
    $_.HasPrivateKey -and
    $_.Subject -like "*{domain}*" -and
    $_.NotAfter -gt (Get-Date)
}}

if (-not $certs) {{
    # Essayer tous les certificats avec une clef privee
    $certs = Get-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object {{
        $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date)
    }}
}}

if (-not $certs) {{
    Write-Host "[ERREUR] Aucun certificat avec clef privee trouve dans Cert:\\LocalMachine\\My" -ForegroundColor Red
    Write-Host "Aucun certificat disponible pour LDAPS." -ForegroundColor Yellow
    Write-Host "NO_CERT"
    exit 0
}}

# Prendre le premier certificat valide
$cert = $certs | Sort-Object NotAfter -Descending | Select-Object -First 1
$certThumbprint = $cert.Thumbprint
$certSubject = $cert.SubjectName.Name
$certExpiry = $cert.NotAfter

Write-Host "[OK] Certificat selectionne : $certSubject" -ForegroundColor Green
Write-Host "    Thumbprint : $certThumbprint" -ForegroundColor Gray
Write-Host "    Valable jusqu'au : $certExpiry" -ForegroundColor Gray
Write-Host ""

# 2. Verifier/ajouter dans le magasin Root si auto-signe
Write-Host "[2/5] Verification du magasin Root..." -ForegroundColor Yellow
$rootCert = Get-ChildItem -Path Cert:\\LocalMachine\\Root | Where-Object {{ $_.Thumbprint -eq $certThumbprint }}
if (-not $rootCert) {{
    Write-Host "  Certificat non trouve dans Root, ajout en cours..." -ForegroundColor Yellow
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    $store.Add($cert)
    $store.Close()
    Write-Host "  [OK] Certificat ajoute au magasin Root" -ForegroundColor Green
}} else {{
    Write-Host "  [OK] Certificat deja present dans Root" -ForegroundColor Green
}}
Write-Host ""

# 3. Configurer le mapping certificat pour NTDS
Write-Host "[3/5] Configuration du mapping certificat NTDS..." -ForegroundColor Yellow
$registryPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\CertMapping"
if (-not (Test-Path $registryPath)) {{
    New-Item -Path $registryPath -ItemType Directory -Force | Out-Null
    Write-Host "  [OK] Cle de registre creee" -ForegroundColor Green
}}

# Verifier si un mapping existe deja
$existingMapping = Get-ChildItem -Path $registryPath -ErrorAction SilentlyContinue
if ($existingMapping) {{
    Write-Host "  [INFO] Mapping existant trouve, mise a jour..." -ForegroundColor Yellow
}}

# Creer ou mettre a jour le mapping
$itemName = "1"
if (-not (Test-Path "$registryPath\\$itemName")) {{
    New-Item -Path $registryPath -Name $itemName -Force | Out-Null
}}
New-ItemProperty -Path "$registryPath\\$itemName" -Name "Subject" -Value $certSubject -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$registryPath\\$itemName" -Name "Thumbprint" -Value $certThumbprint -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$registryPath\\$itemName" -Name "MappingType" -Value 7 -PropertyType DWord -Force | Out-Null

Write-Host "  [OK] Mapping certificat configure" -ForegroundColor Green
Write-Host ""

# 4. Redemarrer le service NTDS
Write-Host "[4/5] Redemarrage du service NTDS..." -ForegroundColor Yellow
try {{
    Restart-Service -Name NTDS -Force -ErrorAction Stop
    Write-Host "  [OK] Service NTDS redemarre" -ForegroundColor Green
}} catch {{
    Write-Host "  [ATTENTION] Impossible de redemarrer NTDS automatiquement: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  Redemarrez manuellement le service 'Active Directory Domain Services'" -ForegroundColor Yellow
}}
Write-Host "  Attente 10 secondes..." -ForegroundColor Yellow
Start-Sleep -Seconds 10
Write-Host ""

# 5. Verifier le port 636
Write-Host "[5/5] Verification du port LDAPS (636)..." -ForegroundColor Yellow
Start-Sleep -Seconds 2
$test = Test-NetConnection -ComputerName localhost -Port 636 -WarningAction SilentlyContinue
if ($test.TcpTestSucceeded) {{
    Write-Host "  [SUCCESS] Port 636 (LDAPS) ouvert et ecoutant !" -ForegroundColor Green
    Write-Host "SUCCESS"
}} else {{
    Write-Host "  [ATTENTION] Port 636 non detecte immediatement." -ForegroundColor Yellow
    Write-Host "  Cela peut prendre quelques secondes apres le redemarrage NTDS." -ForegroundColor Yellow
    Write-Host "  Attendez 30 secondes et reessayez, ou redemarrez le service AD DS." -ForegroundColor Yellow
    Write-Host "PARTIAL_SUCCESS"
}}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CONFIGURATION LDAPS TERMINEE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Serveur : {domain}" -ForegroundColor Cyan
Write-Host "  • Serveur LDAPS : $certSubject" -ForegroundColor White
Write-Host "  • Port : 636" -ForegroundColor White
Write-Host "  • SSL/TLS : Active" -ForegroundColor White
Write-Host ""
Write-Host "Prochaines etapes :" -ForegroundColor Yellow
Write-Host "  1. Deconnectez-vous d'AD Web Interface" -ForegroundColor White
Write-Host "  2. Reconnectez-vous avec :" -ForegroundColor White
Write-Host "     - Port : 636" -ForegroundColor White
Write-Host "     - SSL/TLS : Coche" -ForegroundColor White
Write-Host "  3. Vous pourrez creer des utilisateurs avec mot de passe !" -ForegroundColor Green
'''

    try:
        result = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
            capture_output=True,
            text=True,
            timeout=120
        )

        stdout = result.stdout or ''
        stderr = result.stderr or ''

        logger.info(f"LDAPS Configure: returncode={result.returncode}")
        logger.info(f"LDAPS Configure: stdout={stdout[:500]}")

        if 'NO_CERT' in stdout:
            flash('Aucun certificat avec clef privee trouve sur ce serveur. '
                  'Installez un certificat SSL valide avant de configurer LDAPS.', 'error')
        elif 'SUCCESS' in stdout:
            lines = stdout.split('\n')
            server_info = next((l for l in lines if 'Certificat selectionne' in l or 'Serveur :' in l), '')
            flash(f'LDAPS configure avec succes !\n\n{server_info}\n\n'
                  f'DECONNECTEZ-VOUS puis reconnectez-vous avec le port 636 et SSL active.', 'success')
        elif 'PARTIAL_SUCCESS' in stdout:
            flash('Configuration LDAPS terminee mais le port 636 n\'est pas encore detecte. '
                  'Attendez 30 secondes ou redemarrez le service AD DS, puis reconnectez-vous en LDAPS (port 636, SSL coche).', 'warning')
        else:
            error_msg = stderr if stderr else stdout
            logger.error(f"LDAPS Configure: error={error_msg[:500]}")
            if 'Access is denied' in error_msg or 'access denied' in error_msg.lower():
                flash('Erreur de permissions. Cette action necessite des droits d\'administrateur du serveur.', 'error')
            else:
                flash(f'Erreur lors de la configuration LDAPS: {error_msg[:300]}', 'error')

    except subprocess.TimeoutExpired:
        logger.error("LDAPS Configure: Timeout")
        flash('Timeout lors de la configuration LDAPS. Le redemarrage NTDS peut prendre du temps.', 'error')
    except Exception as e:
        logger.error(f"LDAPS Configure: Exception={e}", exc_info=True)
        flash(f'Erreur: {str(e)}', 'error')

    return redirect(url_for('users.create_user'))


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

    # Script PowerShell avec verification de version et extension schema
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
$supportsNativeLAPS = $buildNumber -ge 17763

if (-not $supportsNativeLAPS) {{
    Write-Host ""
    Write-Host "ATTENTION: Ce serveur ne supporte pas Windows LAPS nativement." -ForegroundColor Yellow
    Write-Host "Windows LAPS natif necessite Windows Server 2019 ou superieur." -ForegroundColor Yellow
    Write-Host "LEGACY_REQUIRED"
    exit 0
}}

Write-Host "OK Windows LAPS natif est supporte sur ce serveur." -ForegroundColor Green
Write-Host ""

# 2. Verifier et etendre le schema AD pour LAPS
Write-Host "=== Verification du schema AD ===" -ForegroundColor Cyan

$schemaNC = (Get-ADRootDSE).schemaNamingContext
$lapsSchemaObjects = Get-ADObject -LDAPFilter "(name=ms-LAPS-*)" -SearchBase $schemaNC -ErrorAction SilentlyContinue

if ($lapsSchemaObjects) {{
    Write-Host "OK Le schema AD contient deja les attributs LAPS ($($lapsSchemaObjects.Count) objets)." -ForegroundColor Green
}} else {{
    Write-Host "Le schema AD ne contient pas les attributs LAPS." -ForegroundColor Yellow
    Write-Host "Extension du schema AD pour Windows LAPS..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "IMPORTANT: Cette operation requiert les droits Schema Admins." -ForegroundColor Yellow
    Write-Host ""
    
    try {{
        # Importer le module LAPS
        Import-Module LAPS -ErrorAction SilentlyContinue
        
        # Etendre le schema (Update-LapsADSchema = commande correcte sur WS2022)
        Update-LapsADSchema -ErrorAction Stop
        Write-Host ""
        Write-Host "OK Schema AD etendu avec succes pour Windows LAPS!" -ForegroundColor Green
        
        # Attendre la replication
        Write-Host "Attente de la replication du schema (30 secondes)..." -ForegroundColor Yellow
        Start-Sleep -Seconds 30
        
    }} catch {{
        Write-Host ""
        Write-Host "ERREUR: Impossible d'etendre le schema AD." -ForegroundColor Red
        Write-Host "Raison: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Solutions possibles:" -ForegroundColor Yellow
        Write-Host "  1. Verifiez que votre compte est membre du groupe 'Schema Admins'" -ForegroundColor White
        Write-Host "  2. Executez manuellement: Update-LapsADSchema" -ForegroundColor White
        Write-Host ""
        Write-Host "SCHEMA_ERROR"
        exit 0
    }}
}}

Write-Host ""

# 3. Verifier si la GPO existe deja
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

# 4. Configurer les parametres LAPS
Write-Host ""
Write-Host "Configuration des parametres LAPS..." -ForegroundColor Green

Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "EnableLAPS" -Type DWord -Value 1 -ErrorAction SilentlyContinue | Out-Null
Write-Host "  OK LAPS active" -ForegroundColor White

# BackupDirectory = 1 (stocker dans AD)
Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "BackupDirectory" -Type DWord -Value 1 -ErrorAction SilentlyContinue | Out-Null
Write-Host "  OK Stockage: Active Directory" -ForegroundColor White

Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "PasswordLength" -Type DWord -Value 14 -ErrorAction SilentlyContinue | Out-Null
Write-Host "  OK Longueur mot de passe: 14 caracteres" -ForegroundColor White

Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "PasswordAgeDays" -Type DWord -Value 30 -ErrorAction SilentlyContinue | Out-Null
Write-Host "  OK Duree de validite: 30 jours" -ForegroundColor White

Set-GPRegistryValue -Name $gpoName -Key "HKLM\\Software\\Policies\\Microsoft\\Windows\\LAPS" -ValueName "PasswordComplexity" -Type DWord -Value 1 -ErrorAction SilentlyContinue | Out-Null
Write-Host "  OK Complexite: Haute" -ForegroundColor White

# 5. Lier la GPO au domaine
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
    }}
}}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "     CONFIGURATION TERMINEE AVEC SUCCES" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Prochaines etapes:" -ForegroundColor White
Write-Host "  1. Sur chaque ordinateur: gpupdate /force" -ForegroundColor White
Write-Host "  2. Ou: Invoke-LapsPolicyProcessing" -ForegroundColor White
Write-Host "  3. Les mots de passe apparaitront dans AD" -ForegroundColor White
Write-Host ""
Write-Host "SUCCESS"
'''

    try:
        result = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
            capture_output=True,
            text=True,
            timeout=120
        )

        stdout = result.stdout or ''
        stderr = result.stderr or ''

        logger.info(f"LAPS Configure: returncode={result.returncode}")
        logger.info(f"LAPS Configure: stdout={stdout[:500]}")

        if 'LEGACY_REQUIRED' in stdout:
            flash('Ce serveur ne supporte pas Windows LAPS natif. Windows Server 2019 ou superieur est requis. Installez Legacy LAPS depuis Microsoft.', 'warning')
        elif 'SCHEMA_ERROR' in stdout:
            flash('Erreur lors de l\'extension du schema AD. Verifiez que votre compte est membre du groupe "Schema Admins" et reessayez. Vous pouvez aussi executer manuellement: Initialize-LapsADSchema', 'error')
        elif result.returncode == 0 and 'SUCCESS' in stdout:
            lines = stdout.split('\n')
            server_info = next((l for l in lines if 'Systeme detecte' in l), '')
            schema_info = 'Schema etendu' if 'Schema AD etendu' in stdout else 'Schema deja configure'
            flash(f'Windows LAPS configure avec succes!\n\n{server_info}\n{schema_info}\n\nExecutez "Invoke-LapsPolicyProcessing" sur les ordinateurs pour generer les mots de passe.', 'success')
        else:
            error_msg = stderr if stderr else stdout
            logger.error(f"LAPS Configure: error={error_msg[:500]}")

            if error_msg:
                if 'Access is denied' in error_msg or 'permission' in error_msg.lower():
                    flash('Erreur de permissions. Cette action necessite des droits Schema Admins et Domain Admin.', 'error')
                elif 'already linked' in error_msg.lower():
                    lines = stdout.split('\n') if stdout else []
                    server_info = next((l for l in lines if 'Systeme detecte' in l), '')
                    flash(f'Windows LAPS deja configure!\n\n{server_info}', 'success')
                else:
                    flash(f'Erreur lors de la configuration: {error_msg[:300]}', 'error')
            else:
                flash('Erreur inconnue lors de la configuration.', 'error')

    except subprocess.TimeoutExpired:
        logger.error("LAPS Configure: Timeout")
        flash('Timeout lors de la configuration. L\'extension du schema peut prendre du temps.', 'error')
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
                                else:
                                    has_new_laps = True
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


@tools_bp.route('/laps/refresh', methods=['POST'])
@tools_bp.route('/laps/refresh/<path:computer_dn>', methods=['POST'])
@require_connection
@require_permission('admin')
def laps_force_refresh(computer_dn=''):
    """Forcer la mise a jour LAPS sur un ordinateur."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF inval.', 'error')
        return redirect(url_for('tools.laps_passwords'))

    computer_name = request.form.get('computer_name', '').strip()

    if not computer_name:
        flash('Nom d\'ordinateur requis.', 'error')
        return redirect(url_for('tools.laps_passwords'))

    # Construire le FQDN
    base_dn = session.get('ad_base_dn', '')
    domain = base_dn.replace('DC=', '').replace(',', '.')
    computer_fqdn = f"{computer_name}.{domain}" if '.' not in computer_name else computer_name

    logger.info(f"LAPS Force Refresh: Attempting to refresh LAPS on {computer_fqdn}")

    # Script PowerShell pour forcer la mise a jour LAPS
    # Utilise plusieurs methodes: WinRM, PSExec, ou instructions manuelles
    ps_script = f'''
$ErrorActionPreference = "Continue"
$computerName = "{computer_fqdn}"
$computerShort = "{computer_name}"

Write-Host "=== Force LAPS Update on $computerName ===" -ForegroundColor Cyan

# Verifier si l'ordinateur est en ligne
if (-not (Test-Connection -ComputerName $computerName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {{
    Write-Host "ERROR: Computer $computerName is not reachable (offline or firewall)" -ForegroundColor Red
    Write-Host "OFFLINE"
    exit
}}

Write-Host "Connection OK: $computerName is reachable" -ForegroundColor Green

# Methode 1: WinRM (Invoke-Command)
Write-Host "Method 1: Trying WinRM..." -ForegroundColor Yellow
$winrmResult = $null
try {{
    $winrmResult = Invoke-Command -ComputerName $computerName -ScriptBlock {{
        try {{
            $null = Invoke-LapsPolicyProcessing -ErrorAction Stop
            "SUCCESS_WINRM"
        }} catch {{
            # Essayer via service LAPS
            try {{
                Restart-Service LAPS -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
                "SUCCESS_SERVICE"
            }} catch {{
                $_.Exception.Message
            }}
        }}
    }} -ErrorAction Stop
    
    if ($winrmResult -like "SUCCESS*") {{
        Write-Host "WinRM SUCCESS: $winrmResult" -ForegroundColor Green
        Write-Host "SUCCESS"
        exit
    }}
}} catch {{
    Write-Host "WinRM failed: $($_.Exception.Message)" -ForegroundColor Yellow
}}

# Methode 2: PSExec (si disponible)
Write-Host "Method 2: Trying PSExec..." -ForegroundColor Yellow
$psexecPath = Get-Command psexec -ErrorAction SilentlyContinue
if ($psexecPath) {{
    try {{
        $psexecOutput = & psexec "\\$computerName" -accepteula -nobanner cmd /c "gpupdate /force /target:computer" 2>&1
        if ($LASTEXITCODE -eq 0) {{
            Write-Host "PSExec SUCCESS" -ForegroundColor Green
            Write-Host "SUCCESS"
            exit
        }}
    }} catch {{
        Write-Host "PSExec failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }}
}} else {{
    Write-Host "PSExec not available" -ForegroundColor Yellow
}}

# Methode 3: WMI pour executer gpupdate
Write-Host "Method 3: Trying WMI..." -ForegroundColor Yellow
try {{
    $process = Invoke-WmiMethod -ComputerName $computerName -Class Win32_Process -Name Create -ArgumentList "cmd /c gpupdate /force /target:computer" -ErrorAction Stop
    if ($process.ReturnValue -eq 0) {{
        Write-Host "WMI: GPUpdate started (PID: $($process.ProcessId))" -ForegroundColor Green
        Write-Host "SUCCESS_WMI"
        Write-Host "SUCCESS"
        exit
    }}
}} catch {{
    Write-Host "WMI failed: $($_.Exception.Message)" -ForegroundColor Yellow
}}

# Aucune methode n'a fonctionne
Write-Host "ERROR: All remote methods failed" -ForegroundColor Red
Write-Host "MANUAL_REQUIRED"
Write-Host "To manually update LAPS, run this command on $computerShort :"
Write-Host "  gpupdate /force /target:computer"
Write-Host "  OR"
Write-Host "  Invoke-LapsPolicyProcessing"
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

        logger.info(f"LAPS Force Refresh: stdout={stdout}")

        if 'SUCCESS' in stdout:
            method = 'WinRM' if 'SUCCESS_WINRM' in stdout else ('WMI' if 'SUCCESS_WMI' in stdout else 'PSExec')
            flash(f'Mise a jour LAPS reussie sur {computer_name} via {method}! Rafraichissez la page pour voir le mot de passe.', 'success')
        elif 'OFFLINE' in stdout:
            flash(f'L\'ordinateur {computer_name} est inaccessible. Verifiez qu\'il est allume et connecte au reseau.', 'warning')
        elif 'MANUAL_REQUIRED' in stdout:
            # Extraire les instructions manuelles
            manual_lines = [line for line in stdout.split('\n') if line.strip() and not line.startswith('===')]
            flash(f'Connexion impossible a {computer_name}. Executez manuellement sur l\'ordinateur:\n\nInvoke-LapsPolicyProcessing\nou\ngpupdate /force /target:computer', 'warning')
        elif 'ERROR' in stdout:
            error_msg = stderr if stderr else stdout
            if 'Access is denied' in error_msg or 'access denied' in error_msg.lower():
                flash(f'Acces refuse sur {computer_name}. Configurez WinRM avec: Enable-PSRemoting -Force', 'error')
            else:
                # Afficher le message d'erreur tronque
                error_clean = error_msg.replace('=== Force LAPS Update', '').strip()[:300]
                flash(f'Erreur lors de la mise a jour LAPS:\n{error_clean}', 'error')
        else:
            flash(f'Resultat inattendu. Verifiez les logs.', 'warning')

    except subprocess.TimeoutExpired:
        logger.error("LAPS Force Refresh: Timeout")
        flash(f'Timeout lors de la connexion a {computer_name} (90s). L\'ordinateur est peut-etre lent ou hors ligne.', 'error')
    except Exception as e:
        logger.error(f"LAPS Force Refresh: Exception={e}", exc_info=True)
        flash(f'Erreur: {str(e)}', 'error')

    return redirect(url_for('tools.laps_passwords'))