#!/usr/bin/env python3
"""Vérifier les droits AD de testino sur les OUs."""
import os
import sys
import subprocess

os.chdir(os.path.dirname(os.path.abspath(__file__)))

AD_DOMAIN = "selest.local"
AD_USER = "testino"

print("=== VERIFICATION DROITS AD POUR: testino ===\n")

# Vérifier les OU disponibles
ps_cmd = f"""
$domain = "{AD_DOMAIN}"
$user = "{AD_USER}"
$sam = $user

# Obtenir les OU du domaine
Write-Host "--- OUs disponibles ---" -ForegroundColor Cyan
Get-ADOrganizationalUnit -Filter * | Select-Object -First 10 DistinguishedName | Format-Table -AutoSize

# Vérifier les droits de délégation sur les OU principales
Write-Host "--- Droits délégation sur OU=Users ---" -ForegroundColor Cyan
$usersOU = (Get-ADDomain).UsersContainer
$acl = Get-Acl "AD:\\$usersOU"
$access = $acl.Access | Where-Object {{ $_.IdentityReference -like "*$sam*" }}
if ($access) {{
    $access | Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType -AutoSize
}} else {{
    Write-Host "  Aucun droit délégué trouvé pour $sam sur $usersOU" -ForegroundColor Yellow
}}

Write-Host "--- Vérification membres groupes testino ---" -ForegroundColor Cyan
$groups = Get-ADPrincipalGroupMembership -Identity $sam | Select-Object -ExpandProperty Name
$groups | ForEach-Object {{ Write-Host "  - $_" }}

Write-Host "--- Droits sur CN=Users ---" -ForegroundColor Cyan
$cnUsers = "CN=Users,$((Get-ADDomain).DistinguishedName)"
$acl2 = Get-Acl "AD:\\$cnUsers"
$access2 = $acl2.Access | Where-Object {{ $_.IdentityReference -like "*$sam*" }}
if ($access2) {{
    $access2 | Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType -AutoSize
}} else {{
    Write-Host "  Aucun droit délégué trouvé pour $sam sur $cnUsers" -ForegroundColor Yellow
}}

Write-Host ""
Write-Host "=== FIN VERIFICATION ===" -ForegroundColor Green
"""

try:
    result = subprocess.run(
        ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_cmd],
        capture_output=True, text=True, timeout=30
    )
    print(result.stdout)
    if result.stderr:
        print(f"Erreurs PowerShell:\n{result.stderr}")
except Exception as e:
    print(f"Erreur: {e}")
