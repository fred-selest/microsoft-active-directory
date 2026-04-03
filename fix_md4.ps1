# ============================================================================
# SCRIPT D'INSTALLATION FINALE - SUPPORT MD4/NTLM
# ============================================================================
# Ce script configure definitivement le support MD4 pour Python 3.12+
# ============================================================================

[CmdletBinding()]
param()

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  CONFIGURATION FINALE - SUPPORT MD4/NTLM" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

$installDir = "C:\AD-WebInterface"
Set-Location $installDir

# 1. Arreter et supprimer l'ancien service
Write-Host "[1/7] Arret du service..." -ForegroundColor Yellow
net stop ADWebInterface /y 2>$null
Start-Sleep -Seconds 2

Write-Host "[2/7] Suppression de l'ancien service..." -ForegroundColor Yellow
.\nssm\nssm.exe remove ADWebInterface confirm 2>$null
Start-Sleep -Seconds 2

# 3. Recreer openssl_legacy.cnf avec la configuration CORRECTE
Write-Host "[3/7] Creation de openssl_legacy.cnf..." -ForegroundColor Yellow

$opensslContent = @"
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
"@

$opensslContent | Out-File -FilePath "$installDir\openssl_legacy.cnf" -Encoding ASCII -NoNewline
Write-Host "      Fichier cree : $installDir\openssl_legacy.cnf" -ForegroundColor Green

# 4. Definir la variable d'environnement SYSTEME OPENSSL_CONF
Write-Host "[4/7] Configuration de OPENSSL_CONF..." -ForegroundColor Yellow
[Environment]::SetEnvironmentVariable("OPENSSL_CONF", "$installDir\openssl_legacy.cnf", "Machine")
Write-Host "      OPENSSL_CONF definie au niveau systeme" -ForegroundColor Green

# 5. Installer le nouveau service
Write-Host "[5/7] Installation du nouveau service..." -ForegroundColor Yellow

$pythonExe = "$installDir\venv\Scripts\python.exe"
$runPy = "$installDir\run.py"

.\nssm\nssm.exe install ADWebInterface "$pythonExe" "$runPy"
.\nssm\nssm.exe set ADWebInterface AppDirectory "$installDir"
.\nssm\nssm.exe set ADWebInterface DisplayName "Interface Web Active Directory"
.\nssm\nssm.exe set ADWebInterface Description "Interface Web pour Microsoft Active Directory"
.\nssm\nssm.exe set ADWebInterface Start SERVICE_AUTO_START
.\nssm\nssm.exe set ADWebInterface AppEnvironmentExtra "OPENSSL_CONF=$installDir\openssl_legacy.cnf"

Write-Host "      Service installe avec OPENSSL_CONF" -ForegroundColor Green

# 6. Demarrer le service
Write-Host "[6/7] Demarrage du service..." -ForegroundColor Yellow
net start ADWebInterface

# 7. Attendre que le serveur demarre
Write-Host "[7/7] Attente du demarrage du serveur..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Verification
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "  CONFIGURATION TERMINEE" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Le support MD4/NTLM est maintenant actif pour Python 3.12+" -ForegroundColor Green
Write-Host ""
Write-Host "Testez la connexion :" -ForegroundColor White
Write-Host "  http://localhost:5000/connect" -ForegroundColor Cyan
Write-Host ""
Write-Host "Utilisez la connexion MANUELLE :" -ForegroundColor Yellow
Write-Host "  Serveur AD : 192.168.10.252" -ForegroundColor Cyan
Write-Host "  Port       : 389" -ForegroundColor Cyan
Write-Host "  Base DN    : DC=SELEST,DC=local" -ForegroundColor Cyan
Write-Host "  Identifiant: selest\admin" -ForegroundColor Cyan
Write-Host ""

pause
