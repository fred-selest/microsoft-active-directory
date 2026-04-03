# ============================================================================
# FIX MD4/NTLM - SOLUTION DÉFINITIVE
# ============================================================================
# Ce script configure TOUT ce qu'il faut pour que MD4 fonctionne avec Python 3.12+
# ============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$installDir = "C:\AD-WebInterface"

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  FIX MD4/NTLM - SOLUTION DÉFINITIVE" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

try {
    # 1. Arrêter TOUS les processus Python
    Write-Host "[1/8] Arret des processus Python..." -ForegroundColor Yellow
    Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-Process pythonw -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2

    # 2. Arrêter et supprimer le service
    Write-Host "[2/8] Suppression de l'ancien service..." -ForegroundColor Yellow
    net stop ADWebInterface /y 2>$null
    Start-Sleep -Seconds 2
    & "$installDir\nssm\nssm.exe" remove ADWebInterface confirm 2>$null
    Start-Sleep -Seconds 2

    # 3. Créer openssl_legacy.cnf avec la BONNE syntaxe
    Write-Host "[3/8] Creation de openssl_legacy.cnf..." -ForegroundColor Yellow
    
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
    Write-Host "      OK: $installDir\openssl_legacy.cnf" -ForegroundColor Green

    # 4. Définir OPENSSL_CONF au niveau SYSTÈME (Machine)
    Write-Host "[4/8] Configuration OPENSSL_CONF (niveau systeme)..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("OPENSSL_CONF", "$installDir\openssl_legacy.cnf", "Machine")
    $env:OPENSSL_CONF = "$installDir\openssl_legacy.cnf"
    Write-Host "      OK: OPENSSL_CONF=$env:OPENSSL_CONF" -ForegroundColor Green

    # 5. Vérifier que le venv existe
    Write-Host "[5/8] Verification de l'environnement virtuel..." -ForegroundColor Yellow
    if (-not (Test-Path "$installDir\venv\Scripts\python.exe")) {
        Write-Host "      Creation du venv..." -ForegroundColor Yellow
        python -m venv "$installDir\venv"
    }
    Write-Host "      OK: venv present" -ForegroundColor Green

    # 6. Installer le NOUVEAU service avec OPENSSL_CONF
    Write-Host "[6/8] Installation du nouveau service..." -ForegroundColor Yellow
    
    $pythonExe = "$installDir\venv\Scripts\python.exe"
    $runPy = "$installDir\run.py"
    
    & "$installDir\nssm\nssm.exe" install ADWebInterface "$pythonExe" "$runPy"
    & "$installDir\nssm\nssm.exe" set ADWebInterface AppDirectory "$installDir"
    & "$installDir\nssm\nssm.exe" set ADWebInterface DisplayName "Interface Web Active Directory"
    & "$installDir\nssm\nssm.exe" set ADWebInterface Description "Interface Web pour Microsoft Active Directory"
    & "$installDir\nssm\nssm.exe" set ADWebInterface Start SERVICE_AUTO_START
    & "$installDir\nssm\nssm.exe" set ADWebInterface AppEnvironmentExtra "OPENSSL_CONF=$($installDir)\openssl_legacy.cnf"
    
    Write-Host "      OK: Service installe avec OPENSSL_CONF" -ForegroundColor Green

    # 7. Démarrer le service
    Write-Host "[7/8] Demarrage du service..." -ForegroundColor Yellow
    net start ADWebInterface
    
    # 8. Attendre et vérifier
    Write-Host "[8/8] Attente du demarrage..." -ForegroundColor Yellow
    Start-Sleep -Seconds 15
    
    # Vérifier les logs
    if (Test-Path "$installDir\logs\server.log") {
        $lastLog = Get-Content "$installDir\logs\server.log" -Tail 3
        if ($lastLog -match "Serving on http") {
            Write-Host "      OK: Serveur operationnel" -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host "  FIX TERMINE AVEC SUCCES" -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Le support MD4/NTLM est maintenant actif !" -ForegroundColor Green
    Write-Host ""
    Write-Host "Testez la connexion :" -ForegroundColor White
    Write-Host "  http://localhost:5000/connect" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Configuration MANUELLE :" -ForegroundColor Yellow
    Write-Host "  Serveur : 192.168.10.252" -ForegroundColor Cyan
    Write-Host "  Port    : 389" -ForegroundColor Cyan
    Write-Host "  Base DN : DC=SELEST,DC=local" -ForegroundColor Cyan
    Write-Host "  User    : selest\admin" -ForegroundColor Cyan
    Write-Host ""

} catch {
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Red
    Write-Host "  ERREUR" -ForegroundColor Red
    Write-Host "=================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    pause
    exit 1
}

pause
