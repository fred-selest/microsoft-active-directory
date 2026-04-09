# update_minimal.ps1
# Mise a jour ciblee depuis GitHub - telecharge uniquement les fichiers modifies
# Fonctionne meme avec connexion lente

$ErrorActionPreference = "Stop"
$base = "https://raw.githubusercontent.com/fred-selest/microsoft-active-directory/main"
$target = "C:\AD-WebInterface"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Mise a jour minimale v1.37.11" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 1. Arreter le service
Write-Host "[1/3] Arret du service..." -ForegroundColor Yellow
try {
    & "$target\nssm\ADWebInterface.exe" stop 2>$null
    Start-Sleep -Seconds 3
    Write-Host "  OK" -ForegroundColor Green
} catch {
    Write-Host "  [INFO] Deja arrete" -ForegroundColor Yellow
}

# 2. Telecharger les fichiers modifies un par un
Write-Host "[2/3] Telechargement des fichiers..." -ForegroundColor Yellow

$files = @(
    "VERSION",
    "routes/core.py",
    "routes/main.py",
    "routes/api.py",
    "routes/admin/__init__.py",
    "routes/admin_tools.py",
    "routes/tools/laps.py",
    "routes/users/list_users.py",
    "core/security.py",
    "core/settings_manager.py",
    "templates/admin.html",
    "templates/users.html",
    "templates/connect.html",
    "templates/create_user.html",
    "templates/update.html",
    "scripts/fix_ldap_channel_binding.ps1",
    "scripts/update_from_github.ps1"
)

$ok = 0
$fail = 0
foreach ($f in $files) {
    try {
        $dir = [System.IO.Path]::GetDirectoryName("$target\$f")
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Invoke-WebRequest -Uri "$base/$f" -OutFile "$target\$f" -TimeoutSec 30
        Write-Host "  OK $f" -ForegroundColor Green
        $ok++
    } catch {
        Write-Host "  ERREUR $f : $($_.Exception.Message)" -ForegroundColor Red
        $fail++
    }
}

Write-Host ""
Write-Host "  Resultat : $ok reussi(s), $fail echoue(s)" -ForegroundColor $(if($fail -eq 0){"Green"}else{"Yellow"})

# 3. Demarrer le service
Write-Host "[3/3] Demarrage du service..." -ForegroundColor Yellow
try {
    & "$target\nssm\ADWebInterface.exe" start 2>$null
    Start-Sleep -Seconds 5
    Write-Host "  OK" -ForegroundColor Green
} catch {
    Write-Host "  [ATTENTION] Demarrage manuel necessaire" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  TERMINE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

if ($fail -gt 0) {
    Write-Host ""
    Write-Host "ATTENTION: $fail fichier(s) n'ont pas pu etre telecharges." -ForegroundColor Yellow
    Write-Host "Verifiez la connexion reseau et relancez le script." -ForegroundColor Yellow
}
