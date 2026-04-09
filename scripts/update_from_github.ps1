# update_from_github.ps1
# Mise a jour depuis GitHub sans Git
# Executer en tant qu'Administrateur sur le serveur distant

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Mise a jour AD Web Interface depuis GitHub" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Arreter le service
Write-Host "[1/6] Arret du service..." -ForegroundColor Yellow
try {
    & "$PSScriptRoot\..\nssm\ADWebInterface.exe" stop 2>$null
    Start-Sleep -Seconds 3
    Write-Host "  OK Service arrete" -ForegroundColor Green
} catch {
    Write-Host "  [ATTENTION] Service peut-etre deja arrete" -ForegroundColor Yellow
}

# 2. Telecharger l'archive
Write-Host "[2/6] Telechargement de la derniere version..." -ForegroundColor Yellow
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$zipFile = "$env:TEMP\ad-update.zip"

if (Test-Path $zipFile) {
    Remove-Item $zipFile -Force
}

Invoke-WebRequest -Uri "https://github.com/fred-selest/microsoft-active-directory/archive/refs/heads/main.zip" -OutFile $zipFile
Write-Host "  OK Archive telecharge" -ForegroundColor Green

# 3. Extraire
Write-Host "[3/6] Extraction..." -ForegroundColor Yellow
$extractPath = "$env:TEMP\ad-update-extract"
if (Test-Path $extractPath) {
    Remove-Item $extractPath -Recurse -Force
}
Expand-Archive -Path $zipFile -DestinationPath $extractPath -Force
$sourceDir = "$extractPath\microsoft-active-directory-main"
Write-Host "  OK Archive extrait" -ForegroundColor Green

# 4. Copier les fichiers
Write-Host "[4/6] Copie des fichiers..." -ForegroundColor Yellow
$targetDir = "C:\AD-WebInterface"

# Dossiers a copier
$folders = @("routes", "core", "templates", "scripts", "static")
foreach ($folder in $folders) {
    if (Test-Path "$sourceDir\$folder") {
        Copy-Item "$sourceDir\$folder" $targetDir -Recurse -Force
        Write-Host "  OK $folder" -ForegroundColor Green
    }
}

# Fichiers racine importants
$rootFiles = @("app.py", "config.py", "run.py", "_openssl_init.py", "VERSION", "requirements.txt")
foreach ($file in $rootFiles) {
    if (Test-Path "$sourceDir\$file") {
        Copy-Item "$sourceDir\$file" $targetDir -Force
        Write-Host "  OK $file" -ForegroundColor Green
    }
}

# 5. Nettoyage
Write-Host "[5/6] Nettoyage..." -ForegroundColor Yellow
Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "  OK Fichiers temporaires supprimes" -ForegroundColor Green

# 6. Redemarrer le service
Write-Host "[6/6] Demarrage du service..." -ForegroundColor Yellow
try {
    & "$PSScriptRoot\..\nssm\ADWebInterface.exe" start 2>$null
    Start-Sleep -Seconds 3
    Write-Host "  OK Service demarre" -ForegroundColor Green
} catch {
    Write-Host "  [ATTENTION] Demarrage echoue, demarrez manuellement" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  MISE A JOUR TERMINEE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Redemarrez votre navigateur et reconnectez-vous." -ForegroundColor Cyan
