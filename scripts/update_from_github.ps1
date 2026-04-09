# update_from_github.ps1
# Mise a jour depuis GitHub sans Git
# Executer en tant qu'Administrateur sur le serveur distant
# Avec backup, validation et rollback automatique

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Mise a jour AD Web Interface depuis GitHub" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$targetDir = "C:\AD-WebInterface"
$backupDir = "$targetDir\backup_pre_update"

# 1. Arreter le service
Write-Host "[1/7] Arret du service..." -ForegroundColor Yellow
try {
    & "$targetDir\nssm\ADWebInterface.exe" stop 2>$null
    Start-Sleep -Seconds 3
    Write-Host "  OK Service arrete" -ForegroundColor Green
} catch {
    Write-Host "  [INFO] Service peut-etre deja arrete" -ForegroundColor Yellow
}

# 2. Backup des fichiers actuels
Write-Host "[2/7] Sauvegarde des fichiers actuels..." -ForegroundColor Yellow
if (Test-Path $backupDir) {
    Remove-Item $backupDir -Recurse -Force
}
$backupFolders = @("routes", "core", "templates", "scripts", "static")
$backupFiles = @("app.py", "config.py", "run.py", "_openssl_init.py", "VERSION", "requirements.txt")

foreach ($folder in $backupFolders) {
    if (Test-Path "$targetDir\$folder") {
        Copy-Item "$targetDir\$folder" "$backupDir\$folder" -Recurse -Force
    }
}
foreach ($file in $backupFiles) {
    if (Test-Path "$targetDir\$file") {
        Copy-Item "$targetDir\$file" $backupDir -Force
    }
}
Write-Host "  OK Backup cree : $backupDir" -ForegroundColor Green

# 3. Telecharger l'archive
Write-Host "[3/7] Telechargement de la derniere version..." -ForegroundColor Yellow
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$zipFile = "$env:TEMP\ad-update.zip"

if (Test-Path $zipFile) {
    Remove-Item $zipFile -Force
}

Invoke-WebRequest -Uri "https://github.com/fred-selest/microsoft-active-directory/archive/refs/heads/main.zip" -OutFile $zipFile
Write-Host "  OK Archive telecharge" -ForegroundColor Green

# 4. Extraire
Write-Host "[4/7] Extraction..." -ForegroundColor Yellow
$extractPath = "$env:TEMP\ad-update-extract"
if (Test-Path $extractPath) {
    Remove-Item $extractPath -Recurse -Force
}
Expand-Archive -Path $zipFile -DestinationPath $extractPath -Force
$sourceDir = "$extractPath\microsoft-active-directory-main"
Write-Host "  OK Archive extrait" -ForegroundColor Green

# 5. Copier les fichiers (en atomique : d'abord dans un dossier temporaire)
Write-Host "[5/7] Copie des fichiers..." -ForegroundColor Yellow
$stagingDir = "$env:TEMP\ad-update-staging"
if (Test-Path $stagingDir) {
    Remove-Item $stagingDir -Recurse -Force
}

# Copier les dossiers
foreach ($folder in $backupFolders) {
    if (Test-Path "$sourceDir\$folder") {
        Copy-Item "$sourceDir\$folder" $stagingDir -Recurse -Force
        Write-Host "  OK $folder" -ForegroundColor Green
    }
}

# Copier les fichiers racine
foreach ($file in $backupFiles) {
    if (Test-Path "$sourceDir\$file") {
        Copy-Item "$sourceDir\$file" $stagingDir -Force
        Write-Host "  OK $file" -ForegroundColor Green
    }
}

# Validation : verifier que les fichiers Python sont syntaxiquement valides
Write-Host ""
Write-Host "  Validation des fichiers Python..." -ForegroundColor Yellow
$pythonExe = "$targetDir\venv\Scripts\python.exe"
$valid = $true

foreach ($folder in $backupFolders) {
    if (Test-Path "$stagingDir\$folder") {
        $pyFiles = Get-ChildItem "$stagingDir\$folder" -Filter "*.py" -Recurse
        foreach ($pyFile in $pyFiles) {
            $relPath = $pyFile.FullName.Replace("$stagingDir\", "").Replace('\', '/')
            $result = & $pythonExe -c "import ast; ast.parse(open(r'$($pyFile.FullName)', encoding='utf-8').read()); print('OK')" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  ERREUR SYNTAXE : $relPath" -ForegroundColor Red
                $valid = $false
            }
        }
    }
}

if (-not $valid) {
    Write-Host ""
    Write-Host "[ERREUR] Des fichiers ont des erreurs de syntaxe. Annulation..." -ForegroundColor Red
    Remove-Item $stagingDir -Recurse -Force
    Write-Host "  Restauration depuis le backup..." -ForegroundColor Yellow
    foreach ($folder in $backupFolders) {
        if (Test-Path "$backupDir\$folder") {
            Copy-Item "$backupDir\$folder" $targetDir -Recurse -Force
        }
    }
    foreach ($file in $backupFiles) {
        if (Test-Path "$backupDir\$file") {
            Copy-Item "$backupDir\$file" $targetDir -Force
        }
    }
    Write-Host "  OK Restauration terminee." -ForegroundColor Green
    exit 1
}

# Copie finale : remplacer les fichiers du dossier cible
foreach ($folder in $backupFolders) {
    if (Test-Path "$stagingDir\$folder") {
        Copy-Item "$stagingDir\$folder" $targetDir -Recurse -Force
    }
}
foreach ($file in $backupFiles) {
    if (Test-Path "$stagingDir\$file") {
        Copy-Item "$stagingDir\$file" $targetDir -Force
    }
}

Write-Host "  OK Fichiers copies" -ForegroundColor Green

# 6. Test de demarrage
Write-Host "[6/7] Test de demarrage..." -ForegroundColor Yellow
$testOutput = & $pythonExe -c "from app import app; print('APP_OK')" 2>&1
if ($testOutput -match "APP_OK") {
    Write-Host "  OK Application demarre correctement" -ForegroundColor Green
} else {
    Write-Host "  [ERREUR] L'application ne demarre pas : $testOutput" -ForegroundColor Red
    Write-Host "  Restauration depuis le backup..." -ForegroundColor Yellow
    foreach ($folder in $backupFolders) {
        if (Test-Path "$backupDir\$folder") {
            Copy-Item "$backupDir\$folder" $targetDir -Recurse -Force
        }
    }
    foreach ($file in $backupFiles) {
        if (Test-Path "$backupDir\$file") {
            Copy-Item "$backupDir\$file" $targetDir -Force
        }
    }
    Write-Host "  OK Restauration terminee." -ForegroundColor Green
    exit 1
}

# Nettoyage des fichiers temporaires
Write-Host "[7/7] Nettoyage..." -ForegroundColor Yellow
Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "  OK Fichiers temporaires supprimes" -ForegroundColor Green

# Demarrer le service
Write-Host ""
Write-Host "Demarrage du service..." -ForegroundColor Yellow
try {
    & "$targetDir\nssm\ADWebInterface.exe" start 2>$null
    Start-Sleep -Seconds 5
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
Write-Host "Backup disponible dans : $backupDir" -ForegroundColor Gray
