# sync_check.ps1
# Rapport de derive entre un serveur de production et GitHub.
# Compare le manifeste local (data/update_manifest.json) avec la liste GitHub.
#
# Usage:
#   .\sync_check.ps1
#   .\sync_check.ps1 -AppDir "D:\AD-WebInterface"
#   .\sync_check.ps1 -OutputJson "C:\Temp\drift_report.json"
#
# Codes de retour:
#   0 = synchronise
#   1 = derive detectee
#   2 = erreur (connexion, manifeste manquant, etc.)

param(
    [string]$AppDir = "C:\AD-WebInterface",
    [string]$OutputJson = "",
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$GITHUB_REPO   = "fred-selest/microsoft-active-directory"
$GITHUB_BRANCH = "main"
$API_BASE      = "https://api.github.com/repos/$GITHUB_REPO"
$RAW_BASE      = "https://raw.githubusercontent.com/$GITHUB_REPO/$GITHUB_BRANCH"
$MANIFEST_PATH = Join-Path $AppDir "data\update_manifest.json"
$VERSION_PATH  = Join-Path $AppDir "VERSION"

$PRESERVE = @('.env', 'logs', 'data', 'venv', '__pycache__', '.git', '.github')

function Write-Status($msg, $color = "Cyan") {
    if (-not $Quiet) { Write-Host $msg -ForegroundColor $color }
}

function Should-Skip($path) {
    foreach ($p in $PRESERVE) {
        if ($path -like "$p*" -or $path -like "*/$p/*" -or $path -eq $p) { return $true }
    }
    return $false
}

# -- En-tete ------------------------------------------------------------------
Write-Status ""
Write-Status "=============================================" "White"
Write-Status "  RAPPORT DE DERIVE - AD Web Interface" "White"
Write-Status "=============================================" "White"
Write-Status "  Repertoire : $AppDir"
Write-Status "  Date       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Status "=============================================`n" "White"

# -- Version locale -----------------------------------------------------------
$localVersion = "inconnue"
if (Test-Path $VERSION_PATH) {
    $localVersion = (Get-Content $VERSION_PATH -Raw).Trim()
}
Write-Status "Version locale : $localVersion"

# -- Version GitHub -----------------------------------------------------------
try {
    $remoteVersion = (Invoke-WebRequest -Uri "$RAW_BASE/VERSION" -UseBasicParsing -TimeoutSec 10).Content.Trim()
    Write-Status "Version GitHub : $remoteVersion"
} catch {
    Write-Host "ERREUR: Impossible de contacter GitHub: $_" -ForegroundColor Red
    exit 2
}

if ($localVersion -eq $remoteVersion) {
    Write-Status "`n[OK] Versions identiques ($localVersion)" "Green"
} else {
    Write-Host "`n[!] Version differente : local=$localVersion, GitHub=$remoteVersion" -ForegroundColor Yellow
}

# -- Chargement du manifeste local --------------------------------------------
if (-not (Test-Path $MANIFEST_PATH)) {
    Write-Host "`n[!] ATTENTION: Pas de manifeste local ($MANIFEST_PATH)" -ForegroundColor Yellow
    Write-Host "    Ce serveur n'a pas encore ete mis a jour via le systeme automatique." -ForegroundColor Yellow
    Write-Host "    Impossible de detecter les derives fichier par fichier." -ForegroundColor Yellow
    if ($localVersion -ne $remoteVersion) { exit 1 } else { exit 0 }
}

try {
    $localManifest = Get-Content $MANIFEST_PATH -Raw | ConvertFrom-Json
} catch {
    Write-Host "ERREUR: Impossible de lire $MANIFEST_PATH : $_" -ForegroundColor Red
    exit 2
}

$localHash = @{}
$localManifest.PSObject.Properties | ForEach-Object { $localHash[$_.Name] = $_.Value }

# -- Recuperer l'arbre GitHub -------------------------------------------------
Write-Status "Recuperation de l'arbre GitHub..."
try {
    $headers   = @{ 'User-Agent' = 'AD-WebInterface-SyncCheck'; 'Accept' = 'application/vnd.github.v3+json' }
    $branch    = Invoke-RestMethod -Uri "$API_BASE/branches/$GITHUB_BRANCH" -Headers $headers -TimeoutSec 15
    $commitSha = $branch.commit.sha
    $tree      = Invoke-RestMethod -Uri "$API_BASE/git/trees/${commitSha}?recursive=1" -Headers $headers -TimeoutSec 30
    $remoteFiles = $tree.tree | Where-Object { $_.type -eq 'blob' }
} catch {
    Write-Host "ERREUR: Impossible de recuperer l'arbre GitHub: $_" -ForegroundColor Red
    exit 2
}

# -- Comparaison --------------------------------------------------------------
$drifted  = [System.Collections.Generic.List[PSObject]]::new()
$missing  = [System.Collections.Generic.List[string]]::new()
$upToDate = 0
$skipped  = 0

foreach ($file in $remoteFiles) {
    $path = $file.path
    if (Should-Skip $path) { $skipped++; continue }

    $remoteSha = $file.sha
    if ($localHash.ContainsKey($path)) {
        if ($localHash[$path] -ne $remoteSha) {
            $drifted.Add([PSCustomObject]@{
                File      = $path
                LocalSHA  = $localHash[$path]
                RemoteSHA = $remoteSha
                Status    = "Modifie localement"
            })
        } else {
            $upToDate++
        }
    } else {
        $missing.Add($path)
    }
}

$remoteSet = @{}
$remoteFiles | ForEach-Object { $remoteSet[$_.path] = $true }
$extra = $localHash.Keys | Where-Object { -not $remoteSet.ContainsKey($_) -and -not (Should-Skip $_) }

# -- Affichage du rapport -----------------------------------------------------
Write-Status "`n-- Resume --------------------------------------------"
Write-Status "  Fichiers synchronises : $upToDate" "Green"
Write-Status "  Fichiers ignores      : $skipped"

$hasDrift = ($drifted.Count -gt 0) -or ($missing.Count -gt 0) -or ($extra.Count -gt 0)

if ($drifted.Count -gt 0) {
    Write-Host "`n[!] Fichiers modifies localement ($($drifted.Count)) :" -ForegroundColor Yellow
    $drifted | Select-Object -First 20 | ForEach-Object {
        Write-Host "    $($_.File)" -ForegroundColor Yellow
    }
    if ($drifted.Count -gt 20) {
        Write-Host "    ... et $($drifted.Count - 20) autres" -ForegroundColor Yellow
    }
}

if ($missing.Count -gt 0) {
    Write-Host "`n[X] Fichiers manquants dans le manifeste local ($($missing.Count)) :" -ForegroundColor Red
    $missing | Select-Object -First 10 | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    if ($missing.Count -gt 10) {
        Write-Host "    ... et $($missing.Count - 10) autres" -ForegroundColor Red
    }
}

if ($extra.Count -gt 0) {
    Write-Host "`n[+] Fichiers extra - presents localement, absents de GitHub ($($extra.Count)) :" -ForegroundColor Cyan
    $extra | Select-Object -First 10 | ForEach-Object { Write-Host "    $_" -ForegroundColor Cyan }
}

# -- Export JSON optionnel ----------------------------------------------------
if ($OutputJson) {
    $report = @{
        generated_at   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        app_dir        = $AppDir
        local_version  = $localVersion
        remote_version = $remoteVersion
        up_to_date     = $upToDate
        drifted        = $drifted
        missing        = $missing
        extra          = @($extra)
        has_drift      = $hasDrift
    }
    $report | ConvertTo-Json -Depth 5 | Set-Content $OutputJson -Encoding UTF8
    Write-Status "`nRapport JSON sauvegarde : $OutputJson"
}

# -- Conclusion ---------------------------------------------------------------
Write-Status "`n=============================================" "White"
if (-not $hasDrift) {
    Write-Host "  [OK] Serveur synchronise avec GitHub" -ForegroundColor Green
    Write-Status "=============================================`n" "White"
    exit 0
} else {
    Write-Host "  [!] Derive detectee - lancez une mise a jour" -ForegroundColor Yellow
    Write-Status "=============================================`n" "White"
    exit 1
}
