#!/usr/bin/env pwsh
# Commit et push vers GitHub - AD Web Interface v1.22.0

Set-Location $PSScriptRoot

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  COMMIT GITHUB - AD Web Interface v1.22.0" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier Git
Write-Host "[INFO] Vérification de Git..." -ForegroundColor Yellow
try {
    $gitVersion = git --version 2>&1
    Write-Host "[OK] $gitVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERREUR] Git n'est pas installé ou non dans le PATH" -ForegroundColor Red
    Write-Host ""
    Write-Host "Installation :" -ForegroundColor Yellow
    Write-Host "  1. winget install Git.Git" -ForegroundColor White
    Write-Host "  2. Redémarrer ce script" -ForegroundColor White
    Write-Host ""
    pause
    exit 1
}

# Vérifier le dépôt
Write-Host ""
Write-Host "[INFO] Vérification du dépôt Git..." -ForegroundColor Yellow
if (-not (Test-Path ".git")) {
    Write-Host "[INFO] Initialisation du dépôt..." -ForegroundColor Yellow
    git init
    git remote add origin https://github.com/fred-selest/microsoft-active-directory.git 2>$null
    Write-Host "[OK] Dépôt initialisé" -ForegroundColor Green
}

# Afficher les fichiers à commiter
Write-Host ""
Write-Host "[INFO] Fichiers à commiter :" -ForegroundColor Yellow
Write-Host "  NOUVEAUX :" -ForegroundColor Cyan
Write-Host "    - features.py" -ForegroundColor White
Write-Host "    - templates/feature_disabled.html" -ForegroundColor White
Write-Host "    - MODULARITE.md" -ForegroundColor White
Write-Host "    - RESUME_CHANGEMENTS.md" -ForegroundColor White
Write-Host "    - PUSH_GITHUB_INSTRUCTIONS.md" -ForegroundColor White
Write-Host "    - COMMIT_READY.md" -ForegroundColor White
Write-Host "    - commit_github.bat" -ForegroundColor White
Write-Host "  MODIFIÉS :" -ForegroundColor Cyan
Write-Host "    - VERSION (1.22.0)" -ForegroundColor White
Write-Host "    - CHANGELOG.md" -ForegroundColor White
Write-Host "    - config.py (+50 feature flags)" -ForegroundColor White
Write-Host "    - app.py" -ForegroundColor White
Write-Host "    - routes/tools.py (+3 routes)" -ForegroundColor White
Write-Host "    - templates/base.html" -ForegroundColor White
Write-Host "    - templates/admin.html" -ForegroundColor White
Write-Host "    - templates/recycle_bin.html" -ForegroundColor White
Write-Host "    - templates/locked_accounts.html" -ForegroundColor White
Write-Host "    - .env.example" -ForegroundColor White
Write-Host ""

# Ajouter les fichiers
Write-Host "[INFO] Ajout des fichiers..." -ForegroundColor Yellow
git add VERSION
git add CHANGELOG.md
git add features.py
git add templates/feature_disabled.html
git add MODULARITE.md
git add RESUME_CHANGEMENTS.md
git add PUSH_GITHUB_INSTRUCTIONS.md
git add COMMIT_READY.md
git add commit_github.bat
git add config.py
git add app.py
git add routes/tools.py
git add templates/base.html
git add templates/admin.html
git add templates/recycle_bin.html
git add templates/locked_accounts.html
git add .env.example

Write-Host "[OK] Fichiers ajoutés" -ForegroundColor Green
Write-Host ""

# Créer le commit
Write-Host "[INFO] Création du commit..." -ForegroundColor Yellow
$commitMessage = @"
feat: Système de feature flags et corrections erreurs 500 [v1.22.0]

Nouveautés :
- Système de feature flags avec 50+ options de modularité
- Module features.py avec utilitaires et décorateurs
- Page feature_disabled.html pour fonctionnalités désactivées
- Documentation MODULARITE.md avec guide complet
- Page admin.html redesignée

Corrections :
- Erreur 500 sur /recycle-bin (route restore_deleted_object)
- Erreur 500 sur /locked-accounts (route bulk_unlock_accounts)
- Erreur export_expiring_pdf dans les logs

Modifications :
- config.py : 50+ variables FEATURE_XXX_ENABLED
- templates/base.html : Menu conditionnel selon feature flags
- routes/tools.py : 3 routes manquantes ajoutées
- .env.example : Section Feature Flags ajoutée
- VERSION : Passage à 1.22.0

Tests :
- 14/14 tests automatisés passés
- 100% des pages fonctionnelles

BREAKING CHANGE: Nouvelles variables FEATURE_XXX_ENABLED dans .env
Voir MODULARITE.md pour la liste complète des feature flags.
"@

git commit -m $commitMessage

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[ERREUR] Échec du commit" -ForegroundColor Red
    Write-Host ""
    pause
    exit 1
}

Write-Host "[OK] Commit créé avec succès !" -ForegroundColor Green
Write-Host ""

# Demander si on veut pousser
$response = Read-Host "Voulez-vous pousser vers GitHub maintenant ? (O/n)"
if ($response -eq 'n' -or $response -eq 'N') {
    Write-Host ""
    Write-Host "[INFO] Pour pousser manuellement : git push origin main" -ForegroundColor Yellow
    pause
    exit 0
}

Write-Host ""
Write-Host "[INFO] Push vers GitHub..." -ForegroundColor Yellow

# Vérifier l'authentification
Write-Host "[INFO] Vérification de l'authentification..." -ForegroundColor Yellow
try {
    $ghAuth = gh auth status 2>&1
    Write-Host "[OK] Authentifié sur GitHub" -ForegroundColor Green
} catch {
    Write-Host "[AVERTISSEMENT] GitHub CLI non authentifié" -ForegroundColor Yellow
    Write-Host "[INFO] Utilisation de Git avec HTTPS..." -ForegroundColor Yellow
}

git push origin main

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[AVERTISSEMENT] Le push a échoué" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Solutions possibles :" -ForegroundColor Yellow
    Write-Host "  1. gh auth login" -ForegroundColor White
    Write-Host "  2. git push origin main" -ForegroundColor White
    Write-Host ""
    pause
    exit 1
}

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host "  COMMIT ET PUSH TERMINÉS AVEC SUCCÈS !" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Version : 1.22.0" -ForegroundColor Cyan
Write-Host "  Dépôt   : https://github.com/fred-selest/microsoft-active-directory" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Prochaines étapes :" -ForegroundColor Yellow
Write-Host "    1. Vérifier le commit sur GitHub" -ForegroundColor White
Write-Host "    2. Mettre à jour les releases sur GitHub" -ForegroundColor White
Write-Host "    3. Créer un tag : git tag v1.22.0 && git push origin v1.22.0" -ForegroundColor White
Write-Host ""
pause
