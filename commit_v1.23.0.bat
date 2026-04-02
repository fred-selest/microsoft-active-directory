@echo off
REM ============================================
REM Script de commit pour AD Web Interface v1.23.0
REM ============================================

echo.
echo ============================================================
echo   AD Web Interface - Version 1.23.0
echo   Commit et Push vers GitHub
echo ============================================================
echo.

REM Vérifier si git est installé
where git >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERREUR] Git n'est pas installe ou pas dans le PATH
    echo.
    echo Installez Git depuis: https://git-scm.com/download/win
    echo Ou utilisez l'interface web GitHub pour uploader les fichiers
    echo.
    pause
    exit /b 1
)

REM Vérifier si on est dans un repo git
if not exist .git (
    echo [ERREUR] Ce repertoire n'est pas un depot Git
    echo.
    echo Initialisation du depot...
    git init
    git remote add origin https://github.com/fred-selest/microsoft-active-directory.git
)

echo [INFO] Ajout des fichiers...
git add -A

echo [INFO] Verification des modifications...
git status --short

echo.
set /p CONFIRM="Voulez-vous continuer avec le commit? (O/N): "
if /i not "%CONFIRM%"=="O" (
    echo [ANNULATION] Commit annule par l'utilisateur
    pause
    exit /b 1
)

echo.
echo [INFO] Creation du commit...
git commit -m "v1.23.0 - Alertes, Personnalisation, Correction bugs et Sécurité

NOUVELLES FONCTIONNALITÉS:
🔔 Système d'alertes complet avec détection automatique
   - Comptes expirants (30 jours)
   - Mots de passe expirant (14 jours)
   - Comptes inactifs (90 jours)
   - Page /alerts avec filtres, acquittement, export JSON
   
🔐 Case 'Changer MDP à prochaine connexion'
   - Dans /users/create
   - Force pwdLastSet=0 pour obligation de changement
   
🎨 Personnalisation avancée
   - Logo personnalisé (upload via Admin)
   - Couleurs thématiques (5 couleurs configurables)
   - Police personnalisée (Google Fonts support)
   - CSS personnalisé (injection dynamique)
   - Guide complet: GUIDE_PERSONNALISATION.md

🧰 Scripts PowerShell de correction
   - fix_smbv1.ps1 (désactivation SMBv1)
   - fix_ntlm.ps1 (durcissement NTLM niveau 5)
   - fix_ldap_signing.ps1 (activation signing LDAP)
   - fix_channel_binding.ps1 (activation Channel Binding)

🔍 Détection automatique des protocoles
   - SMBv1, NTLM/LM, LDAP Signing, Channel Binding
   - API /api/fix-protocol pour appliquer corrections
   - Boutons 'Appliquer la correction' dans Password Audit

📊 Tests visuels automatisés
   - test_full.py (test complet avec Chromium)
   - test_debug.py (détection bugs d'affichage)
   - Captures d'écran automatiques dans logs/screenshots/

CORRECTIONS DE BUGS:
- Overflow horizontal (+280px) sur toutes les pages
- Boutons empilés verticalement dans header-actions
- Politique MDP avec valeurs vides
- Template LAPS erreur syntaxe endif
- Routes /admin/ et /password-audit incorrectes
- Fonctions JavaScript showLoading/hideLoading manquantes
- Erreur ACTIONS['OTHER'] dans audit.py
- Import request manquant dans debug_utils.py
- Template debug/dashboard.html JSON non sérialisable

SÉCURITÉ:
- Autorisations granulaires par groupe AD
- Détection protocoles obsolètes (SMBv1, NTLMv1, LM)
- Audit des mots de passe enrichi (score 0-100, ANSSI)
- Error handlers 404/500 avec logging

TECHNIQUE:
- +2500 lignes ajoutées, -200 supprimées
- 20+ fichiers modifiés
- 8 pages testées automatiquement
- Overflow horizontal corrigé (280px → 0px)

FICHIERS NOUVEAUX:
- templates/alerts.html, error.html, errors.html
- scripts/fix_*.ps1 (4 scripts PowerShell)
- test_*.py (4 scripts de test)
- GUIDE_PERSONNALISATION.md, GUIDE_TEST_RESPONSIVE.md
- static/js/display-debugger.js

Voir CHANGELOG.md pour le détail complet."

if %ERRORLEVEL% NEQ 0 (
    echo [ERREUR] Echec du commit
    pause
    exit /b 1
)

echo.
echo [INFO] Commit reussi!
echo.

REM Demander si on veut pusher
set /p PUSH="Voulez-vous pousser vers GitHub? (O/N): "
if /i "%PUSH%"=="O" (
    echo [INFO] Push en cours...
    git push origin main
    
    if %ERRORLEVEL% NEQ 0 (
        echo [ERREUR] Echec du push. Verifiez vos identifiants GitHub
        pause
        exit /b 1
    )
    
    echo.
    echo [SUCCES] Push reussi!
    echo.
    echo Rendez-vous sur: https://github.com/fred-selest/microsoft-active-directory
    echo pour verifier les modifications
)

echo.
echo ============================================================
echo   Operation terminee
echo ============================================================
echo.
pause
