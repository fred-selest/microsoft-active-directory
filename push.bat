@echo off
REM Push vers GitHub sans erreur de tags existants

echo.
echo ========================================
echo  PUSH VERS GITHUB
echo ========================================
echo.

REM 1. Push des commits
echo [1/2] Push des commits...
git push origin main
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ❌ Erreur lors du push des commits
    exit /b 1
)

REM 2. Push du dernier tag uniquement
echo [2/2] Push du dernier tag...
for /f "tokens=*" %%i in ('git describe --tags --abbrev=0 2^>nul') do set LATEST_TAG=%%i
if defined LATEST_TAG (
    echo       Tag: %LATEST_TAG%
    git push origin %LATEST_TAG%
    if %ERRORLEVEL% NEQ 0 (
        echo.
        echo ⚠️  Erreur lors du push du tag (peut-etre existe deja)
    ) else (
        echo       ✅ Tag pousse avec succes
    )
) else (
    echo       Aucun tag a pousser
)

echo.
echo ========================================
echo  PUSH TERMINE
echo ========================================
echo.
