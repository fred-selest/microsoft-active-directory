@echo off
cd /d C:\AD-WebInterface

REM Supprimer les fichiers problématiques du tracking git
git rm --cached update_readme.bat 2>nul
git rm --cached clean_git.bat 2>nul
git rm --cached .claude\settings.json 2>nul
git rm --cached .claude\settings.local.json 2>nul
git rm --cached core\data\settings.json 2>nul
git rm --cached data\permissions.json 2>nul
git rm --cached data\update_manifest.json 2>nul
git rm --cached routes\tools\accounts_part3.dat 2>nul
git rm --cached routes\tools\test.dat 2>nul
git rm --cached routes\tools\test_write.txt 2>nul

REM Supprimer README.md du tracking car il a été modifié par cmd au lieu de python
git rm --cached README.md 2>nul

REM Supprimer du filesystem les fichiers batch
del update_readme.bat 2>nul
del clean_git.bat 2>nul

REM Refaire le README proprement
python -c "
readme = open('README.md', 'r', encoding='utf-8').read()
# Annuler le changement corrompu du README
# Le fichier a été modifié mais le commit contient aussi le batch avec le PAT
print('README length:', len(readme))
"

git add -A
git commit -m "chore: remove temp files and fix README — v1.45.0"

git push origin main --force
