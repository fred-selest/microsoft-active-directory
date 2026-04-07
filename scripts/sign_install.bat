@echo off
powershell -ExecutionPolicy Bypass -Command "$cert = Get-Item 'Cert:\LocalMachine\My\89F29C7EB08BFA6F7BDB582EE0A32BB59667557C'; Set-AuthenticodeSignature -FilePath 'C:\AD-WebInterface\scripts\install_standalone.ps1' -Certificate $cert; Get-AuthenticodeSignature 'C:\AD-WebInterface\scripts\install_standalone.ps1' | Select-Object Status"
pause