@echo off
chcp 65001 >nul
setlocal
echo Forzando reescaneo de Downloads/Descargas...
del /f /q "C:\ProgramData\MiniSIEMAgent\state.json" 2>nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\MiniSIEMAgent\MiniSIEMAgent.ps1" -ConfigPath "C:\ProgramData\MiniSIEMAgent\config.json"
echo.
echo Revisa EDR, Integritat, Esdeveniments y Alertes.
pause
