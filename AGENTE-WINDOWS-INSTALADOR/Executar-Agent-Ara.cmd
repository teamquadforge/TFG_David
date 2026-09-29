@echo off
chcp 65001 >nul
setlocal
echo ================================================
echo  Ejecutando Mini-SIEM Agent ahora mismo
echo ================================================
echo.
if not exist "C:\Program Files\MiniSIEMAgent\MiniSIEMAgent.ps1" (
  echo No encuentro C:\Program Files\MiniSIEMAgent\MiniSIEMAgent.ps1
  echo Ejecuta primero Setup-MiniSIEMAgent.cmd como administrador.
  pause
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\MiniSIEMAgent\MiniSIEMAgent.ps1" -ConfigPath "C:\ProgramData\MiniSIEMAgent\config.json"
echo.
echo Ahora revisa la pestaña Agents, EDR, Integritat y Esdeveniments.
echo Log: C:\ProgramData\MiniSIEMAgent\agent.log
echo.
pause
