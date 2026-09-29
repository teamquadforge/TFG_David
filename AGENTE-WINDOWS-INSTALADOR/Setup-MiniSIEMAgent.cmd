@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
echo.
echo ================================================
echo  Mini-SIEM Sentinel Agent v15.3 - Instalador
echo ================================================
echo.
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Solicitando permisos de administrador...
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-MiniSIEMAgent.ps1"
echo.
echo Si hubo error, ejecuta Diagnosticar-MiniSIEMAgent.cmd y pega la salida.
echo.
pause
