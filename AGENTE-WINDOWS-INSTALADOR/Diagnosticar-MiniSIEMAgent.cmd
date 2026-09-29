@echo off
chcp 65001 >nul
setlocal
echo ================================================
echo  Mini-SIEM Sentinel Agent v15.3 - Diagnostico
echo ================================================
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
"Write-Host '--- Scheduled Tasks ---' -ForegroundColor Cyan; ^
Get-ScheduledTask ^| Where-Object {$_.TaskName -like '*MiniSIEM*'} ^| Format-Table TaskName,State,TaskPath -AutoSize; ^
Write-Host '--- Task Info ---' -ForegroundColor Cyan; ^
try { Get-ScheduledTaskInfo -TaskName 'MiniSIEM Sentinel Agent' ^| Format-List * } catch { Write-Host $_.Exception.Message -ForegroundColor Red }; ^
Write-Host '--- Files ---' -ForegroundColor Cyan; ^
Write-Host ('Install dir exists: ' + (Test-Path 'C:\Program Files\MiniSIEMAgent')); ^
Write-Host ('Data dir exists: ' + (Test-Path 'C:\ProgramData\MiniSIEMAgent')); ^
Write-Host ('Config exists: ' + (Test-Path 'C:\ProgramData\MiniSIEMAgent\config.json')); ^
Write-Host '--- Config ---' -ForegroundColor Cyan; ^
if(Test-Path 'C:\ProgramData\MiniSIEMAgent\config.json'){ Get-Content 'C:\ProgramData\MiniSIEMAgent\config.json' -Raw }; ^
Write-Host '--- Log tail ---' -ForegroundColor Cyan; ^
if(Test-Path 'C:\ProgramData\MiniSIEMAgent\agent.log'){ Get-Content 'C:\ProgramData\MiniSIEMAgent\agent.log' -Tail 120 } else { Write-Host 'No existe agent.log' -ForegroundColor Yellow }; ^
Write-Host '--- Backend test ---' -ForegroundColor Cyan; ^
try { Invoke-RestMethod 'http://127.0.0.1:8000' -TimeoutSec 5 ^| ConvertTo-Json -Depth 5 } catch { Write-Host $_.Exception.Message -ForegroundColor Red }"
echo.
pause
