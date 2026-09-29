$ErrorActionPreference = "Continue"
$current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
  exit
}
Write-Host "Netejant agents MiniSIEM antics..." -ForegroundColor Cyan
Get-ScheduledTask | Where-Object {$_.TaskName -like "*MiniSIEM*"} | ForEach-Object {
  Write-Host "Eliminant tasca: $($_.TaskName)" -ForegroundColor Yellow
  Stop-ScheduledTask -TaskName $_.TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
}
try { Get-Process | Where-Object { $_.Path -like "*MiniSIEMAgent*" -or $_.CommandLine -like "*MiniSIEMAgent*" } | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
Remove-Item -Recurse -Force "$env:ProgramFiles\MiniSIEMAgent" -ErrorAction SilentlyContinue
Remove-Item -Force "$env:ProgramData\MiniSIEMAgent\state.json" -ErrorAction SilentlyContinue
Write-Host "Fet. Pots instal·lar ara l'agent v15.3." -ForegroundColor Green
Read-Host "Prem ENTER per tancar"
