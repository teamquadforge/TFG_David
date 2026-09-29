$ErrorActionPreference = "Continue"
$current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
  exit
}
Write-Host "Aturant i eliminant tasques MiniSIEM antigues..." -ForegroundColor Cyan
Get-ScheduledTask | Where-Object {$_.TaskName -like "*MiniSIEM*"} | ForEach-Object {
  Stop-ScheduledTask -TaskName $_.TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
}
try { Get-Process | Where-Object { $_.Path -like "*MiniSIEMAgent*" -or $_.CommandLine -like "*MiniSIEMAgent*" } | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
Remove-Item -Recurse -Force "$env:ProgramFiles\MiniSIEMAgent" -ErrorAction SilentlyContinue
$choice = Read-Host "Vols esborrar també dades locals/state/logs? (S/N)"
if($choice -match '^[sSyY]') { Remove-Item -Recurse -Force "$env:ProgramData\MiniSIEMAgent" -ErrorAction SilentlyContinue }
Write-Host "MiniSIEM Agent eliminat." -ForegroundColor Green
Read-Host "Prem ENTER per tancar"
