param(
  [string]$BackendUrl = "http://127.0.0.1:8000",
  [string]$AgentToken = "dev-windows-agent-token",
  [switch]$SkipPrompt
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
  $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting administrator privileges..."
    $args = "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -BackendUrl `"$BackendUrl`" -AgentToken `"$AgentToken`" -SkipPrompt"
    Start-Process powershell.exe -Verb RunAs -ArgumentList $args
    exit
  }
}

function Banner {
  Clear-Host
  Write-Host ""
  Write-Host "  ███╗   ███╗██╗███╗   ██╗██╗███████╗██╗███████╗███╗   ███╗" -ForegroundColor Cyan
  Write-Host "  ████╗ ████║██║████╗  ██║██║██╔════╝██║██╔════╝████╗ ████║" -ForegroundColor Cyan
  Write-Host "  ██╔████╔██║██║██╔██╗ ██║██║███████╗██║█████╗  ██╔████╔██║" -ForegroundColor Cyan
  Write-Host "  ██║╚██╔╝██║██║██║╚██╗██║██║╚════██║██║██╔══╝  ██║╚██╔╝██║" -ForegroundColor Cyan
  Write-Host "  ██║ ╚═╝ ██║██║██║ ╚████║██║███████║██║███████╗██║ ╚═╝ ██║" -ForegroundColor Cyan
  Write-Host "  ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝╚══════╝╚═╝╚══════╝╚═╝     ╚═╝" -ForegroundColor Cyan
  Write-Host ""
  Write-Host "  Mini-SIEM Sentinel Agent Installer v15.3" -ForegroundColor White
  Write-Host "  Instal·la un agent Windows que llegeix esdeveniments reals, revisa Descàrregues, controla integritat i executa respostes EDR segures amb aprovació." -ForegroundColor Gray
  Write-Host ""
}

Assert-Admin
Banner

if (-not $SkipPrompt) {
  $inputUrl = Read-Host "URL del servidor SIEM [$BackendUrl]"
  if ($inputUrl.Trim().Length -gt 0) { $BackendUrl = $inputUrl.Trim() }
  $inputToken = Read-Host "Token de l’agent [$AgentToken]"
  if ($inputToken.Trim().Length -gt 0) { $AgentToken = $inputToken.Trim() }
}

# v15.3: neteja agents/tasques antigues abans d'instal·lar per evitar que v10/v14 continuïn enviant telemetria.
try {
  Get-ScheduledTask | Where-Object { $_.TaskName -like "*MiniSIEM*" } | ForEach-Object {
    Stop-ScheduledTask -TaskName $_.TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
  }
} catch {}
try { Get-Process | Where-Object { $_.Path -like "*MiniSIEMAgent*" -or $_.CommandLine -like "*MiniSIEMAgent*" } | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}

$InstallDir = Join-Path $env:ProgramFiles "MiniSIEMAgent"
$DataDir = Join-Path $env:ProgramData "MiniSIEMAgent"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
# Forcem un primer escaneig net de Descàrregues/FIM en instal·lar v15.3. No esborra quarentena.
Remove-Item -Force (Join-Path $DataDir "state.json") -ErrorAction SilentlyContinue

Copy-Item -Force -Path (Join-Path $PSScriptRoot "MiniSIEMAgent.ps1") -Destination (Join-Path $InstallDir "MiniSIEMAgent.ps1")
Copy-Item -Force -Path (Join-Path $PSScriptRoot "Uninstall-MiniSIEMAgent.ps1") -Destination (Join-Path $InstallDir "Uninstall-MiniSIEMAgent.ps1")

$agentId = "$env:COMPUTERNAME-$([guid]::NewGuid().ToString('N').Substring(0,8))"
$config = [ordered]@{
  backend_url = $BackendUrl.TrimEnd('/')
  agent_token = $AgentToken
  agent_id = $agentId
  poll_seconds = 10
  max_events_per_cycle = 30
  monitor_downloads = $true
  downloads_max_file_mb = 200
  edr_enabled = $true
  version = "15.3"
  agent_version = "15.3"
}
$config | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 (Join-Path $DataDir "config.json")

$taskName = "MiniSIEM Sentinel Agent"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\MiniSIEMAgent.ps1`" -ConfigPath `"$DataDir\config.json`" -ServiceMode"
$triggerStartup = New-ScheduledTaskTrigger -AtStartup
$triggerLogon = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($triggerStartup,$triggerLogon) -Principal $principal -Settings $settings | Out-Null

# Test backend connectivity before starting. It is OK if this warns; the agent will retry later.
try {
  $health = Invoke-RestMethod -Uri ($BackendUrl.TrimEnd('/') + '/') -TimeoutSec 5
  Write-Host "Backend OK: $($health | ConvertTo-Json -Compress)" -ForegroundColor Green
} catch {
  Write-Host "AVÍS: no puc contactar amb el backend ara mateix: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Start scheduled task and also run one foreground cycle so the user sees errors immediately.
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3
try {
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$InstallDir\MiniSIEMAgent.ps1" -ConfigPath "$DataDir\config.json"
} catch {
  Write-Host "AVÍS executant cicle inicial: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "MiniSIEM Agent v15.3 instal·lat correctament." -ForegroundColor Green
Write-Host "Instalación: $InstallDir" -ForegroundColor Gray
Write-Host "Datos:       $DataDir" -ForegroundColor Gray
Write-Host "Agente ID:   $agentId" -ForegroundColor Gray
Write-Host "Servidor:    $BackendUrl" -ForegroundColor Gray
Write-Host ""
Write-Host "Per enviar esdeveniments demo ara:" -ForegroundColor Yellow
Write-Host "powershell -ExecutionPolicy Bypass -File `"$InstallDir\MiniSIEMAgent.ps1`" -ConfigPath `"$DataDir\config.json`" -DemoOnce" -ForegroundColor Yellow
Write-Host ""
if (-not $SkipPrompt) { Read-Host "Prem ENTER per tancar" }
