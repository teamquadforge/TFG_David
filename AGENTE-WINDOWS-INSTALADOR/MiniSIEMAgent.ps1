param(
  [string]$ConfigPath = "$env:ProgramData\MiniSIEMAgent\config.json",
  [switch]$ServiceMode,
  [switch]$DemoOnce
)

$ErrorActionPreference = "Continue"
$Script:AgentVersion = "15.3"

function Write-AgentLog {
  param([string]$Message)
  $dir = Join-Path $env:ProgramData "MiniSIEMAgent"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $line = "$(Get-Date -Format o) $Message"
  Add-Content -Path (Join-Path $dir "agent.log") -Value $line
  Write-Host $line
}

function Load-Config {
  param([string]$Path)
  if (!(Test-Path $Path)) { throw "Config file not found: $Path" }
  return Get-Content $Path -Raw | ConvertFrom-Json
}

function Save-State {
  param($State)
  $statePath = Join-Path $env:ProgramData "MiniSIEMAgent\state.json"
  ($State | ConvertTo-Json -Depth 8) | Set-Content -Encoding UTF8 $statePath
}

function Load-State {
  $statePath = Join-Path $env:ProgramData "MiniSIEMAgent\state.json"
  if (Test-Path $statePath) {
    try { return Get-Content $statePath -Raw | ConvertFrom-Json } catch {}
  }
  return [pscustomobject]@{ channels = @{} }
}

function Ensure-StateChannel {
  param($State, [string]$Channel)
  if ($null -eq $State.channels) { $State | Add-Member -NotePropertyName channels -NotePropertyValue @{} -Force }
  if (-not ($State.channels.PSObject.Properties.Name -contains $Channel)) {
    $State.channels | Add-Member -NotePropertyName $Channel -NotePropertyValue 0 -Force
  }
}

function To-HashtableFromEventProperties {
  param($Event)
  $h = @{}

  # Always keep positional properties as fallback.
  $idx = 0
  foreach ($p in $Event.Properties) {
    $h["p$idx"] = "$($p.Value)"
    $idx += 1
  }

  # v10.3: enrich with real EventData names from the Windows Event XML.
  # This is what allows the SIEM to extract IpAddress, TargetUserName,
  # WorkstationName, ProcessName, CommandLine, etc. from real Windows logs.
  try {
    [xml]$xml = $Event.ToXml()
    $dataNodes = $xml.Event.EventData.Data
    foreach ($d in $dataNodes) {
      $name = $d.Name
      $value = $d.'#text'
      if ($null -ne $name -and "$name".Trim() -ne "") {
        $h["$name"] = "$value"
      }
    }

    # Some providers put fields under UserData instead of EventData.
    $userData = $xml.Event.UserData
    if ($null -ne $userData) {
      foreach ($node in $userData.ChildNodes) {
        foreach ($child in $node.ChildNodes) {
          if ($child.Name -and $child.InnerText) {
            $h["$($child.Name)"] = "$($child.InnerText)"
          }
        }
      }
    }
  } catch {
    # If XML parsing fails, positional p0..pN fields are still sent.
  }

  return $h
}

function Send-Json {
  param($Config, [string]$Path, $Body)
  $url = ($Config.backend_url.TrimEnd('/')) + $Path
  $headers = @{ "X-Agent-Token" = $Config.agent_token; "Accept" = "application/json" }
  $json = $Body | ConvertTo-Json -Depth 12 -Compress

  # v10.2: keep the request simple and backend-tolerant. PowerShell 5.1 can be weird
  # with byte[] bodies; a normal JSON string plus charset works reliably with FastAPI.
  return Invoke-RestMethod -Uri $url -Method Post -Headers $headers -ContentType "application/json; charset=utf-8" -Body $json -TimeoutSec 15
}


function Test-EventLogAvailable {
  param([string]$LogName)
  try { Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop | Out-Null; return $true } catch { return $false }
}

function Get-SecurityPosture {
  $posture = [ordered]@{}
  try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $posture.defender_enabled = [bool]$mp.AntivirusEnabled
    $posture.defender_status = "RealTime=$($mp.RealTimeProtectionEnabled); Signature=$($mp.AntivirusSignatureLastUpdated)"
  } catch { $posture.defender_enabled = $false; $posture.defender_status = "No disponible" }
  try {
    $fw = Get-NetFirewallProfile -ErrorAction Stop
    $posture.firewall_enabled = [bool](($fw | Where-Object {$_.Enabled -eq $true}).Count -gt 0)
    $posture.firewall_profile = (($fw | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join '; ')
  } catch { $posture.firewall_enabled = $false; $posture.firewall_profile = "No disponible" }
  try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $posture.bitlocker_enabled = ($bl.ProtectionStatus -eq 'On')
    $posture.bitlocker_status = "$($bl.ProtectionStatus)"
  } catch { $posture.bitlocker_enabled = $false; $posture.bitlocker_status = "No disponible" }
  try {
    $uac = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop
    $posture.uac_enabled = ([int]$uac.EnableLUA -eq 1)
  } catch { $posture.uac_enabled = $false }
  $posture.powershell_logging = Test-EventLogAvailable -LogName 'Microsoft-Windows-PowerShell/Operational'
  $posture.sysmon_installed = Test-EventLogAvailable -LogName 'Microsoft-Windows-Sysmon/Operational'
  return $posture
}

function Send-Heartbeat {
  param($Config)
  $os = Get-CimInstance Win32_OperatingSystem
  $cs = Get-CimInstance Win32_ComputerSystem
  $body = @{
    agent_id = $Config.agent_id
    hostname = $env:COMPUTERNAME
    os_type = "windows"
    os_version = $os.Caption + " " + $os.Version
    version = $Script:AgentVersion
    status = "online"
    metadata = @{
      manufacturer = $cs.Manufacturer
      model = $cs.Model
      user = $env:USERNAME
      domain = $env:USERDOMAIN
      install_mode = "scheduled_task"
      posture = Get-SecurityPosture
    }
  }
  try { Send-Json -Config $Config -Path "/agents/heartbeat" -Body $body | Out-Null } catch { Write-AgentLog "heartbeat failed: $($_.Exception.Message)" }
}

function Send-WindowsEvent {
  param($Config, $Event)
  $msg = ""
  try { $msg = $Event.FormatDescription() } catch { $msg = $Event.Message }
  if ($null -eq $msg) { $msg = "" }
  if ($msg.Length -gt 6000) { $msg = $msg.Substring(0, 6000) }

  $body = @{
    agent_id = $Config.agent_id
    hostname = $env:COMPUTERNAME
    os_version = (Get-CimInstance Win32_OperatingSystem).Caption
    log_name = $Event.LogName
    provider_name = $Event.ProviderName
    event_id = [int]$Event.Id
    record_id = [int64]$Event.RecordId
    level = "$($Event.LevelDisplayName)"
    time_created = $Event.TimeCreated.ToUniversalTime().ToString("o")
    message = $msg
    event_data = To-HashtableFromEventProperties -Event $Event
  }
  try {
    Send-Json -Config $Config -Path "/ingest-windows" -Body $body | Out-Null
    return $true
  } catch {
    $details = $_.Exception.Message
    try {
      if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $details = $details + " | " + $_.ErrorDetails.Message }
    } catch {}
    Write-AgentLog "send failed channel=$($Event.LogName) id=$($Event.Id) record=$($Event.RecordId): $details"
    Start-Sleep -Seconds 5
    return $false
  }
}

function Read-And-Send {
  param($Config, $State)
  $channels = @(
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational"
  )

  foreach ($channel in $channels) {
    Ensure-StateChannel -State $State -Channel $channel
    $last = [int64]$State.channels.$channel
    try {
      $events = Get-WinEvent -LogName $channel -MaxEvents $Config.max_events_per_cycle -ErrorAction Stop |
        Where-Object { $_.RecordId -gt $last } |
        Sort-Object RecordId
      foreach ($ev in $events) {
        $ok = Send-WindowsEvent -Config $Config -Event $ev
        if ($ok -and $ev.RecordId -gt [int64]$State.channels.$channel) {
          $State.channels.$channel = [int64]$ev.RecordId
          Save-State -State $State
        } elseif (-not $ok) {
          Write-AgentLog "backoff: stopping this channel cycle after failed send to avoid spam"
          break
        }
      }
    } catch {
      # Sysmon/Defender/PowerShell channels may not exist on every Windows installation.
      Write-AgentLog "channel skipped: $channel ($($_.Exception.Message))"
    }
  }
}

function Get-FileSha256 {
  param([string]$Path)
  try { return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return "" }
}

function Ensure-DownloadState {
  param($State)
  if ($null -eq $State.downloads) { $State | Add-Member -NotePropertyName downloads -NotePropertyValue @{} -Force }
}

function Send-DownloadGuardEvent {
  param($Config, [int]$EventId, [string]$Message, $EventData)
  $body = @{
    agent_id = $Config.agent_id
    hostname = $env:COMPUTERNAME
    os_version = (Get-CimInstance Win32_OperatingSystem).Caption
    log_name = "MiniSIEM-DownloadGuard"
    provider_name = "MiniSIEMAgent Download Guard"
    event_id = [int]$EventId
    record_id = [int64](Get-Date -UFormat %s)
    level = "Warning"
    time_created = (Get-Date).ToUniversalTime().ToString("o")
    message = $Message
    event_data = $EventData
  }
  try { Send-Json -Config $Config -Path "/ingest-windows" -Body $body | Out-Null; return $true } catch { Write-AgentLog "download guard send failed: $($_.Exception.Message)"; return $false }
}

function Analyze-ZipFile {
  param([string]$Path)
  $suspiciousExt = @('.exe','.msi','.ps1','.psm1','.bat','.cmd','.vbs','.js','.jse','.wsf','.hta','.scr','.lnk','.dll','.docm','.xlsm','.iso','.img')
  $suspiciousNames = @('crack','keygen','activator','invoice','factura','urgent','update','setup','password')
  $entries = @()
  $suspicious = @()
  $encryptedOrUnreadable = $false
  try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
      foreach ($e in $zip.Entries) {
        if ($entries.Count -lt 120) { $entries += $e.FullName }
        $ext = [System.IO.Path]::GetExtension($e.FullName).ToLowerInvariant()
        if ($suspiciousExt -contains $ext) { $suspicious += $e.FullName }
        $lowerName = $e.FullName.ToLowerInvariant()
        foreach($sn in $suspiciousNames){ if($lowerName.Contains($sn)){ $suspicious += $e.FullName; break } }
        if($lowerName -match '\.(pdf|docx|xlsx|jpg|png)\.(exe|scr|cmd|bat|ps1|js|vbs)$'){ $suspicious += $e.FullName }
      }
    } finally { $zip.Dispose() }
  } catch {
    $encryptedOrUnreadable = $true
  }
  $verdict = 'clean'
  if ($encryptedOrUnreadable) { $verdict = 'suspicious' }
  # v15.3: per a un SIEM personal, qualsevol executable/script/macro dins un ZIP ja és risc alt.
  if ($suspicious.Count -gt 0) { $verdict = 'high' }
  return [ordered]@{
    entries = ($entries -join ' | ')
    suspicious_entries = ($suspicious -join ' | ')
    suspicious_count = [int]$suspicious.Count
    encrypted_or_unreadable = [bool]$encryptedOrUnreadable
    verdict = $verdict
  }
}


function Get-UserProfileRoots {
  $roots = @()
  try {
    $profiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
      $_.Name -notin @('Public','Default','Default User','All Users') -and $_.Name -notmatch '^WDAGUtilityAccount$'
    }
    foreach($p in $profiles){ $roots += $p.FullName }
  } catch {}
  if($roots.Count -eq 0 -and $env:USERPROFILE){ $roots += $env:USERPROFILE }
  return $roots | Select-Object -Unique
}

function Get-DownloadFolders {
  $dirs = @()
  foreach($profile in Get-UserProfileRoots){
    foreach($d in @('Downloads','Descargas')){
      $p = Join-Path $profile $d
      if(Test-Path $p){ $dirs += $p }
    }
    try {
      $oneDrives = Get-ChildItem -Path $profile -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'OneDrive*' }
      foreach($od in $oneDrives){
        foreach($d in @('Downloads','Descargas','Escriptori','Desktop')){
          $p = Join-Path $od.FullName $d
          if(Test-Path $p){ $dirs += $p }
        }
      }
    } catch {}
  }
  return $dirs | Select-Object -Unique
}

function Get-FimFolders {
  $dirs = @()
  foreach($profile in Get-UserProfileRoots){
    foreach($d in @('Desktop','Escriptori','Documents','Downloads','Descargas')){
      $p = Join-Path $profile $d
      if(Test-Path $p){ $dirs += $p }
    }
    $startup = Join-Path $profile 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    if(Test-Path $startup){ $dirs += $startup }
  }
  $globalStartup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
  if(Test-Path $globalStartup){ $dirs += $globalStartup }
  return $dirs | Select-Object -Unique
}

function Test-SafeUserFilePath {
  param([string]$Path)
  try {
    $full = [System.IO.Path]::GetFullPath($Path)
    $win = [System.IO.Path]::GetFullPath($env:WINDIR)
    $pf = [System.IO.Path]::GetFullPath($env:ProgramFiles)
    $pfx86 = if($env:ProgramFiles -ne $env:ProgramFilesx86 -and $env:ProgramFilesx86){ [System.IO.Path]::GetFullPath($env:ProgramFilesx86) } else { '' }
    if($full.StartsWith($win, [System.StringComparison]::OrdinalIgnoreCase)){ return $false }
    if($full.StartsWith($pf, [System.StringComparison]::OrdinalIgnoreCase)){ return $false }
    if($pfx86 -and $full.StartsWith($pfx86, [System.StringComparison]::OrdinalIgnoreCase)){ return $false }
    foreach($profile in Get-UserProfileRoots){
      $prof = [System.IO.Path]::GetFullPath($profile)
      if($full.StartsWith($prof, [System.StringComparison]::OrdinalIgnoreCase)){ return $true }
    }
    $temp = [System.IO.Path]::GetFullPath($env:TEMP)
    if($full.StartsWith($temp, [System.StringComparison]::OrdinalIgnoreCase)){ return $true }
  } catch {}
  return $false
}

function Scan-Downloads {
  param($Config, $State)
  if ($Config.monitor_downloads -eq $false) { return }
  Ensure-DownloadState -State $State
  $maxMb = 200
  try { if ($Config.downloads_max_file_mb) { $maxMb = [int]$Config.downloads_max_file_mb } } catch {}
  $downloadDirs = Get-DownloadFolders
  Write-AgentLog ("Download Guard folders=" + (($downloadDirs | ForEach-Object { $_ }) -join ' ; '))
  if (-not $downloadDirs -or $downloadDirs.Count -eq 0) { Write-AgentLog "Download Guard WARNING: no folders found to scan" }
  foreach($downloads in $downloadDirs){
    try {
      $files = Get-ChildItem -Path $downloads -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -le ($maxMb * 1MB) } | Sort-Object LastWriteTime -Descending | Select-Object -First 100
      foreach ($f in $files) {
        $key = "download|$($f.FullName)|$($f.Length)|$($f.LastWriteTimeUtc.Ticks)"
        if ($State.downloads.PSObject.Properties.Name -contains $key) { continue }
        Write-AgentLog "Download Guard new file=$($f.FullName) ext=$($f.Extension) size=$($f.Length)"
        $ext = $f.Extension.ToLowerInvariant()
        $hash = Get-FileSha256 -Path $f.FullName
        if ($ext -eq '.zip') {
          $analysis = Analyze-ZipFile -Path $f.FullName
          $data = @{
            file_name = $f.Name
            path = $f.FullName
            folder = $downloads
            extension = $ext
            size_bytes = [int64]$f.Length
            sha256 = $hash
            entries = $analysis.entries
            suspicious_entries = $analysis.suspicious_entries
            suspicious_count = $analysis.suspicious_count
            encrypted_or_unreadable = $analysis.encrypted_or_unreadable
            verdict = $analysis.verdict
          }
          $msg = "Download Guard scanned ZIP $($f.Name). Path=$($f.FullName). Verdict=$($analysis.verdict). Suspicious=$($analysis.suspicious_count)."
          if ($analysis.verdict -in @('high','suspicious')) { Send-DownloadGuardEvent -Config $Config -EventId 90012 -Message $msg -EventData $data | Out-Null }
          else { Send-DownloadGuardEvent -Config $Config -EventId 90010 -Message $msg -EventData $data | Out-Null }
        } elseif (@('.exe','.msi','.ps1','.bat','.cmd','.vbs','.js','.jse','.wsf','.hta','.scr','.lnk','.dll','.docm','.xlsm') -contains $ext) {
          $data = @{ file_name=$f.Name; path=$f.FullName; folder=$downloads; extension=$ext; size_bytes=[int64]$f.Length; sha256=$hash; verdict='executable_download' }
          $msg = "Download Guard observed executable-like download $($f.Name). Path=$($f.FullName)."
          Send-DownloadGuardEvent -Config $Config -EventId 90011 -Message $msg -EventData $data | Out-Null
        }
        $State.downloads | Add-Member -NotePropertyName $key -NotePropertyValue (Get-Date).ToUniversalTime().ToString("o") -Force
        Save-State -State $State
      }
    } catch { Write-AgentLog "download scan failed folder=${downloads}: $($_.Exception.Message)" }
  }
}


function Ensure-FimState {
  param($State)
  if ($null -eq $State.fim) { $State | Add-Member -NotePropertyName fim -NotePropertyValue @{} -Force }
}

function Send-FimEvent {
  param($Config, [int]$EventId, [string]$Message, $EventData)
  $body = @{
    agent_id = $Config.agent_id
    hostname = $env:COMPUTERNAME
    os_version = (Get-CimInstance Win32_OperatingSystem).Caption
    log_name = "MiniSIEM-FIM"
    provider_name = "MiniSIEMAgent File Integrity Monitor"
    event_id = [int]$EventId
    record_id = [int64](Get-Date -UFormat %s)
    level = "Warning"
    time_created = (Get-Date).ToUniversalTime().ToString("o")
    message = $Message
    event_data = $EventData
  }
  try { Send-Json -Config $Config -Path "/ingest-windows" -Body $body | Out-Null; return $true } catch { Write-AgentLog "fim send failed: $($_.Exception.Message)"; return $false }
}

function Scan-FileIntegrity {
  param($Config, $State)
  Ensure-FimState -State $State
  $paths = @("$env:SystemRoot\System32\drivers\etc\hosts") + (Get-FimFolders)
  $dangerExt = @('.exe','.msi','.ps1','.bat','.cmd','.vbs','.js','.jse','.wsf','.hta','.scr','.lnk','.dll')
  foreach($path in $paths){
    if(!(Test-Path $path)){ continue }
    try {
      if((Get-Item $path).PSIsContainer){
        $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 80
        foreach($f in $files){
          $key = "fim|$($f.FullName)|$($f.Length)|$($f.LastWriteTimeUtc.Ticks)"
          if($State.fim.PSObject.Properties.Name -contains $key){ continue }
          $ext = $f.Extension.ToLowerInvariant()
          if($dangerExt -contains $ext){
            $eid = 90022
            if($path.ToLowerInvariant().Contains('startup')){ $eid = 90021 }
            $data = @{ file_name=$f.Name; path=$f.FullName; extension=$ext; size_bytes=[int64]$f.Length; sha256=(Get-FileSha256 -Path $f.FullName) }
            Send-FimEvent -Config $Config -EventId $eid -Message "FIM observed suspicious file $($f.FullName)" -EventData $data | Out-Null
          }
          $State.fim | Add-Member -NotePropertyName $key -NotePropertyValue (Get-Date).ToUniversalTime().ToString('o') -Force
        }
      } else {
        $hash = Get-FileSha256 -Path $path
        $key = "hash|$path"
        $old = $State.fim.$key
        if($old -and $old -ne $hash){
          $eid = 90020
          if($path.ToLowerInvariant().EndsWith('\hosts')){ $eid = 90023 }
          $data = @{ path=$path; previous_hash=$old; new_hash=$hash; sha256=$hash }
          Send-FimEvent -Config $Config -EventId $eid -Message "FIM detected sensitive file modification: $path" -EventData $data | Out-Null
        }
        $State.fim | Add-Member -NotePropertyName $key -NotePropertyValue $hash -Force
      }
    } catch { Write-AgentLog "fim scan failed path=${path}: $($_.Exception.Message)" }
  }
  Save-State -State $State
}

function Send-DemoEvents {
  param($Config)
  $samples = @(
    @{ event_id=4625; log_name="Security"; provider_name="Microsoft-Windows-Security-Auditing"; message="An account failed to log on. Account Name: david Source Network Address: 203.0.113.77" },
    @{ event_id=4625; log_name="Security"; provider_name="Microsoft-Windows-Security-Auditing"; message="An account failed to log on. Account Name: admin Source Network Address: 203.0.113.77" },
    @{ event_id=4624; log_name="Security"; provider_name="Microsoft-Windows-Security-Auditing"; message="An account was successfully logged on. Account Name: david Source Network Address: 203.0.113.77" },
    @{ event_id=1116; log_name="Microsoft-Windows-Windows Defender/Operational"; provider_name="Microsoft-Windows-Windows Defender"; message="Microsoft Defender Antivirus detected malware or other potentially unwanted software." },
    @{ event_id=4104; log_name="Microsoft-Windows-PowerShell/Operational"; provider_name="Microsoft-Windows-PowerShell"; message="Creating Scriptblock text: powershell -enc SQBFAFgA" }
  )
  $rid = [int64](Get-Date -UFormat %s)
  foreach ($s in $samples) {
    $body = @{
      agent_id = $Config.agent_id
      hostname = $env:COMPUTERNAME
      os_version = (Get-CimInstance Win32_OperatingSystem).Caption
      log_name = $s.log_name
      provider_name = $s.provider_name
      event_id = [int]$s.event_id
      record_id = $rid
      level = "Warning"
      time_created = (Get-Date).ToUniversalTime().ToString("o")
      message = $s.message
      event_data = @{ demo = "true"; source = "MiniSIEMAgent demo" }
    }
    Send-Json -Config $Config -Path "/ingest-windows" -Body $body | Out-Null
    $rid += 1
  }
}


function Invoke-GetJson {
  param($Config, [string]$Path)
  $url = ($Config.backend_url.TrimEnd('/')) + $Path
  $headers = @{ "X-Agent-Token" = $Config.agent_token; "Accept" = "application/json" }
  return Invoke-RestMethod -Uri $url -Method Get -Headers $headers -TimeoutSec 15
}

function Send-ActionResult {
  param($Config, [int]$ActionId, [string]$Status, [string]$Result, [string]$QuarantinePath = "", [string]$Sha256 = "", $Metadata = @{})
  $body = @{ status=$Status; result=$Result; quarantine_path=$QuarantinePath; sha256=$Sha256; metadata=$Metadata }
  try { Send-Json -Config $Config -Path "/edr/actions/$ActionId/result" -Body $body | Out-Null } catch { Write-AgentLog "EDR result send failed action=${ActionId}: $($_.Exception.Message)" }
}

function Send-QuarantineRecord {
  param($Config, [string]$OriginalPath, [string]$QuarantinePath, [string]$Sha256, [string]$Reason, [int]$ActionId, [object]$Action)
  $body = @{
    agent_id = $Config.agent_id
    hostname = $env:COMPUTERNAME
    original_path = $OriginalPath
    quarantine_path = $QuarantinePath
    sha256 = $Sha256
    reason = $Reason
    alert_id = $Action.alert_id
    event_id = $Action.event_id
    status = "quarantined"
    metadata = @{ action_id=$ActionId; action_type=$Action.action_type }
  }
  try { Send-Json -Config $Config -Path "/edr/quarantine" -Body $body | Out-Null } catch { Write-AgentLog "quarantine record send failed action=${ActionId}: $($_.Exception.Message)" }
}

function Invoke-QuarantineFile {
  param($Config, $Action)
  $actionId = [int]$Action.id
  $path = [string]$Action.target_path
  if ([string]::IsNullOrWhiteSpace($path)) { Send-ActionResult -Config $Config -ActionId $actionId -Status "failed" -Result "target_path empty"; return }
  try {
    $full = [System.IO.Path]::GetFullPath($path)
    if(-not (Test-SafeUserFilePath -Path $full)){
      Send-ActionResult -Config $Config -ActionId $actionId -Status "blocked" -Result "Refused to quarantine unsafe path: $full"
      return
    }
    if (!(Test-Path -LiteralPath $full -PathType Leaf)) {
      Send-ActionResult -Config $Config -ActionId $actionId -Status "failed" -Result "File not found: $full"
      return
    }
    $sha = Get-FileSha256 -Path $full
    if ($Action.target_hash -and $sha -and ($sha.ToLowerInvariant() -ne ([string]$Action.target_hash).ToLowerInvariant())) {
      Send-ActionResult -Config $Config -ActionId $actionId -Status "failed" -Result "Hash mismatch. Expected $($Action.target_hash), got $sha" -Sha256 $sha
      return
    }
    $qdir = Join-Path $env:ProgramData "MiniSIEMAgent\Quarantine"
    New-Item -ItemType Directory -Force -Path $qdir | Out-Null
    $safeName = ([System.IO.Path]::GetFileName($full) -replace '[^a-zA-Z0-9._-]', '_')
    $ts = Get-Date -Format "yyyyMMddHHmmss"
    $dest = Join-Path $qdir ("${ts}_${sha}_$safeName.quarantine")
    Move-Item -LiteralPath $full -Destination $dest -Force
    $meta = @{
      original_path = $full
      quarantine_path = $dest
      sha256 = $sha
      reason = $Action.requested_reason
      action_id = $actionId
      quarantined_at = (Get-Date).ToUniversalTime().ToString("o")
    }
    ($meta | ConvertTo-Json -Depth 8) | Set-Content -Encoding UTF8 ($dest + ".json")
    Send-QuarantineRecord -Config $Config -OriginalPath $full -QuarantinePath $dest -Sha256 $sha -Reason ([string]$Action.requested_reason) -ActionId $actionId -Action $Action
    Send-ActionResult -Config $Config -ActionId $actionId -Status "completed" -Result "File moved to quarantine" -QuarantinePath $dest -Sha256 $sha -Metadata $meta
    Write-AgentLog "EDR quarantine completed action=$actionId path=$full"
  } catch {
    Send-ActionResult -Config $Config -ActionId $actionId -Status "failed" -Result $_.Exception.Message
    Write-AgentLog "EDR quarantine failed action=${actionId}: $($_.Exception.Message)"
  }
}


function Invoke-DeleteFileSafe {
  param($Config, $Action)
  $actionId = [int]$Action.id
  $path = [string]$Action.target_path
  if ([string]::IsNullOrWhiteSpace($path)) { Send-ActionResult -Config $Config -ActionId $actionId -Status "failed" -Result "target_path empty"; return }
  try {
    $full = [System.IO.Path]::GetFullPath($path)
    if(-not (Test-SafeUserFilePath -Path $full)){
      Send-ActionResult -Config $Config -ActionId $actionId -Status "blocked" -Result "Refused to delete unsafe path: $full"
      return
    }
    if (!(Test-Path -LiteralPath $full -PathType Leaf)) {
      Send-ActionResult -Config $Config -ActionId $actionId -Status "failed" -Result "File not found: $full"
      return
    }
    $sha = Get-FileSha256 -Path $full
    if ($Action.target_hash -and $sha -and ($sha.ToLowerInvariant() -ne ([string]$Action.target_hash).ToLowerInvariant())) {
      Send-ActionResult -Config $Config -ActionId $actionId -Status "failed" -Result "Hash mismatch. Expected $($Action.target_hash), got $sha" -Sha256 $sha
      return
    }
    $meta = @{ original_path=$full; sha256=$sha; reason=$Action.requested_reason; action_id=$actionId; deleted_at=(Get-Date).ToUniversalTime().ToString("o") }
    Remove-Item -LiteralPath $full -Force
    Send-ActionResult -Config $Config -ActionId $actionId -Status "completed" -Result "File deleted safely by MiniSIEM Agent" -Sha256 $sha -Metadata $meta
    Write-AgentLog "EDR delete completed action=$actionId path=$full"
  } catch {
    Send-ActionResult -Config $Config -ActionId $actionId -Status "failed" -Result $_.Exception.Message
    Write-AgentLog "EDR delete failed action=${actionId}: $($_.Exception.Message)"
  }
}

function Poll-EDRActions {
  param($Config)
  if ($Config.edr_enabled -eq $false) { return }
  try {
    $path = "/edr/actions/pending?agent_id=$([uri]::EscapeDataString($Config.agent_id))&hostname=$([uri]::EscapeDataString($env:COMPUTERNAME))"
    $actions = Invoke-GetJson -Config $Config -Path $path
    foreach($a in $actions){
      if($a.action_type -eq "quarantine_file") { Invoke-QuarantineFile -Config $Config -Action $a }
      elseif($a.action_type -eq "delete_file") { Invoke-DeleteFileSafe -Config $Config -Action $a }
      else { Send-ActionResult -Config $Config -ActionId ([int]$a.id) -Status "skipped" -Result "Unsupported local agent action: $($a.action_type)" }
    }
  } catch {
    Write-AgentLog "EDR polling failed: $($_.Exception.Message)"
  }
}


try {
  $Config = Load-Config -Path $ConfigPath
  New-Item -ItemType Directory -Force -Path (Join-Path $env:ProgramData "MiniSIEMAgent") | Out-Null
  if ($DemoOnce) {
    Send-Heartbeat -Config $Config
    Send-DemoEvents -Config $Config
    Write-AgentLog "demo events sent"
    exit 0
  }
  Write-AgentLog "MiniSIEMAgent v15.3 started. backend=$($Config.backend_url) serviceMode=$ServiceMode"
  do {
    $State = Load-State
    Send-Heartbeat -Config $Config
    Read-And-Send -Config $Config -State $State
    Scan-Downloads -Config $Config -State $State
    Scan-FileIntegrity -Config $Config -State $State
    Poll-EDRActions -Config $Config
    if ($ServiceMode) { Start-Sleep -Seconds ([int]$Config.poll_seconds) }
  } while ($ServiceMode)
  Write-AgentLog "MiniSIEMAgent v15.3 finished one collection cycle"
} catch {
  Write-AgentLog "fatal: $($_.Exception.Message)"
  exit 1
}
