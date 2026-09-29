$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Out = Join-Path $Root "dist"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Package = Join-Path $Out "payload"
Remove-Item -Recurse -Force $Package -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $Package | Out-Null
Copy-Item "$Root\MiniSIEMAgent.ps1" $Package -Force
Copy-Item "$Root\Install-MiniSIEMAgent.ps1" $Package -Force
Copy-Item "$Root\Uninstall-MiniSIEMAgent.ps1" $Package -Force
Copy-Item "$Root\Setup-MiniSIEMAgent.cmd" $Package -Force

$Sed = Join-Path $Out "MiniSIEMAgentSetup.sed"
$Exe = Join-Path $Out "MiniSIEMAgentSetup.exe"
$files = @("MiniSIEMAgent.ps1", "Install-MiniSIEMAgent.ps1", "Uninstall-MiniSIEMAgent.ps1", "Setup-MiniSIEMAgent.cmd")
$fileSection = ""
for ($i=0; $i -lt $files.Count; $i++) { $fileSection += "FILE$($i)=`"$($files[$i])`"`r`n" }

@"
[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=1
HideExtractAnimation=0
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=Mini-SIEM Sentinel Agent v9 will be installed on this computer.
DisplayLicense=
FinishMessage=Mini-SIEM Agent installer finished.
TargetName=$Exe
FriendlyName=Mini-SIEM Sentinel Agent Setup
AppLaunched=Setup-MiniSIEMAgent.cmd
PostInstallCmd=<None>
AdminQuietInstCmd=Setup-MiniSIEMAgent.cmd
UserQuietInstCmd=Setup-MiniSIEMAgent.cmd
SourceFiles=SourceFiles
[SourceFiles]
SourceFiles0=$Package\
[SourceFiles0]
$fileSection
"@ | Set-Content -Encoding ASCII $Sed

$iexpress = Join-Path $env:SystemRoot "System32\iexpress.exe"
if (!(Test-Path $iexpress)) { throw "iexpress.exe not found. It is included in most Windows installations." }
& $iexpress /N /Q $Sed
Write-Host "Generated: $Exe" -ForegroundColor Green
