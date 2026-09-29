param(
    [string]$LogFile = "$env:USERPROFILE\Downloads\router_log.txt",
    [string]$TargetHost = "127.0.0.1",
    [int]$TargetPort = 5514,
    [int]$DelayMs = 80
)

if (-not (Test-Path -LiteralPath $LogFile)) {
    Write-Host "No existeix el fitxer: $LogFile" -ForegroundColor Red
    exit 1
}

Write-Host "Enviant logs del router al Mini-SIEM..."
Write-Host "Fitxer: $LogFile"
Write-Host "Destí: $TargetHost`:$TargetPort/udp"

$udp = New-Object System.Net.Sockets.UdpClient
$count = 0

try {
    Get-Content -LiteralPath $LogFile -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()

        if ([string]::IsNullOrWhiteSpace($line)) {
            return
        }

        # Si la línia no porta capçalera syslog, li afegim una.
        if ($line -notmatch '^<\d+>') {
            $line = "<13>TP-Link Archer C80: $line"
        }

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
        [void]$udp.Send($bytes, $bytes.Length, $TargetHost, $TargetPort)

        $count++
        Write-Host "[$count] $line"

        Start-Sleep -Milliseconds $DelayMs
    }
}
finally {
    $udp.Close()
}

Write-Host ""
Write-Host "Enviats $count missatges al Mini-SIEM." -ForegroundColor Green