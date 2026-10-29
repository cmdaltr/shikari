<#
.SYNOPSIS
Saves this machine's logs for given time windows, in the lab recorder's layout, for steps something
else ran here: a CALDERA operation's links (archer/lab/caldera.py, #30).

.DESCRIPTION
The same log sources as record-atomics.ps1, read back after the fact, so it runs nothing but
the log readers. PowerShell 7, elevated. Each window is a step; its logs land in <Out>/<Run>/<folder>
beside a manifest.json that archer/telemetry/lab.py reads like any other lab run.

  Windows  events.xml      Security, System, PowerShell, Sysmon (if installed), Task Scheduler, WMI, Defender, BITS
  Linux    audit.log       auditd, by each record's epoch
           journal.log     the systemd journal, syslog format
  macOS    unified.ndjson  the unified log

Endpoint Security (eslogger) and the launch-item diff only exist live, so a capture after the
fact has neither on macOS; record-atomics.ps1 does.

-Windows is a JSON file: [{"technique": "T1057", "folder": "T1057-1", "name": "...", "start": "<UTC ISO>", "end": "<UTC ISO>"}]

.EXAMPLE
sudo pwsh ./capture-window.ps1 -Windows windows.json -Run caldera-op1 -Tool CALDERA
#>
param(
    [Parameter(Mandatory)][string]$Windows,
    [Parameter(Mandatory)][string]$Run,
    [string]$Out = (Join-Path $PWD 'archer-lab'),
    [string]$Tool = 'CALDERA'
)
$ErrorActionPreference = 'Stop'

# $IsWindows/$IsMacOS/$IsLinux are PowerShell 7 automatic variables; Windows PowerShell 5.1 — which
# Lab invokes as `powershell` (archer.lab.record._pwsh) — leaves them undefined, so without this the
# platform would misdetect as linux and nothing would be captured. 5.1 only runs on Windows.
if ($null -eq $IsWindows) { $IsWindows = $true; $IsLinux = $false; $IsMacOS = $false }

$platform = if ($IsWindows) { 'windows' } elseif ($IsMacOS) { 'macos' } else { 'linux' }
$hostName = ([Environment]::MachineName).ToLower()
$runDir = Join-Path $Out $Run
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$manifest = [ordered]@{ run = $Run; host = $hostName; platform = $platform; tool = $Tool
                        started = (Get-Date).ToUniversalTime().ToString('o'); tests = @() }

$windowsLogs = 'Security', 'System', 'Application', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-Bits-Client/Operational', 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
$present = if ($IsWindows) { Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LogName } else { @() }

$i = 0
foreach ($w in (Get-Content $Windows -Raw | ConvertFrom-Json)) {
    $i++
    # ConvertFrom-Json already turns ISO strings into DateTime; [datetime] keeps either form working
    $start = ([datetime]$w.start).ToUniversalTime(); $end = ([datetime]$w.end).ToUniversalTime()
    $dir = Join-Path $runDir $w.folder
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Write-Host "==> $($w.technique) ($($w.folder)): $($start.ToString('o')) to $($end.ToString('o'))"

    if ($IsWindows) {
        $xml = foreach ($log in $windowsLogs | Where-Object { $present -contains $_ }) {
            Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start.ToLocalTime(); EndTime = $end.ToLocalTime() } -ErrorAction SilentlyContinue | ForEach-Object { $_.ToXml() }
        }
        if ($xml) { $xml | Set-Content -Path (Join-Path $dir 'events.xml') -Encoding utf8 }
    } elseif ($IsLinux) {
        $from = ([DateTimeOffset]$start).ToUnixTimeSeconds(); $to = ([DateTimeOffset]$end).ToUnixTimeSeconds()
        $logs = Get-ChildItem /var/log/audit -Filter 'audit.log*' -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -ne '.gz' }
        if ($logs) {
            $logs | Get-Content | Where-Object {
                $_ -match 'msg=audit\((\d+)\.' -and [long]$Matches[1] -ge $from -and [long]$Matches[1] -le $to
            } | Set-Content (Join-Path $dir 'audit.log')
        } else { Write-Warning 'auditd not installed or not logging: no audit.log' }
        & journalctl --since "@$from" --until "@$to" -o short --no-pager 2>$null | Set-Content (Join-Path $dir 'journal.log')
    } else {
        & /usr/bin/log show --start $start.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss') --end $end.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss') --style ndjson 2>$null | Set-Content (Join-Path $dir 'unified.ndjson')
    }

    $manifest.tests += [ordered]@{ technique = $w.technique; test = $i; name = $w.name; folder = $w.folder
                                   start = $start.ToString('yyyy-MM-ddTHH:mm:ssZ'); end = $end.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $runDir 'manifest.json')
}
Write-Host "Captured $($manifest.tests.Count) windows in $runDir"
