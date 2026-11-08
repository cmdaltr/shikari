<#
.SYNOPSIS
Records the telemetry of an arbitrary operator-supplied command for Shikari's Emulate page - a novel or
undocumented technique, a custom procedure variant, something no public corpus or Atomic Red Team covers
(shikari/telemetry/lab.py, #27).

.DESCRIPTION
A sibling to record-atomics.ps1. Instead of invoking an Atomic test, it wraps a command you give it,
captures the identical per-platform telemetry set between the command's start and end, and writes the
same data/telemetry/lab/<run>/ layout - with a manifest entry marked `custom` that carries your own
ATT&CK mapping (a technique, a sub-technique, or explicitly novel/unmapped), the command, and notes. The
recording then grounds generated detection fields exactly as an ART run does, including for behaviours
with no public procedure example.

DANGER. This EXECUTES WHATEVER YOU PASS IT, which for novel/undocumented behaviour is unvetted and may be
genuinely malicious. Run it only on a disposable machine you can throw away - a snapshot-and-revert VM, or
inside sbx. It refuses to run unless the machine is a designated lab host: set SHIKARI_LAB_HOST=1 (or
create ~/.shikari-lab-host), or pass -IAmADisposableLabHost. Never designate a host that matters.

PowerShell 7 (or Windows PowerShell 5.1 on Windows), elevated (an administrator prompt, or sudo pwsh), same logging prerequisites as
record-atomics.ps1 (on Windows, run prepare-windows.ps1 once for Sysmon, 4688 and PowerShell logging;
auditd on Linux, eslogger + Full Disk Access on macOS). Captured sources:
  Windows  events.xml      Security, System, PowerShell, Sysmon (if installed), Task Scheduler, WMI, Defender, BITS
  Linux    audit.log       auditd, by each record's epoch
           journal.log     the systemd journal, syslog format
  macOS    es.ndjson       Endpoint Security events (eslogger)
           unified.ndjson  the unified log
           plists.ndjson   launch agents, daemons and login items changed

Call it again with the same -Run to add more executions to one run. Copy the run's folder to Shikari's
data/telemetry/lab/ and press Update on the Emulate page.

.EXAMPLE
sudo pwsh ./record-custom.ps1 -Command 'rundll32 .\payload.dll,Start' -Name 'novel dll persistence' -MappingKind novel

.EXAMPLE
sudo pwsh ./record-custom.ps1 -ScriptPath ./variant.sh -Name 'cron variant' -Mapping T1053.003 -MappingKind sub -Notes 'per-second schedule'
#>
param(
    [string]$Command,
    [string]$ScriptPath,
    [Parameter(Mandatory)][string]$Name,
    [string]$Mapping = '',
    [ValidateSet('sub', 'parent', 'novel')][string]$MappingKind = 'novel',
    [string]$Notes = '',
    [string]$Run = "$([Environment]::MachineName.ToLower())-$(Get-Date -Format yyyyMMdd-HHmm)",
    [string]$Out = (Join-Path $PWD 'shikari-lab'),
    [int]$Settle = 20,
    [int]$Timeout = 120,
    [switch]$IAmADisposableLabHost
)
$ErrorActionPreference = 'Stop'

# $IsWindows/$IsMacOS/$IsLinux are PowerShell 7 automatic variables; Windows PowerShell 5.1 leaves them
# undefined, and without this the platform would misdetect as linux. 5.1 only runs on Windows.
if ($null -eq $IsWindows) { $IsWindows = $true; $IsLinux = $false; $IsMacOS = $false }

# -- Lab-host gate (#27): refuse to detonate unvetted code on a machine that isn't opted in ----------
$truthy = @('1', 'true', 'yes', 'on')
$designated = $IAmADisposableLabHost -or
    ($truthy -contains ("$env:SHIKARI_LAB_HOST").ToLower()) -or
    (Test-Path (Join-Path $HOME '.shikari-lab-host'))
if (-not $designated) {
    throw "This machine isn't a designated lab host. record-custom.ps1 executes unvetted code and will " +
          "only run on a disposable machine. Set SHIKARI_LAB_HOST=1, create $HOME/.shikari-lab-host, or " +
          "pass -IAmADisposableLabHost - on a snapshot-and-revert VM or inside sbx, never a host that matters."
}
if (-not $Command -and -not $ScriptPath) { throw 'Give -Command or -ScriptPath.' }
if ($Command -and $ScriptPath) { throw 'Give -Command or -ScriptPath, not both.' }

$platform = if ($IsWindows) { 'windows' } elseif ($IsMacOS) { 'macos' } else { 'linux' }
$hostName = ([Environment]::MachineName).ToLower()
$runDir = Join-Path $Out $Run
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

# Append to an existing run, so several custom executions share one run folder/manifest.
$manifestPath = Join-Path $runDir 'manifest.json'
if (Test-Path $manifestPath) {
    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
    $tests = @($manifest.tests)
} else {
    $manifest = [ordered]@{ run = $Run; host = $hostName; platform = $platform; tool = 'Custom execution'
                            started = (Get-Date).ToUniversalTime().ToString('o'); tests = @() }
    $tests = @()
}
$n = $tests.Count + 1
$folder = "custom-$n"
$dir = Join-Path $runDir $folder
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$windowsLogs = 'Security', 'System', 'Application', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-Bits-Client/Operational', 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
$esEvents = 'exec', 'fork', 'create', 'rename', 'unlink', 'write', 'btm_launch_item_add', 'btm_launch_item_remove',
    'login_login', 'authentication', 'sudo', 'su', 'xp_malware_detected', 'tcc_modify', 'profile_add', 'od_create_user',
    'od_group_add', 'screensharing_attach', 'openssh_login', 'mount', 'kextload', 'setowner', 'setmode', 'signal'
if ($IsMacOS) {
    $supported = (& /usr/bin/eslogger --list-events) -split "`n" | ForEach-Object { $_.Trim() }
    $esEvents = $esEvents | Where-Object { $supported -contains $_ }
}

function Get-PlistState {
    $paths = @('/Library/LaunchAgents', '/Library/LaunchDaemons', '/Library/Preferences/com.apple.loginwindow.plist') +
        (Get-ChildItem /Users -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'Library/LaunchAgents' })
    $state = @{}
    foreach ($p in $paths) {
        Get-ChildItem -Path $p -Filter *.plist -File -ErrorAction SilentlyContinue | ForEach-Object {
            $state[$_.FullName] = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        }
    }
    $state
}
function Write-PlistChanges($before, $after, $file) {
    $lines = foreach ($path in (@($before.Keys) + @($after.Keys) | Sort-Object -Unique)) {
        $change = if (-not $before.ContainsKey($path)) { 'added' } elseif (-not $after.ContainsKey($path)) { 'removed' }
                  elseif ($before[$path] -ne $after[$path]) { 'changed' } else { $null }
        if (-not $change) { continue }
        $entry = [ordered]@{ plist = $change; path = $path }
        if ($change -ne 'removed') {
            try {
                $doc = & /usr/bin/plutil -convert json -o - $path 2>$null | ConvertFrom-Json
                $entry.Label = $doc.Label; $entry.ProgramArguments = ($doc.ProgramArguments -join ' '); $entry.Program = $doc.Program
            } catch { }
        }
        $entry | ConvertTo-Json -Compress
    }
    if ($lines) { $lines | Set-Content -Path $file }
}

$display = if ($ScriptPath) { "script $ScriptPath" } else { $Command }
Write-Host "==> custom ${n}: $Name  [$display]"

$es = $null
if ($IsMacOS) {
    $plistsBefore = Get-PlistState
    $es = Start-Process -FilePath /usr/bin/eslogger -ArgumentList $esEvents -RedirectStandardOutput (Join-Path $dir 'es.ndjson') -PassThru -NoNewWindow
    Start-Sleep -Seconds 2
}

$start = Get-Date
# Run the operator's command in a job so it can be time-bounded. It runs with this (elevated) session's
# privileges - that's the point, and why this only runs on a throwaway machine.
$job = if ($ScriptPath) {
    Start-Job -ScriptBlock { param($p) & $p } -ArgumentList $ScriptPath
} else {
    Start-Job -ScriptBlock { param($c) Invoke-Expression $c } -ArgumentList $Command
}
if (-not (Wait-Job $job -Timeout $Timeout)) { Write-Warning "command still running after ${Timeout}s; stopping it"; Stop-Job $job }
Receive-Job $job -ErrorAction SilentlyContinue | Out-Null
Remove-Job $job -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds $Settle
$end = Get-Date

if ($IsWindows) {
    $present = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LogName
    $xml = foreach ($log in $windowsLogs | Where-Object { $present -contains $_ }) {
        Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start; EndTime = $end } -ErrorAction SilentlyContinue | ForEach-Object { $_.ToXml() }
    }
    if ($xml) { $xml | Set-Content -Path (Join-Path $dir 'events.xml') -Encoding utf8 }
} elseif ($IsLinux) {
    $from = [DateTimeOffset]$start.ToUniversalTime(); $to = [DateTimeOffset]$end.ToUniversalTime()
    $logs = Get-ChildItem /var/log/audit -Filter 'audit.log*' -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -ne '.gz' }
    if ($logs) {
        $logs | Get-Content | Where-Object {
            $_ -match 'msg=audit\((\d+)\.' -and [long]$Matches[1] -ge $from.ToUnixTimeSeconds() -and [long]$Matches[1] -le $to.ToUnixTimeSeconds()
        } | Set-Content (Join-Path $dir 'audit.log')
    } else { Write-Warning 'auditd not installed or not logging: no audit.log' }
    & journalctl --since $start.ToString('yyyy-MM-dd HH:mm:ss') --until $end.ToString('yyyy-MM-dd HH:mm:ss') -o short --no-pager 2>$null | Set-Content (Join-Path $dir 'journal.log')
} else {
    Stop-Process -Id $es.Id -ErrorAction SilentlyContinue
    & /usr/bin/log show --start $start.ToString('yyyy-MM-dd HH:mm:ss') --end $end.ToString('yyyy-MM-dd HH:mm:ss') --style ndjson 2>$null | Set-Content (Join-Path $dir 'unified.ndjson')
    Write-PlistChanges $plistsBefore (Get-PlistState) (Join-Path $dir 'plists.ndjson')
}

$entry = [ordered]@{
    custom = $true; folder = $folder; name = $Name
    command = if ($ScriptPath) { "script:$ScriptPath" } else { $Command }
    mapping = $Mapping; mapping_kind = $MappingKind; notes = $Notes
    provenance = "$([Environment]::UserName)@$hostName"
    start = $start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); end = $end.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}
$manifest.tests = @($tests) + $entry
$manifest | ConvertTo-Json -Depth 5 | Set-Content $manifestPath
Write-Host "Recorded custom execution '$Name' ($folder) in $runDir"
