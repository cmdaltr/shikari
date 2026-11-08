<#
.SYNOPSIS
Turns on the Windows logging Shikari's lab recordings read: Sysmon, process-creation auditing (4688)
with command lines, and PowerShell script block and module logging.

.DESCRIPTION
Run once, elevated, on a lab machine before record-atomics.ps1, record-custom.ps1 or a CALDERA capture
(capture-window.ps1). Without it a recording holds only what Windows logs by default: no Sysmon, and no
4688 because Process Creation auditing is off on Windows client.

  Sysmon        from Sysinternals, with a lab config that logs every process (1), network connection (3),
                file created (11), registry change (12-14), DNS query (22), remote thread (8) and
                process tampering (25). Too much for production; right for a short recording window.
                Installs Sysmon64a.exe on ARM64 Windows, Sysmon64.exe on x64. Re-running updates the config.
  4688          Audit Process Creation (success) and "Include command line in process creation events"
  PowerShell    script block logging (4104) and module logging (4103) for every module
  Log sizes     Security and Sysmon logs raised to 1 GB so a run's events aren't rolled over

For a lab machine only: the Sysmon config and PowerShell logging are verbose by design.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\prepare-windows.ps1
#>
param(
    [string]$SysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
)
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell (Run as administrator)'
}

$config = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>MD5,SHA256,IMPHASH</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <RuleGroup name="Shikari lab: log everything" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
      <NetworkConnect onmatch="exclude"/>
      <FileCreate onmatch="exclude"/>
      <RegistryEvent onmatch="exclude"/>
      <DnsQuery onmatch="exclude"/>
      <CreateRemoteThread onmatch="exclude"/>
      <ProcessTampering onmatch="exclude"/>
      <ProcessTerminate onmatch="include"/>
      <ImageLoad onmatch="include"/>
      <ProcessAccess onmatch="include"/>
      <RawAccessRead onmatch="include"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@

Write-Host '[1/4] Sysmon'
$work = Join-Path $env:TEMP 'shikari-sysmon'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$configPath = Join-Path $work 'shikari-sysmon.xml'
Set-Content -Path $configPath -Value $config -Encoding UTF8
$exe = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'Sysmon64a.exe' } else { 'Sysmon64.exe' }
$service = Get-Service -Name Sysmon64, Sysmon64a, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
if ($service) {
    $installed = (Get-CimInstance Win32_Service -Filter "Name='$($service.Name)'").PathName.Trim('"')
    & $installed -c $configPath | Out-Null
    Write-Host "      OK  $($service.Name) was installed; config updated"
} else {
    $zip = Join-Path $work 'Sysmon.zip'
    Invoke-WebRequest -UseBasicParsing -Uri $SysmonUrl -OutFile $zip
    Expand-Archive -Force -Path $zip -DestinationPath $work
    $bin = Join-Path $work $exe
    if (-not (Test-Path $bin)) { throw "$exe isn't in $SysmonUrl" }
    $sig = Get-AuthenticodeSignature $bin
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "$exe isn't signed by Microsoft ($($sig.Status)): not installing it"
    }
    & $bin -accepteula -i $configPath | Out-Null
    Write-Host "      OK  $exe installed with the lab config"
}

Write-Host '[2/4] Process creation auditing (4688) with command lines'
# By GUID, so it works whatever the display language
& auditpol /set /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
$audit = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Force -Path $audit | Out-Null
Set-ItemProperty -Path $audit -Name ProcessCreationIncludeCmdLine_Enabled -Type DWord -Value 1
Write-Host '      OK'

Write-Host '[3/4] PowerShell script block and module logging'
$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
New-Item -Force -Path "$ps\ScriptBlockLogging" | Out-Null
Set-ItemProperty -Path "$ps\ScriptBlockLogging" -Name EnableScriptBlockLogging -Type DWord -Value 1
New-Item -Force -Path "$ps\ModuleLogging\ModuleNames" | Out-Null
Set-ItemProperty -Path "$ps\ModuleLogging" -Name EnableModuleLogging -Type DWord -Value 1
Set-ItemProperty -Path "$ps\ModuleLogging\ModuleNames" -Name '*' -Type String -Value '*'
Write-Host '      OK'

Write-Host '[4/4] Log sizes'
& wevtutil sl Security /ms:1073741824
& wevtutil sl 'Microsoft-Windows-Sysmon/Operational' /ms:1073741824
Write-Host '      OK'

$check = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction SilentlyContinue
Write-Host ''
Write-Host "  Ready. Sysmon is logging$(if ($check) { '' } else { ' (no events yet: run anything and check Event Viewer)' })."
Write-Host '  4688 and PowerShell logging apply to processes started from now on.'
