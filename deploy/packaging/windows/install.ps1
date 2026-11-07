<#
.SYNOPSIS
Install the self-contained Shikari team server as a Windows service (#29).

.DESCRIPTION
Runs from an unpacked shikari-server Windows bundle (built by deploy/packaging/build_server_pkg_windows.ps1).
The bundle carries its own Python - no system Python, no venv, no checkout. This copies it to -InstallDir,
points the bundled interpreter at the app, seeds %ProgramData%\Shikari\shikari.env on first install, and
registers a first-class SCM service (pywin32) that starts at boot and restarts on failure.

Run in an elevated PowerShell from the unpacked bundle:
    .\install.ps1 [-InstallDir 'C:\Program Files\Shikari'] [-DataDir "$env:ProgramData\Shikari"]

Re-running upgrades in place: it stops the service, refreshes code and Python, and starts it again,
leaving the data dir and shikari.env untouched.
#>
param(
    [string]$InstallDir = 'C:\Program Files\Shikari',
    [string]$DataDir = (Join-Path $env:ProgramData 'Shikari')
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this in an elevated PowerShell (Run as administrator).'
}

$bundle = $PSScriptRoot
if (-not (Test-Path (Join-Path $bundle 'python\python.exe')) -or -not (Test-Path (Join-Path $bundle 'app'))) {
    throw "This doesn't look like an unpacked Shikari server bundle (no python\ or app\ beside install.ps1)."
}
$python = Join-Path $InstallDir 'python\python.exe'
$svc = Get-Service -Name 'Shikari' -ErrorAction SilentlyContinue

Write-Host "==> Shikari team-server (service) install"
Write-Host "    install: $InstallDir   data: $DataDir"

# Stop the old service before overwriting its files.
if ($svc -and $svc.Status -ne 'Stopped') {
    Write-Host "Stopping the running Shikari service"
    Stop-Service 'Shikari' -Force
    (Get-Service 'Shikari').WaitForStatus('Stopped', '00:00:30')
}

# --- lay down code + Python ----------------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($part in 'python', 'app') {
    $dst = Join-Path $InstallDir $part
    if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
    Copy-Item -Recurse -Force (Join-Path $bundle $part) $dst
}

# Make the app importable by the bundled interpreter (InstallDir can differ from build time, so write
# the path now rather than baking it into the bundle).
$sitePackages = (& $python -c "import sysconfig; print(sysconfig.get_path('purelib'))").Trim()
Set-Content -Path (Join-Path $sitePackages 'shikari-app.pth') -Value (Join-Path $InstallDir 'app') -Encoding ASCII

# --- data + config -------------------------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$envFile = Join-Path $DataDir 'shikari.env'
if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path $bundle 'shikari.env.example') $envFile
    # Pin SHIKARI_HOME to the actual data dir (the service uses it as its working directory, and it
    # must be a valid Windows path - not the example's default - whenever -DataDir was overridden).
    $lines = Get-Content $envFile
    if ($lines -match '^\s*SHIKARI_HOME\s*=') {
        $lines = $lines -replace '^\s*SHIKARI_HOME\s*=.*', "SHIKARI_HOME=$DataDir"
    } else {
        $lines += "SHIKARI_HOME=$DataDir"
    }
    Set-Content -Path $envFile -Value $lines -Encoding ASCII
    Write-Host "Wrote $envFile (edit host/port there, then restart the service)"
}

# Seed the ATT&CK STIX cache so the service starts without network on first boot (it refreshes online).
$cacheDir = Join-Path $DataDir 'shikari\data\cache'
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
$cacheFile = Join-Path $cacheDir 'enterprise-attack.json'
$seed = Join-Path $bundle 'enterprise-attack.json'
if ((-not (Test-Path $cacheFile)) -and (Test-Path $seed)) { Copy-Item $seed $cacheFile }

# --- register / refresh the service --------------------------------------------------------------
$svcModule = @('-m', 'shikari.win_service')
if ($svc) {
    Write-Host "Updating the existing Shikari service"
} else {
    Write-Host "Registering the Shikari service"
    & $python @svcModule --startup auto install
    if ($LASTEXITCODE) { throw "service registration failed ($LASTEXITCODE)" }
}
# Restart on failure (SCM recovery): restart after 5s on the first two failures, reset the count daily.
& sc.exe failure Shikari reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
& $python @svcModule --startup auto update | Out-Null

Start-Service 'Shikari'
(Get-Service 'Shikari').WaitForStatus('Running', '00:00:30')

# --- health check ---------------------------------------------------------------------------------
$cfg = @{}
Get-Content $envFile | ForEach-Object {
    if ($_ -match '^\s*([^#=]+?)\s*=\s*(.*?)\s*$') { $cfg[$matches[1]] = $matches[2].Trim('"').Trim("'") }
}
$port = if ($cfg['SHIKARI_PORT']) { $cfg['SHIKARI_PORT'] } else { '32453' }
Write-Host "Waiting for Shikari to answer on 127.0.0.1:$port ..."
$ok = $false
# Cold start is slow: the service spawns the bundled Python, which starts uvicorn, imports the app and
# loads the ATT&CK bundle - comfortably over 30s on a small box. Wait up to ~90s before warning.
foreach ($i in 1..90) {
    try {
        if ((Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/health" -TimeoutSec 2).StatusCode -eq 200) { $ok = $true; break }
    } catch { Start-Sleep 1 }
}
if ($ok) { Write-Host "Shikari is up. Put a reverse proxy on 443 in front of 127.0.0.1:$port." }
else { Write-Warning "No /health yet - check the Event Log and 'Get-Service Shikari'." }
