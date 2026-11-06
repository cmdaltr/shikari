<#
.SYNOPSIS
Build, install and smoke-test the self-contained Shikari server bundle on this Windows box (#29).

.DESCRIPTION
Run from (or pointed at) a Shikari checkout, in an elevated PowerShell, on a throwaway Windows Server VM.
It builds the bundle (its own Python + deps + pywin32), unpacks it, runs the bundled install.ps1 to
register the SCM service, waits for /health, prints the result, and uninstalls again unless you pass -Keep.

    .\verify-windows.ps1                       # build x64 (or ARM64 on an ARM64 host), install, test, remove
    .\verify-windows.ps1 -Arch aarch64         # force an architecture
    .\verify-windows.ps1 -Keep                 # leave the service installed and running
    $env:SHIKARI_REPO='C:\src\shikari'; .\verify-windows.ps1    # checkout elsewhere

Needs: a working `python` on PATH only to read the version for the zip name (optional); the build itself
downloads its own CPython. Run elevated - install.ps1 registers a system service.
#>
param(
    [ValidateSet('x86_64', 'aarch64')]
    [string]$Arch = $(if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { 'x86_64' }),
    [switch]$Keep
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this in an elevated PowerShell (Run as administrator).'
}

# Repo root: $env:SHIKARI_REPO, else three levels up (deploy\packaging\verify\ -> repo), else the cwd.
$here = $PSScriptRoot
$repo = if ($env:SHIKARI_REPO) { $env:SHIKARI_REPO } else { (Resolve-Path (Join-Path $here '..\..\..')).Path }
if (-not (Test-Path (Join-Path $repo 'deploy\packaging\build_server_pkg_windows.ps1'))) { $repo = (Get-Location).Path }
if (-not (Test-Path (Join-Path $repo 'deploy\packaging\build_server_pkg_windows.ps1'))) {
    throw "Can't find the Shikari checkout. Run from inside it or set `$env:SHIKARI_REPO."
}

$dist = Join-Path $repo 'dist'
Write-Host "==> Building the Windows bundle ($Arch; downloads CPython + deps)"
& (Join-Path $repo 'deploy\packaging\build_server_pkg_windows.ps1') -Arch $Arch -Out $dist
if ($LASTEXITCODE) { throw "build failed ($LASTEXITCODE)" }

$suffix = if ($Arch -eq 'aarch64') { 'arm64' } else { 'x64' }
$zip = Get-ChildItem (Join-Path $dist "shikari-server_*_windows-$suffix.zip") | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $zip) { throw "no bundle produced in $dist" }
Write-Host "==> Built $($zip.FullName)"

$unpack = Join-Path $env:TEMP ("shikari-verify-" + [Guid]::NewGuid())
Expand-Archive -Path $zip.FullName -DestinationPath $unpack

Write-Host "==> Installing (registers the Shikari service)"
& (Join-Path $unpack 'install.ps1')

$envFile = Join-Path $env:ProgramData 'Shikari\shikari.env'
$port = '8000'
if (Test-Path $envFile) {
    $m = Select-String -Path $envFile -Pattern '^\s*SHIKARI_PORT\s*=\s*(.+?)\s*$' | Select-Object -First 1
    if ($m) { $port = $m.Matches[0].Groups[1].Value.Trim('"').Trim("'") }
}

Write-Host "==> Waiting for the service on 127.0.0.1:$port"
$python = 'C:\Program Files\Shikari\python\python.exe'
& $python (Join-Path $here 'healthcheck.py') --url "http://127.0.0.1:$port/health" --timeout 120
$ok = ($LASTEXITCODE -eq 0)

Write-Host "==> Service state:"; Get-Service Shikari | Format-List Name, Status, StartType
if (-not $ok) {
    Write-Warning "/health never answered. Recent Shikari events:"
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Shikari' } -MaxEvents 20 -ErrorAction SilentlyContinue |
        Format-Table TimeCreated, LevelDisplayName, Message -Wrap
}

if ($Keep) {
    Write-Host "==> -Keep: leaving the Shikari service installed and running."
} else {
    Write-Host "==> Uninstalling (purge)"
    & (Join-Path $unpack 'uninstall.ps1') -Purge
    Remove-Item -Recurse -Force $unpack -ErrorAction SilentlyContinue
}

if ($ok) { Write-Host 'PASS' } else { Write-Error 'FAIL'; exit 1 }
