<#
.SYNOPSIS
Remove the Shikari team-server Windows service and files (#29).

.DESCRIPTION
Stops and unregisters the Shikari SCM service and deletes the install dir. The data dir
(%ProgramData%\Shikari - database, bespoke config, telemetry) is kept unless you pass -Purge.

Run in an elevated PowerShell:
    .\uninstall.ps1 [-InstallDir 'C:\Program Files\Shikari'] [-DataDir "$env:ProgramData\Shikari"] [-Purge]
#>
param(
    [string]$InstallDir = 'C:\Program Files\Shikari',
    [string]$DataDir = (Join-Path $env:ProgramData 'Shikari'),
    [switch]$Purge
)
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this in an elevated PowerShell (Run as administrator).'
}

$python = Join-Path $InstallDir 'python\python.exe'
if (Get-Service -Name 'Shikari' -ErrorAction SilentlyContinue) {
    Write-Host "Stopping and removing the Shikari service"
    Stop-Service 'Shikari' -Force -ErrorAction SilentlyContinue
    if (Test-Path $python) { & $python -m shikari.win_service remove | Out-Null }
    else { & sc.exe delete Shikari | Out-Null }
}

if (Test-Path $InstallDir) {
    Write-Host "Removing $InstallDir"
    Remove-Item -Recurse -Force $InstallDir
}

if ($Purge) {
    if (Test-Path $DataDir) { Write-Host "Purging data at $DataDir"; Remove-Item -Recurse -Force $DataDir }
} else {
    Write-Host "Kept data at $DataDir (pass -Purge to remove it)."
}
