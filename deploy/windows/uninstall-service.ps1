<#
.SYNOPSIS
Remove the Shikari Windows team server (#29). Keeps data by default.

.DESCRIPTION
Elevated PowerShell:
    .\deploy\windows\uninstall-service.ps1 [-Purge]

-Purge also removes the data dir (%ProgramData%\Shikari). The code dir is always left in place.
#>
param(
    [string]$DataDir = (Join-Path $env:ProgramData 'Shikari'),
    [string]$TaskName = 'Shikari',
    [switch]$Purge
)
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this in an elevated PowerShell (Run as administrator).'
}

Write-Host "==> removing Scheduled Task '$TaskName'"
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

if ($Purge) {
    Write-Host "==> purging $DataDir"
    Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
} else {
    Write-Host "    kept data ($DataDir). Re-run with -Purge to remove it."
}
