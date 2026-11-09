<#
Remove the Shikari desktop app from Windows (desktop/README.md).

    powershell -ExecutionPolicy Bypass -File uninstall.ps1             remove the app, then ask before deleting its data folder
    powershell -ExecutionPolicy Bypass -File uninstall.ps1 -KeepData   remove the app only: the data folder stays for a reinstall
    powershell -ExecutionPolicy Bypass -File uninstall.ps1 -Yes        don't ask: delete the data folder too

The data folder is SHIKARI_HOME (%LOCALAPPDATA%\Shikari\home): the database, generated detections,
bespoke\, logs, and the window's WebView2 and Edge profiles. Without a console to ask on, it's kept
unless -Yes says otherwise. The program itself is removed by Windows Installer, as Settings > Apps
would. Works in Windows PowerShell 5.1 and pwsh.
#>
param(
    [switch]$KeepData,
    [switch]$Yes
)
$ErrorActionPreference = "Stop"

$script:step = 0
$script:steps = 3
function Step($text) {
    $script:step++
    Write-Host ""
    Write-Host ("[{0}/{1}] {2}" -f $script:step, $script:steps, $text) -ForegroundColor Cyan
}
function Done($text) { Write-Host "      OK  $text" -ForegroundColor Green }
function Note($text) { Write-Host "      $text" -ForegroundColor DarkGray }

$base = Join-Path $env:LOCALAPPDATA "Shikari"
$home_ = if ($env:SHIKARI_HOME) { $env:SHIKARI_HOME } else { Join-Path $base "home" }

Write-Host ""
Write-Host "  Shikari: desktop app uninstaller"

Step "Quitting Shikari"
$running = Get-Process Shikari -ErrorAction SilentlyContinue
if ($running) { $running | Stop-Process -Force; Start-Sleep -Seconds 2; Done "Quit" } else { Done "Not running" }

Step "Removing the app"
# A per-user install registers under HKCU; a machine-wide one under HKLM (either registry view)
$keys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$entries = @(Get-ItemProperty $keys -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq "Shikari" -and $_.PSChildName -match '^\{[0-9A-Fa-f-]+\}$' })
if (-not $entries) {
    Done "Shikari isn't installed"
} else {
    foreach ($e in $entries) {
        $log = Join-Path $env:TEMP "shikari-uninstall.log"
        Note "Windows shows its own progress window while it removes Shikari $($e.DisplayVersion)"
        $p = Start-Process msiexec.exe -ArgumentList "/x", $e.PSChildName, "/passive", "/l*v", "`"$log`"" -Wait -PassThru
        # 1605: already gone; 3010: removed, a restart is pending for something else
        if ($p.ExitCode -notin 0, 1605, 3010) {
            Get-Content $log -Tail 40
            throw "msiexec failed with $($p.ExitCode)"
        }
        Done "Removed Shikari $($e.DisplayVersion)"
    }
}

Step "The data folder"
if (-not (Test-Path $home_)) {
    Done "None at $home_"
} else {
    $bytes = (Get-ChildItem $home_ -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    $size = "{0:N0} MB" -f ($bytes / 1MB)
    $delete = [bool]$Yes
    if (-not $Yes -and -not $KeepData -and [Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
        $answer = Read-Host "      Delete $home_ ($size): the database, detections and bespoke\? It can't be undone. [y/N]"
        $delete = $answer -match '^[yY]'
    }
    if ($delete) {
        Remove-Item -Recurse -Force $home_
        # The parent goes too once it's empty
        if (-not $env:SHIKARI_HOME -and (Test-Path $base) -and -not (Get-ChildItem -Force $base)) { Remove-Item -Force $base }
        Done "Deleted $home_ ($size)"
    } else {
        Done "Kept $home_ ($size): delete it to start again, or reinstall to carry on"
    }
}

Write-Host ""
Write-Host "  Shikari is uninstalled." -ForegroundColor Green
