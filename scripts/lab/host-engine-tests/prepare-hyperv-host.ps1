# Prepare a Windows 11 VM to be a Hyper-V host for Shikari: check nested virtualisation reached it,
# enable Hyper-V, add this user to Hyper-V Administrators, install Python 3.12 and qemu-img (to
# convert Ubuntu's cloud image to VHDX), and turn on the OpenSSH server so the VM is reachable
# with ssh -J macmini. Run it elevated, inside the Windows VM, then reboot.
#
#   powershell -ExecutionPolicy Bypass -File scripts\lab\host-engine-tests\prepare-hyperv-host.ps1 `
#       -PublicKey "ssh-ed25519 AAAA... rowanholt-lab"
#
# Safe to run again. It creates no VM. ASCII only: Windows PowerShell 5.1 misreads anything else.
#Requires -RunAsAdministrator
param(
    [string]$PublicKey = ""
)
$ErrorActionPreference = 'Stop'
function Say($m) { Write-Host ""; Write-Host "== $m" -ForegroundColor Cyan }

Say "Virtualisation as Windows sees it (before Hyper-V is on)"
$cs = Get-CimInstance Win32_Processor | Select-Object -First 1
Write-Host ("VM Monitor Mode Extensions: {0}" -f $cs.VMMonitorModeExtensions)
Write-Host ("Virtualisation enabled in firmware: {0}" -f $cs.VirtualizationFirmwareEnabled)
Write-Host ("Second Level Address Translation: {0}" -f $cs.SecondLevelAddressTranslationExtensions)
$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
if ($feature.State -ne 'Enabled' -and -not ($cs.VMMonitorModeExtensions -and $cs.SecondLevelAddressTranslationExtensions)) {
    Write-Host "Nested virtualisation hasn't reached this VM: power it off and run fusion-nested.sh on the Mini." -ForegroundColor Red
    exit 1
}

Say "Hyper-V"
if ($feature.State -eq 'Enabled') {
    Write-Host "already enabled"
} else {
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart | Out-Null
    Write-Host "enabled (takes effect after the reboot)"
}

Say "Hyper-V Administrators"
try {
    Add-LocalGroupMember -SID 'S-1-5-32-578' -Member $env:USERNAME -ErrorAction Stop
    Write-Host "added $env:USERNAME (sign out and in for it to apply)"
} catch {
    Write-Host "$env:USERNAME is already a member"
}

Say "Python 3.12, Git and QEMU (qemu-img)"
# winget, where it works; it often doesn't in a remote session (WinRM, as homelab lab build runs this, or
# SSH), so each one falls back to its own installer, downloaded and run silently
function Install-Direct($name, $url, $installArgs) {
    $exe = Join-Path $env:TEMP ($url -split '/')[-1]
    Write-Host "  $name from $url"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $exe
    $p = Start-Process -FilePath $exe -ArgumentList $installArgs -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "$name installer exited $($p.ExitCode)" }
}
$haveWinget = [bool](Get-Command winget -ErrorAction SilentlyContinue)
$tools = @(
    @{ Id = 'Python.Python.3.12'; Test = 'C:\Program Files\Python312\python.exe'; Name = 'Python 3.12'
       Url = 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe'
       Args = '/quiet InstallAllUsers=1 PrependPath=1 Include_test=0' },
    @{ Id = 'Git.Git'; Test = 'C:\Program Files\Git\cmd\git.exe'; Name = 'Git'
       Url = 'https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/Git-2.47.1-64-bit.exe'
       Args = '/VERYSILENT /NORESTART /SP-' },
    @{ Id = 'SoftwareFreedomConservancy.QEMU'; Test = 'C:\Program Files\qemu\qemu-img.exe'; Name = 'QEMU'
       Url = ''; Args = '/S' }
)
foreach ($t in $tools) {
    if (Test-Path $t.Test) { Write-Host "  $($t.Name): already installed"; continue }
    if ($haveWinget) {
        winget install --id $t.Id -e --silent --accept-source-agreements --accept-package-agreements
    }
    if (Test-Path $t.Test) { continue }
    $url = $t.Url
    if (-not $url) {
        # QEMU's Windows builds are dated: take the newest installer listed
        $index = (Invoke-WebRequest -UseBasicParsing -Uri 'https://qemu.weilnetz.de/w64/').Content
        $latest = [regex]::Matches($index, 'qemu-w64-setup-\d+\.exe') | ForEach-Object Value | Sort-Object -Unique | Select-Object -Last 1
        $url = "https://qemu.weilnetz.de/w64/$latest"
    }
    Install-Direct $t.Name $url $t.Args
}
# The QEMU installer doesn't put itself on PATH; Shikari calls qemu-img by name
$qemu = 'C:\Program Files\qemu'
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ((Test-Path $qemu) -and ($path -notlike "*$qemu*")) {
    [Environment]::SetEnvironmentVariable('Path', "$path;$qemu", 'Machine')
    Write-Host "added $qemu to the machine PATH"
}

Say "OpenSSH server"
if ((Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0').State -ne 'Installed') {
    Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
}
Set-Service sshd -StartupType Automatic
Start-Service sshd
if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True `
        -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}
if ($PublicKey) {
    # An administrator's key goes here, not in their profile, and only SYSTEM and Administrators may read it
    $keys = 'C:\ProgramData\ssh\administrators_authorized_keys'
    if (-not ((Test-Path $keys) -and (Select-String -Path $keys -SimpleMatch $PublicKey -Quiet))) {
        Add-Content -Path $keys -Value $PublicKey -Encoding ascii
    }
    icacls $keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
    Write-Host "key installed in $keys"
}

Say "Done"
Write-Host "Reboot now (Restart-Computer). After it, in an elevated PowerShell:"
Write-Host "  Get-VMHost | Select-Object Name, LogicalProcessorCount"
Write-Host "  Get-VMSwitch -Name 'Default Switch'"
Write-Host "  qemu-img --version"
