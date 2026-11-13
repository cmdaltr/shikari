# The Hyper-V lifecycle test, run elevated inside the Windows 11 VM from the Shikari checkout:
#   -Guest linux    an Ubuntu 24.04 cloud-image VM from the ubuntu-hyperv template, reached over SSH
#   -Guest windows  a Windows Server 2022 VM from prepare-windows-guest.ps1's base disk, reached
#                   over PowerShell Direct as Administrator (you're asked for the password)
#
#   powershell -ExecutionPolicy Bypass -File scripts\lab\host-engine-tests\run-hyperv.ps1 -Guest linux
#   powershell -ExecutionPolicy Bypass -File scripts\lab\host-engine-tests\run-hyperv.ps1 -Guest windows `
#       -Image C:\lab\images\ws2022-base.vhd
#
# Add -Keep to leave the machine in place at the end. ASCII only (Windows PowerShell 5.1).
#Requires -RunAsAdministrator
param(
    [ValidateSet('linux', 'windows')][string]$Guest = 'linux',
    [string]$Image = '',
    [string]$Name = '',
    [switch]$Keep
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
Set-Location $root
$py = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path $py)) { throw "No .venv here: py -3.12 -m venv .venv; .venv\Scripts\pip install -e ." }

# Preflight: what Shikari's detection depends on, said plainly before the test says FAIL
Get-VMHost | Out-Null
if (-not (Get-VMSwitch -Name 'Default Switch' -ErrorAction SilentlyContinue)) { throw "No 'Default Switch' (Windows 11 makes it when Hyper-V is enabled)" }
if ($Guest -eq 'linux' -and -not (Get-Command qemu-img -ErrorAction SilentlyContinue)) {
    throw "qemu-img isn't on PATH (prepare-hyperv-host.ps1 installs it; open a new shell after)"
}

$argv = @('scripts\lab\host-engine-tests\lifecycle.py', '--engine', 'hyperv')
if ($Guest -eq 'linux') {
    $argv += @('--template', 'ubuntu-hyperv')
} else {
    if (-not $Image) { throw "-Image is the base disk prepare-windows-guest.ps1 printed" }
    $pw = Read-Host -AsSecureString "The guests' Administrator password"
    # To the test through the environment of its own process only, never on a command line
    $env:SHIKARI_KIT_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
    $argv += @('--image', $Image, '--os', 'windows', '--user', 'Administrator', '--password-env', 'SHIKARI_KIT_PASSWORD')
}
if ($Name) { $argv += @('--name', $Name) }
if ($Keep) { $argv += '--keep' }
try {
    & $py @argv
    $code = $LASTEXITCODE
} finally {
    Remove-Item Env:\SHIKARI_KIT_PASSWORD -ErrorAction SilentlyContinue
}
exit $code
