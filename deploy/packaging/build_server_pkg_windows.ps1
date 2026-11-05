<#
.SYNOPSIS
Build a self-contained Shikari team-server bundle for Windows (#29).

.DESCRIPTION
The Windows counterpart of deploy/packaging/build_server_pkg.py: produces a zip carrying its own
Python — a SHA-256-verified standalone CPython (python-build-standalone) with the server's dependencies
and pywin32 — plus the app and the install/uninstall scripts. No system Python, no venv, no checkout on
the target; install.ps1 registers a first-class SCM service (shikari.win_service).

Run on Windows (x64 or ARM64) with internet access; nothing else is required:
    pwsh -File deploy\packaging\build_server_pkg_windows.ps1 [-Arch x86_64|aarch64] [-Out dist]

The standalone CPython is verified against the release's own published .sha256 before use. pywin32 is
installed from PyPI (pip verifies the wheel). ARM64 is best-effort: pywin32 ARM64 wheels are newer and
may be unavailable for this interpreter — the build warns and continues, but verify the service on-target.
#>
param(
    [ValidateSet('x86_64', 'aarch64')]
    [string]$Arch = $(if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { 'x86_64' }),
    [string]$Out = 'dist',
    [string]$Pywin32 = 'pywin32==306'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$release = 'https://github.com/astral-sh/python-build-standalone/releases/download/20261009'
$asset = "cpython-3.11.17+20261009-$Arch-pc-windows-msvc-install_only_stripped.tar.gz"
$version = (& python -c "import tomllib;print(tomllib.load(open(r'$repo\pyproject.toml','rb'))['project']['version'])" 2>$null)
if (-not $version) { $version = '2.0.0' }   # only used to name the zip

$work = Join-Path ([IO.Path]::GetTempPath()) ("shikari-win-" + [Guid]::NewGuid())
$stage = Join-Path $work 'stage'
New-Item -ItemType Directory -Force $stage | Out-Null
New-Item -ItemType Directory -Force $Out | Out-Null

try {
    # --- fetch + verify standalone CPython -------------------------------------------------------
    Write-Host "Fetching $asset"
    $tgz = Join-Path $work $asset
    Invoke-WebRequest -UseBasicParsing "$release/$asset" -OutFile $tgz
    $expected = (Invoke-WebRequest -UseBasicParsing "$release/$asset.sha256").Content.Trim().Split()[0]
    $actual = (Get-FileHash -Algorithm SHA256 $tgz).Hash.ToLower()
    if ($actual -ne $expected.ToLower()) { throw "$asset doesn't match its published SHA-256: refusing to bundle it" }

    # install_only tarball unpacks to a top-level python/ dir.
    & tar -xzf $tgz -C $stage
    $python = Join-Path $stage 'python\python.exe'
    if (-not (Test-Path $python)) { throw "unexpected archive layout: no python\python.exe" }

    # --- dependencies + pywin32 ------------------------------------------------------------------
    $deps = (& $python -c "import tomllib;print('\n'.join(tomllib.load(open(r'$repo\pyproject.toml','rb'))['project']['dependencies']))") -split "`n" | Where-Object { $_ }
    Write-Host "Installing $($deps.Count) dependencies + pywin32 into the bundled Python"
    & $python -m pip install -q --no-cache-dir --no-warn-script-location @deps $Pywin32
    if ($LASTEXITCODE) { throw "pip install failed ($LASTEXITCODE) — on ARM64 a pywin32 wheel may not exist for this interpreter" }

    # pywin32 needs its post-install to place pythonservice.exe and the pywintypes DLL where the
    # service host finds them.
    $post = Join-Path $stage 'python\Scripts\pywin32_postinstall.py'
    if (Test-Path $post) { & $python $post -install -quiet | Out-Null }
    else { Write-Warning "pywin32_postinstall.py not found — the service host may fail to start" }

    # --- app sources (shikari / templates / static; no seed) -------------------------------------
    $app = Join-Path $stage 'app'
    New-Item -ItemType Directory -Force $app | Out-Null
    foreach ($name in 'shikari', 'templates', 'static') {
        Copy-Item -Recurse -Force (Join-Path $repo $name) (Join-Path $app $name)
    }
    & $python -m compileall -q -j 0 $app | Out-Null

    # --- bundle the installer + config -----------------------------------------------------------
    Copy-Item (Join-Path $PSScriptRoot 'windows\install.ps1') $stage
    Copy-Item (Join-Path $PSScriptRoot 'windows\uninstall.ps1') $stage
    Copy-Item (Join-Path $repo 'deploy\linux\shikari.env.example') (Join-Path $stage 'shikari.env.example')

    # Ship the ATT&CK STIX bundle so the service starts without network on first boot (install.ps1 seeds
    # it into SHIKARI_HOME). Non-fatal: a build host with no egress still produces a usable bundle.
    try {
        Write-Host "Fetching the ATT&CK STIX bundle (seeds the offline cache)"
        Invoke-WebRequest -UseBasicParsing `
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" `
            -OutFile (Join-Path $stage 'enterprise-attack.json')
    } catch {
        Write-Warning "couldn't fetch ATT&CK ($_); the bundle won't seed a cache and the server will need network on first start"
    }

    # --- zip --------------------------------------------------------------------------------------
    $suffix = if ($Arch -eq 'aarch64') { 'arm64' } else { 'x64' }
    $zip = Join-Path (Resolve-Path $Out) "shikari-server_${version}_windows-$suffix.zip"
    if (Test-Path $zip) { Remove-Item $zip }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
    Write-Host "Built $zip"
    Write-Host "On the server: unzip, then (elevated) .\install.ps1"
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
