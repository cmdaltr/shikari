<#
.SYNOPSIS
Build a self-contained Shikari team-server bundle for Windows (#29).

.DESCRIPTION
The Windows counterpart of deploy/packaging/build_server_pkg.py: produces a zip carrying its own
Python - a SHA-256-verified standalone CPython (python-build-standalone) with the server's dependencies
and pywin32 - plus the app and the install/uninstall scripts. No system Python, no venv, no checkout on
the target; install.ps1 registers a first-class SCM service (shikari.win_service).

Run on Windows (x64 or ARM64) with internet access; nothing else is required:
    pwsh -File deploy\packaging\build_server_pkg_windows.ps1 [-Arch x86_64|aarch64] [-Out dist]

The standalone CPython is verified against the release's own published .sha256 before use. pywin32 is
installed from PyPI (pip verifies the wheel). ARM64 is best-effort: pywin32 ARM64 wheels are newer and
may be unavailable for this interpreter - the build warns and continues, but verify the service on-target.
#>
param(
    [ValidateSet('x86_64', 'aarch64')]
    [string]$Arch = $(if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { 'x86_64' }),
    [string]$Out = 'dist',
    # mcp (a server dependency) requires pywin32>=310 on Windows for CPython < 3.14; keep this at or above
    # that floor or the dependency resolver fails. A range lets pip pick a version compatible with the rest.
    [string]$Pywin32 = 'pywin32>=310'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# GitHub release/raw fetches drop connections intermittently; retry with a short backoff rather than
# failing the whole build on one blip. Returns the response; pass -OutFile to stream to disk.
function Invoke-Fetch {
    param([string]$Url, [string]$OutFile)
    for ($i = 1; $i -le 4; $i++) {
        try {
            if ($OutFile) { return Invoke-WebRequest -UseBasicParsing $Url -OutFile $OutFile }
            return Invoke-WebRequest -UseBasicParsing $Url
        } catch {
            if ($i -eq 4) { throw }
            Write-Host "  fetch failed (attempt $i/4): $($_.Exception.Message); retrying..."
            Start-Sleep -Seconds ($i * 3)
        }
    }
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$release = 'https://github.com/astral-sh/python-build-standalone/releases/download/20261009'
$asset = "cpython-3.11.17+20261009-$Arch-pc-windows-msvc-install_only_stripped.tar.gz"
# Pinned SHA-256 per arch (python-build-standalone publishes no per-asset .sha256 sidecar; these come from
# the release's SHA256SUMS). Pinning in-code - as the Linux builder does - means a tampered release can't
# slip through. Bump both when the CPython release above changes.
$assetSha = @{
    'x86_64'  = 'c3045115465bb4aa7d1ca6bfe6ce311ba157d726d768bbb3520fad2580831c3f'
    'aarch64' = 'fb5ef23eff0f4a6fd0d5cde15e25c4a9bb7cdf64a9fb51147a9b016218446652'
}[$Arch]
if (-not $assetSha) { throw "no pinned SHA-256 for architecture $Arch" }
# Read the version from pyproject.toml without any host Python (a fresh Windows box has none, and the
# Microsoft Store 'python' alias would raise a NativeCommandError here). Only used to name the zip.
$version = '2.0.0'
$m = Select-String -Path (Join-Path $repo 'pyproject.toml') -Pattern '^\s*version\s*=\s*"(.+?)"' | Select-Object -First 1
if ($m) { $version = $m.Matches[0].Groups[1].Value }

$work = Join-Path ([IO.Path]::GetTempPath()) ("shikari-win-" + [Guid]::NewGuid())
$stage = Join-Path $work 'stage'
New-Item -ItemType Directory -Force $stage | Out-Null
New-Item -ItemType Directory -Force $Out | Out-Null

try {
    # --- fetch + verify standalone CPython -------------------------------------------------------
    Write-Host "Fetching $asset"
    $tgz = Join-Path $work $asset
    Invoke-Fetch "$release/$asset" -OutFile $tgz
    $actual = (Get-FileHash -Algorithm SHA256 $tgz).Hash.ToLower()
    if ($actual -ne $assetSha) { throw "$asset doesn't match its pinned SHA-256 ($actual): refusing to bundle it" }

    # install_only tarball unpacks to a top-level python/ dir.
    & tar -xzf $tgz -C $stage
    $python = Join-Path $stage 'python\python.exe'
    if (-not (Test-Path $python)) { throw "unexpected archive layout: no python\python.exe" }

    # --- dependencies + pywin32 ------------------------------------------------------------------
    $deps = (& $python -c "import tomllib;print('\n'.join(tomllib.load(open(r'$repo\pyproject.toml','rb'))['project']['dependencies']))") -split "`n" | Where-Object { $_ }
    Write-Host "Installing $($deps.Count) dependencies + pywin32 into the bundled Python"
    & $python -m pip install -q --no-cache-dir --no-warn-script-location @deps $Pywin32
    if ($LASTEXITCODE) { throw "pip install failed ($LASTEXITCODE) - on ARM64 a pywin32 wheel may not exist for this interpreter" }

    # pywin32 needs its post-install to place pythonservice.exe and the pywintypes DLL where the
    # service host finds them.
    $post = Join-Path $stage 'python\Scripts\pywin32_postinstall.py'
    if (Test-Path $post) { & $python $post -install -quiet | Out-Null }
    else { Write-Warning "pywin32_postinstall.py not found - the service host may fail to start" }

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
    Copy-Item (Join-Path $repo 'deploy\windows\shikari.env.example') (Join-Path $stage 'shikari.env.example')

    # Ship the ATT&CK STIX bundle so the service starts without network on first boot (install.ps1 seeds
    # it into SHIKARI_HOME). Non-fatal: a build host with no egress still produces a usable bundle.
    try {
        Write-Host "Fetching the ATT&CK STIX bundle (seeds the offline cache)"
        Invoke-Fetch `
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
