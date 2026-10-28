<#
Install or upgrade the Archer desktop app on Windows from a GitHub release (desktop/README.md).

    powershell -ExecutionPolicy Bypass -File install.ps1                    the latest release
    powershell -ExecutionPolicy Bypass -File install.ps1 -Version v2.1.0    a given release
    powershell -ExecutionPolicy Bypass -File install.ps1 -File Archer.msi   an installer already downloaded
    powershell -ExecutionPolicy Bypass -File install.ps1 -NoDotnet         on ARM64, skip the .NET download

The repository is private: set GH_TOKEN (or GITHUB_TOKEN) to a token that can read it, or be logged
in to the gh CLI. The installer is checked against the release's SHA256SUMS before use. It installs
for the current user, so it needs no administrator rights. Works in Windows PowerShell 5.1 and pwsh.

On Windows on ARM64 it also downloads Microsoft's .NET Desktop Runtime (8 or later, about 55 MB),
per user, with Microsoft's own dotnet-install.ps1 after checking its signature, unless one is
already installed. It isn't in the installer: the ARM64 app's native window needs it, and without
it Archer opens in an Edge app window instead (archer/desktop_edge.py), so the download is optional.
#>
param(
    [string]$Version = "latest",
    [string]$File,
    [switch]$NoDotnet
)
$ErrorActionPreference = "Stop"
# Windows PowerShell's progress bar slows downloads by an order of magnitude
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo = if ($env:ARCHER_REPO) { $env:ARCHER_REPO } else { "cmdaltr/archer" }
# The processor, not this process: an x64 PowerShell under emulation on ARM still gets the ARM64 build
$arm = (Get-CimInstance Win32_Processor | Select-Object -First 1).Architecture -eq 12
$suffix = if ($arm) { "-windows-arm64.msi" } else { "-windows-x64.msi" }
function Test-DesktopRuntime {
    foreach ($root in @($env:DOTNET_ROOT, (Join-Path $env:ProgramFiles "dotnet"), (Join-Path $env:LOCALAPPDATA "Microsoft\dotnet"))) {
        if (-not $root) { continue }
        $dir = Join-Path $root "shared\Microsoft.WindowsDesktop.App"
        if (Get-ChildItem $dir -Directory -ErrorAction SilentlyContinue | Where-Object { [int]($_.Name -split '\.')[0] -ge 8 }) { return $true }
    }
    return $false
}

function Install-DesktopRuntime($dir) {
    if (Test-DesktopRuntime) { Write-Host ".NET Desktop Runtime: already installed"; return }
    # A failed download costs the native window, not Archer: it opens in Edge instead
    try {
        Write-Host "Downloading the .NET Desktop Runtime (ARM64) for Archer's window"
        $script = Join-Path $dir "dotnet-install.ps1"
        Invoke-WebRequest -UseBasicParsing -OutFile $script "https://dot.net/v1/dotnet-install.ps1"
        $sig = Get-AuthenticodeSignature $script
        if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") {
            throw "dotnet-install.ps1 isn't signed by Microsoft ($($sig.Status))"
        }
        & $script -Runtime windowsdesktop -Channel LTS -Architecture arm64 -InstallDir (Join-Path $env:LOCALAPPDATA "Microsoft\dotnet") -NoPath
        if (-not (Test-DesktopRuntime)) { throw "it didn't install" }
    }
    catch {
        Write-Warning "No .NET Desktop Runtime ($_): Archer will open in an Edge window instead"
    }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("archer-" + [Guid]::NewGuid())
New-Item -ItemType Directory $tmp | Out-Null

try {
    if (-not $File) {
        $token = if ($env:GH_TOKEN) { $env:GH_TOKEN } elseif ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { $null }
        if (-not $token -and (Get-Command gh -ErrorAction SilentlyContinue)) { $token = (gh auth token 2>$null) }
        if (-not $token) { throw "Set GH_TOKEN to a token that can read $repo, or log in with gh auth login" }
        $auth = @{ Authorization = "Bearer $token" }

        $path = if ($Version -eq "latest") { "releases/latest" } else { "releases/tags/$Version" }
        $release = Invoke-RestMethod -Headers ($auth + @{ Accept = "application/vnd.github+json" }) "https://api.github.com/repos/$repo/$path"
        $asset = $release.assets | Where-Object { $_.name.EndsWith($suffix) } | Select-Object -First 1
        $sums = $release.assets | Where-Object { $_.name -eq "SHA256SUMS" } | Select-Object -First 1
        if (-not $asset) { throw "The $Version release has no *$suffix" }
        if (-not $sums) { throw "The $Version release has no SHA256SUMS" }

        Write-Host "Downloading $($asset.name)"
        $File = Join-Path $tmp $asset.name
        $raw = $auth + @{ Accept = "application/octet-stream" }
        Invoke-WebRequest -UseBasicParsing -Headers $raw -OutFile $File $asset.url
        Invoke-WebRequest -UseBasicParsing -Headers $raw -OutFile (Join-Path $tmp "SHA256SUMS") $sums.url
        $expected = Get-Content (Join-Path $tmp "SHA256SUMS") | ForEach-Object {
            $hash, $name = $_ -split '\s+\*?', 2
            if ($name -eq $asset.name) { $hash }
        } | Select-Object -First 1
        $actual = (Get-FileHash -Algorithm SHA256 $File).Hash
        if (-not $expected -or $actual -ne $expected) { throw "$($asset.name) doesn't match SHA256SUMS: not installing it" }
    }
    $File = (Resolve-Path $File).Path

    if (Get-Process Archer -ErrorAction SilentlyContinue) { Write-Host "Archer is running: quit it to use the new version" }
    $log = Join-Path $tmp "install.log"
    $p = Start-Process msiexec.exe -ArgumentList "/i", "`"$File`"", "/qb", "/l*v", "`"$log`"" -Wait -PassThru
    # 3010: installed, a restart is pending for something else
    if ($p.ExitCode -notin 0, 3010) {
        Get-Content $log -Tail 40
        throw "msiexec failed with $($p.ExitCode)"
    }
    if ($arm -and -not $NoDotnet) { Install-DesktopRuntime $tmp }
    # It's a per-user install (LocalAppData\Programs\<author>\Archer\Archer.exe, three deep); don't
    # recurse the whole of Program Files, which takes minutes on an ARM64 machine. Fall back to a
    # machine-wide install there, but bounded.
    $exe = Get-ChildItem "$env:LOCALAPPDATA\Programs" -Recurse -Depth 4 -Filter Archer.exe -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $exe) {
        $exe = Get-ChildItem "$env:ProgramFiles" -Recurse -Depth 4 -Filter Archer.exe -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }
    Write-Host "Installed $(if ($exe) { $exe.FullName } else { 'Archer' }): open it from the Start menu"
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
