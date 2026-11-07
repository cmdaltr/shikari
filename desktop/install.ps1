<#
Install or upgrade the Shikari desktop app on Windows from a GitHub release (desktop/README.md).

    powershell -ExecutionPolicy Bypass -File install.ps1                    the latest release
    powershell -ExecutionPolicy Bypass -File install.ps1 -Version v2.1.0    a given release
    powershell -ExecutionPolicy Bypass -File install.ps1 -File Shikari.msi   an installer already downloaded
    powershell -ExecutionPolicy Bypass -File install.ps1 -NoDotnet         on ARM64, skip the .NET download
    powershell -ExecutionPolicy Bypass -File install.ps1 -Launch           open Shikari when it's installed

The repository is private: set GH_TOKEN (or GITHUB_TOKEN) to a token that can read it, or be logged
in to the gh CLI. The installer is checked against the release's SHA256SUMS before use. It installs
for the current user, so it needs no administrator rights. Works in Windows PowerShell 5.1 and pwsh.

On Windows on ARM64 it also downloads Microsoft's .NET Desktop Runtime (8 or later, about 55 MB),
per user, with Microsoft's own dotnet-install.ps1 after checking its signature, unless one is
already installed. It isn't in the installer: the ARM64 app's native window needs it, and without
it Shikari opens in an Edge app window instead (shikari/desktop_edge.py), so the download is optional.
#>
param(
    [string]$Version = "latest",
    [string]$File,
    [switch]$NoDotnet,
    [switch]$Launch
)
$ErrorActionPreference = "Stop"
# Windows PowerShell's progress bar slows downloads by an order of magnitude
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo = if ($env:SHIKARI_REPO) { $env:SHIKARI_REPO } else { "cmdaltr/shikari" }
# The processor, not this process: an x64 PowerShell under emulation on ARM still reports ARM here
$arm = (Get-CimInstance Win32_Processor | Select-Object -First 1).Architecture -eq 12
# On ARM prefer the native arm64 build, but fall back to the x64 .msi (it runs under emulation) when a
# release ships no arm64 asset, so a release without an arm64 build still installs on ARM machines.
$suffixes = if ($arm) { @("-windows-arm64.msi", "-windows-x64.msi") } else { @("-windows-x64.msi") }
# Numbered steps, so it's clear how far through the install is
$script:step = 0
$script:steps = 0
$started = Get-Date
function Step($text) {
    $script:step++
    Write-Host ""
    Write-Host ("[{0}/{1}] {2}" -f $script:step, $script:steps, $text) -ForegroundColor Cyan
}
function Done($text) { Write-Host "      OK  $text" -ForegroundColor Green }
function Note($text) { Write-Host "      $text" -ForegroundColor DarkGray }

# Invoke-WebRequest's own progress bar is what makes it slow in Windows PowerShell: read the stream
# here instead, and print the percentage on one line
function Get-Download($url, $headers, $out) {
    $req = [Net.HttpWebRequest]::Create($url)
    foreach ($k in $headers.Keys) {
        if ($k -eq "Accept") { $req.Accept = $headers[$k] } else { $req.Headers[$k] = $headers[$k] }
    }
    $req.UserAgent = "shikari-install"
    $resp = $req.GetResponse()
    $total = $resp.ContentLength
    $in = $resp.GetResponseStream()
    $fs = [IO.File]::Create($out)
    try {
        $buf = New-Object byte[] (1MB)
        $done = 0
        $shown = -1
        while (($n = $in.Read($buf, 0, $buf.Length)) -gt 0) {
            $fs.Write($buf, 0, $n)
            $done += $n
            if ($total -gt 0) {
                $pct = [int](100 * $done / $total)
                if ($pct -ne $shown) {
                    Write-Host -NoNewline ("`r      {0,3}%  {1:N1} of {2:N1} MB" -f $pct, ($done / 1MB), ($total / 1MB))
                    $shown = $pct
                }
            }
        }
        Write-Host ""
    }
    finally {
        $fs.Close(); $in.Close(); $resp.Close()
    }
}

function Test-DesktopRuntime {
    foreach ($root in @($env:DOTNET_ROOT, (Join-Path $env:ProgramFiles "dotnet"), (Join-Path $env:LOCALAPPDATA "Microsoft\dotnet"))) {
        if (-not $root) { continue }
        $dir = Join-Path $root "shared\Microsoft.WindowsDesktop.App"
        if (Get-ChildItem $dir -Directory -ErrorAction SilentlyContinue | Where-Object { [int]($_.Name -split '\.')[0] -ge 8 }) { return $true }
    }
    return $false
}

function Install-DesktopRuntime($dir) {
    if (Test-DesktopRuntime) { Done ".NET Desktop Runtime already installed"; return }
    # A failed download costs the native window, not Shikari: it opens in Edge instead
    try {
        Note "Downloading the .NET Desktop Runtime (ARM64, about 55 MB) for Shikari's window"
        $script = Join-Path $dir "dotnet-install.ps1"
        Invoke-WebRequest -UseBasicParsing -OutFile $script "https://dot.net/v1/dotnet-install.ps1"
        $sig = Get-AuthenticodeSignature $script
        if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") {
            throw "dotnet-install.ps1 isn't signed by Microsoft ($($sig.Status))"
        }
        & $script -Runtime windowsdesktop -Channel LTS -Architecture arm64 -InstallDir (Join-Path $env:LOCALAPPDATA "Microsoft\dotnet") -NoPath
        if (-not (Test-DesktopRuntime)) { throw "it didn't install" }
        Done ".NET Desktop Runtime installed"
    }
    catch {
        Write-Warning "No .NET Desktop Runtime ($_): Shikari will open in an Edge window instead"
    }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("shikari-" + [Guid]::NewGuid())
New-Item -ItemType Directory $tmp | Out-Null

Write-Host ""
Write-Host "  Shikari: desktop app installer" -ForegroundColor White
Write-Host "  shi-ka-ri \shi-'kar-e\  a professional big-game hunter or guide" -ForegroundColor DarkGray
# Find (and download and check) the installer when there's no -File, install it, the ARM64 runtime
# when it'll be needed, then find what was installed
$script:steps = $(if ($File) { 2 } else { 5 }) + $(if ($arm -and -not $NoDotnet) { 1 } else { 0 })

try {
    if (-not $File) {
        Step "Finding the $Version release of $repo"
        $token = if ($env:GH_TOKEN) { $env:GH_TOKEN } elseif ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { $null }
        if (-not $token -and (Get-Command gh -ErrorAction SilentlyContinue)) { $token = (gh auth token 2>$null) }
        if (-not $token) { throw "Set GH_TOKEN to a token that can read $repo, or log in with gh auth login" }
        $auth = @{ Authorization = "Bearer $token" }

        $path = if ($Version -eq "latest") { "releases/latest" } else { "releases/tags/$Version" }
        $release = Invoke-RestMethod -Headers ($auth + @{ Accept = "application/vnd.github+json" }) "https://api.github.com/repos/$repo/$path"
        $asset = $null
        foreach ($s in $suffixes) {
            $asset = $release.assets | Where-Object { $_.name.EndsWith($s) } | Select-Object -First 1
            if ($asset) { break }
        }
        $sums = $release.assets | Where-Object { $_.name -eq "SHA256SUMS" } | Select-Object -First 1
        if (-not $asset) { throw "The $Version release has no Windows installer ($($suffixes -join ' or '))" }
        if (-not $sums) { throw "The $Version release has no SHA256SUMS" }
        Done "$($release.tag_name): $($asset.name)"

        Step "Downloading $($asset.name)"
        $File = Join-Path $tmp $asset.name
        $raw = $auth + @{ Accept = "application/octet-stream" }
        Get-Download $asset.url $raw $File
        Invoke-WebRequest -UseBasicParsing -Headers $raw -OutFile (Join-Path $tmp "SHA256SUMS") $sums.url
        Done "Downloaded"

        Step "Checking it against the release's SHA256SUMS"
        $expected = Get-Content (Join-Path $tmp "SHA256SUMS") | ForEach-Object {
            $hash, $name = $_ -split '\s+\*?', 2
            if ($name -eq $asset.name) { $hash }
        } | Select-Object -First 1
        $actual = (Get-FileHash -Algorithm SHA256 $File).Hash
        if (-not $expected -or $actual -ne $expected) { throw "$($asset.name) doesn't match SHA256SUMS: not installing it" }
        Done "SHA-256 matches"
    }
    $File = (Resolve-Path $File).Path

    Step "Installing $(Split-Path $File -Leaf)"
    Note "Windows shows its own progress window while it installs"
    if (Get-Process Shikari -ErrorAction SilentlyContinue) { Note "Shikari is running: quit it to use the new version" }
    $log = Join-Path $tmp "install.log"
    # /passive: Windows' progress window, no questions
    $p = Start-Process msiexec.exe -ArgumentList "/i", "`"$File`"", "/passive", "/l*v", "`"$log`"" -Wait -PassThru
    # 3010: installed, a restart is pending for something else
    if ($p.ExitCode -notin 0, 3010) {
        Get-Content $log -Tail 40
        throw "msiexec failed with $($p.ExitCode)"
    }
    Done "Installed$(if ($p.ExitCode -eq 3010) { ' (Windows wants a restart for something else)' })"
    # Only the native arm64 build needs the ARM64 .NET Desktop Runtime; the x64 build (the ARM fallback,
    # or on x64) does not. Key off the file actually installed, which also covers -File.
    if ($arm -and -not $NoDotnet) {
        Step "The .NET Desktop Runtime for the ARM64 window"
        if ($File -like "*-windows-arm64.msi") { Install-DesktopRuntime $tmp } else { Done "Not needed: this is the x64 build" }
    }
    Step "Finding the installed app"
    # It's a per-user install (LocalAppData\Programs\<author>\Shikari\Shikari.exe, three deep); don't
    # recurse the whole of Program Files, which takes minutes on an ARM64 machine. Fall back to a
    # machine-wide install there, but bounded.
    $exe = Get-ChildItem "$env:LOCALAPPDATA\Programs" -Recurse -Depth 4 -Filter Shikari.exe -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $exe) {
        $exe = Get-ChildItem "$env:ProgramFiles" -Recurse -Depth 4 -Filter Shikari.exe -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }
    if ($exe) { Done $exe.FullName }
    $took = (Get-Date) - $started
    Write-Host ""
    Write-Host ("  Shikari is installed ({0}m {1}s). Open it from the Start menu." -f [math]::Floor($took.TotalMinutes), $took.Seconds) -ForegroundColor Green
    Write-Host "  The first start takes a few minutes while it unpacks MITRE ATT&CK; after that, seconds." -ForegroundColor DarkGray
    if ($Launch -and $exe) { Start-Process $exe.FullName }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
