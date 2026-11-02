# Desktop App

Shikari ships two ways to run as an application with a Dock, Start menu or launcher icon.

![Shikari deployment comparison](../docs/architecture/deployment-comparison.svg)

| | Installer (this folder) | `shikari-cli app` |
|---|---|---|
| For | Anyone: download, install, open | A checkout you develop in |
| Runs | Its own bundled Python and dependencies | The repository's `.venv` |
| Data | A per-user folder (below) | The repository, as `shikari-cli start` does |
| Updates | A new installer | `git pull` |

## Installing

Download the file for your machine from the repository's Releases page:

| File | For |
|---|---|
| `Shikari-<version>-macos-arm64.dmg` | Apple Silicon Macs |
| `Shikari-<version>-macos-x86_64.dmg` | Intel Macs |
| `Shikari-<version>-windows-x64.msi` | Windows 10 and 11, including Windows on ARM under emulation |
| `shikari_<version>-1_amd64.deb` | Ubuntu 22.04 or later, Debian 12 or later (x86_64) |
| `shikari_<version>-1_arm64.deb` | The same on arm64, including Ubuntu VMs on Apple Silicon |
| `SHA256SUMS` | Checksums of the above, which the install scripts check |

The builds aren't signed with a paid developer certificate yet, so the first launch needs one extra step. On macOS, opening it shows "Apple could not verify Shikari"; open System Settings > Privacy & Security and choose Open Anyway. On Windows, SmartScreen shows "Windows protected your PC"; choose More info > Run anyway. On Linux, install the package with `sudo apt install ./shikari_<version>-1_amd64.deb`, which pulls in GTK and WebKit, and open Shikari from the applications menu. Every installer carries its own Python 3.11: the `.deb` bundles a standalone CPython under `/usr/lib/shikari/python` rather than using the distro's, and only GTK and WebKit, which have to match the desktop, come from the distro.

### Install scripts

`desktop/install.sh` (macOS and Linux) and `desktop/install.ps1` (Windows) download the right installer for the machine from a release, check it against `SHA256SUMS`, and install it; run again to upgrade. The repository is private, so they need `GH_TOKEN` set to a token that can read it, or a logged-in `gh`.

```bash
sh install.sh                    # or --version v2.1.0, or --file Shikari-<version>-macos-arm64.dmg
```

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1    # or -Version v2.1.0, or -File Shikari-<version>-windows-x64.msi
```

On macOS the app goes to /Applications, or ~/Applications for an account that isn't an administrator; on Linux it's installed with apt (sudo); on Windows it installs for the current user without administrator rights. `-ExecutionPolicy Bypass` applies to that one run: Windows refuses unsigned scripts by default. They're downloaded as files and run, never piped into a shell. A file the scripts download isn't marked as from the internet, so Gatekeeper and SmartScreen don't ask; the checksum is what vouches for it. A file given with `--file` / `-File` is installed as is.

On Windows on ARM64, `install.ps1` also downloads Microsoft's .NET Desktop Runtime (8 or later, about 55 MB) for the current user, using Microsoft's `dotnet-install.ps1` once its signature checks out, unless a Desktop Runtime is already installed; `-NoDotnet` skips it. The installer doesn't carry it. The ARM64 app's native window needs it: on .NET Framework, pythonnet's loader has no ARM64 build. Without it, or if that window fails, Shikari opens in an Edge app window instead, with no tabs or address bar and its own Edge profile. That window has no Change Server menu; the chooser shows whenever no server is saved or the saved one doesn't answer. `SHIKARI_WINDOW=edge` or `SHIKARI_WINDOW=webview` picks one.

The first launch asks how to use it:

- **Connect to your organisation's Shikari**: the app becomes a window onto the central server, with that server's users, library, detections and mappings. Nothing is stored or run locally apart from the login session, and upgrading the server upgrades everyone.
- **Run Shikari on this computer**: the app runs its own server (on 127.0.0.1 only, port 8000 or the next free one) and stops it when the window closes. The first run takes a minute or two while it builds its caches.

Shikari > Change Server switches later. Data made in local mode stays on that computer.

## Connecting an Organisation

Deploy Shikari centrally as usual (`scripts/deployment/DEPLOY.md`) behind HTTPS, then point the apps at it. Users can type the address into the first-run screen, or IT can set it, which skips that screen and removes Change Server:

| | Setting |
|---|---|
| macOS | A configuration profile from your MDM: preference domain `com.cmdaltr.shikari`, key `ServerURL` (string) |
| Windows | Group Policy or Intune: `HKLM\SOFTWARE\Policies\cmdaltr\Shikari`, string value `ServerURL` (HKCU works too) |
| Linux | `/etc/shikari/client.json`: `{"server_url": "https://shikari.example.org"}` |
| Any | The environment variable `SHIKARI_SERVER` (a URL, or `local`); not locked |

For macOS, the profile's payload is a Custom Settings (`com.apple.ManagedClient.preferences`) payload for `com.cmdaltr.shikari`:

```xml
<key>ServerURL</key>
<string>https://shikari.example.org</string>
```

The app checks a server before opening it: it must answer `/health` as Shikari, over HTTPS with a certificate the operating system trusts. An internal CA works once IT has deployed it to the machines. There's no way to click through a certificate error. A user can't type a plain `http://` address except for this computer; IT's setting and `SHIKARI_SERVER` can, for a server on a trusted network.

## Where Your Data Lives

In local mode (connected to a server, this folder only holds the login session and logs):

| | Folder |
|---|---|
| macOS | `~/Library/Application Support/Shikari/home` |
| Windows | `%LOCALAPPDATA%\Shikari\home` |
| Linux | `~/.local/share/shikari/home` |

The folder holds the database, generated detections, caches, logs (`logs/shikari.log`) and `bespoke/`. Uninstalling the app leaves it in place; delete it to start again. Set `SHIKARI_HOME` to use another folder.

The first run fills it from the installer: the reference data in the repository's `data/`, the ATT&CK bundle and the procedures CSV built from it at release time, and generic mappings in `bespoke/mappings/` (Splunk set up for CEF; see `shikari/mappings/defaults/README.md`). Put your organisation's own mappings in `bespoke/mappings/` to replace them: Shikari never overwrites a file that's there.

## What the Installed App Doesn't Do

It can't rebuild the procedures CSV itself: MITRESaw needs its own Python environment. A newer ATT&CK release is downloaded at startup as usual, but threat briefings use the CSV from the installer until the next release. The OSINT detection repositories and detection export need git. The Windows installer carries its own (Git for Windows' MinGit, pinned by SHA-256 in `desktop/stage.py`, its licences in `mingit/`), used only when no git is installed. On a Mac without the developer tools the repositories are downloaded as GitHub tarballs instead, keeping only the rule folders; Azure-Sentinel's tarball is 3.4 GB, so that way it's refreshed weekly rather than hourly, and only when the repository has changed. Ollama is a separate install, which Shikari finds as usual.

## Building

`.github/workflows/desktop.yml` builds all five on a `v*` tag (the `.deb`s on Ubuntu 22.04, the oldest they support), installs the macOS, Windows and Linux packages on clean runners with the install scripts and checks each one serves Shikari, then attaches them and `SHA256SUMS` to a GitHub Release; run it by hand (Actions > Desktop app > Run workflow) for a test build, left as workflow artifacts. It also builds a Windows ARM64 MSI, marked experimental and left out of releases: its window can't open yet, because pythonnet's .NET Framework loader (`clr_loader`) has no ARM64 build. A seed job downloads ATT&CK and runs MITRESaw for the procedures CSV, cached per ATT&CK version, so only a release after an ATT&CK update pays the 90 minutes.

To build on your own machine (macOS here; each platform builds only its own installer):

```bash
.venv/bin/python desktop/stage.py --attack shikari/data/cache/enterprise-attack.json \
  --procedures data/mitre_procedures.csv data/mitre_procedures.meta.json
cd ~/.cache/shikari/desktop
python3.11 -m venv .briefcase && .briefcase/bin/pip install briefcase
.briefcase/bin/briefcase package macOS --adhoc-sign    # dist/Shikari-<version>.dmg
```

On Linux, Briefcase isn't used: `python3 desktop/build_deb.py --stage ~/.cache/shikari/desktop` builds the `.deb` from the staged tree (it needs `dpkg-deb`, `libgirepository1.0-dev`, `libcairo2-dev` and `pkg-config`).

`desktop/stage.py` copies only what git would include (tracked files and new ones that aren't ignored), so nothing `.gitignore` keeps out of the repository can reach an installer; it builds outside the repository because a build is several hundred MB. The installed app's entry point is `shikari/desktop_app.py`; where it puts things is `shikari/paths.py`. Icons come from `shikari.png` via `desktop/make_icons.py`.
