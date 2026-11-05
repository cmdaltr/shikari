# Recording a lab

Step by step: set up disposable Windows, Linux and macOS test machines, run Atomic Red Team on them, and bring each test's logs, and Defender for Endpoint's own rows, into [Emulate](19-emulate.md) as **Your lab**. Public recordings cover Windows well but have nothing recorded by Defender for Endpoint and no macOS unified log; this fills both.

The quickest path is [Emulate → Lab](19-emulate.md#lab-machines-from-inside-shikari): create a machine, set logging on and install Atomic Red Team, snapshot it, then **Record** the techniques — Shikari runs the atomics in the machine, pulls the logs into `data/telemetry/lab/`, reverts and rebuilds **Your lab** for you. Linux and macOS machines are created from Lab directly; a Windows VM is built once in UTM (part 3) and then managed from Lab the same way. This page is the manual walkthrough of the same steps, and the only path for a machine Shikari doesn't manage (physical hardware, a cloud VM, or a VM without the UTM guest tools):

| In Shikari | Depends on |
|---|---|
| **Your lab** on the Emulate page | A run in `data/telemetry/lab/` — **Record**, or a run copied in (part 7) |
| Genuine Defender XDR rows (`MDE Device…` logs) | A machine onboarded to Defender (part 2) and `--mde-export` (part 6) |
| macOS unified log, Endpoint Security and plist recordings | The macOS VM (part 5) |

The atomics change the machines they run on. Run them only on VMs you can throw away, and take a snapshot first.

## 1. What you need

| | Where | Notes |
|---|---|---|
| Windows 11 VM | Apple Silicon (ARM64) | Built once in UTM (part 3), then managed from Lab. Shikari can't create it — UTM has no create-from-image and Tart doesn't run Windows |
| Ubuntu Server 24.04 VM | Any | Or create it from Lab (Docker container or Tart VM) |
| macOS VM | ARM MacBook | Tart (free) runs macOS VMs on Apple Silicon; create it from Lab |
| UTM/QEMU for Windows | Apple Silicon | Free, open-source (`brew install --cask utm`). VMware Fusion (free, incl. commercial) also runs Windows 11 ARM64; Parallels works but is paid |
| A Defender for Endpoint trial tenant | Microsoft | Only for Defender's own rows; the native logs need nothing |
| Shikari's machine | | Where the runs end up |

Give each VM 4 GB of RAM and 60 GB of disk, and a NAT network with internet access (the atomics download their prerequisites).

## 2. The Defender trial tenant (optional, for Defender's rows)

1. Start a Microsoft Defender for Endpoint Plan 2 trial (the Microsoft 365 admin centre's trials, or Microsoft's Defender for Endpoint trial page). It makes a new tenant (`yourname.onmicrosoft.com`); check the trial's current length when you sign up and plan the runs inside it.
2. In the Defender portal (security.microsoft.com), wait for the tenant to provision (it can take a few hours), then **Settings → Endpoints → Onboarding**, and download the onboarding package for each OS you'll onboard: Windows (local script), Linux server (the installer script), macOS (the installation package and the onboarding package).
3. Register an app for Shikari to read Advanced Hunting through Microsoft Graph. In the Entra admin centre:
   - **App registrations → New registration**: name it `shikari-telemetry`, single tenant, no redirect URI.
   - **API permissions → Add → Microsoft Graph → Application permissions → `ThreatHunting.Read.All`**, then **Grant admin consent**.
   - **Certificates & secrets → New client secret**; copy the value now (it's shown once).
   - Note the **Directory (tenant) ID** and **Application (client) ID** from the Overview page.
4. On Shikari's machine, put them in your shell profile (never in the repository):

```bash
export SHIKARI_MDE_TENANT_ID="<directory (tenant) id>"
export SHIKARI_MDE_CLIENT_ID="<application (client) id>"
export SHIKARI_MDE_CLIENT_SECRET="<client secret value>"
```

## 3. Windows VM (UTM, Apple Silicon)

UTM has no create-from-image, so unlike the Linux and macOS machines this one is built by hand once and then managed from Lab. Install UTM first (`brew install --cask utm`), then get a Windows 11 ARM64 image one of the two ways below. Either way, name the VM `shi-win11` — space-free, so Shikari can address it — give it 4 GB of RAM, and once Windows is up take a snapshot called `clean`.

**From Microsoft's ISO (preferred).** Microsoft publish an official multi-edition Windows 11 ARM64 ISO (~5 GB) at [microsoft.com/software-download/windows11arm64](https://microsoft.com/software-download/windows11arm64). Create a VM in UTM from it and run the normal install. There's no ARM64 *evaluation* SKU, so it installs unactivated — a watermark, no functional limit, fine for a disposable lab VM. At OOBE use a local account; no Microsoft account is needed. The source is Microsoft, so nothing here is untrusted.

**From the community gallery (faster).** The official UTM gallery is no longer maintained, but a community gallery ([naveenrajm7.github.io/utm-gallery](https://naveenrajm7.github.io/utm-gallery/vms/windows-11.html)) carries a pre-built Windows 11 Pro ARM64 box (Packer/Bento, Vagrant). Its **Open in UTM** button runs a one-line fetch; the CLI equivalent is `curl -sSf https://naveenrajm7.github.io/utm-gallery/getbox.sh | sh -s windows-11`, which pulls ~5.7 GB and imports the VM. It's a third-party image — treat it as untrusted: disposable VM only, no real credentials. It's a headless build, so add a **Display** before first boot (Edit → Devices → New → Display); the default login is `vagrant` / `vagrant`, which you change.

1. Install the UTM guest tools (the SPICE guest-support package) so Shikari can run commands through `utmctl exec`. Without them Shikari can still snapshot and revert the VM but can't set it up or record in it, and you fall back to the manual steps below.

2. In Shikari, open **Emulate → Lab**. The VM shows under **Your machines**; use **Set OS → Windows** to tell Shikari what it is. From there **Set up** turns on audit logging and installs PowerShell 7 and Atomic Red Team (steps 3, 7), and **Record** drives the atomics. Defender onboarding and the antivirus decision (steps 5–6) stay manual either way. The rest of this section is what those buttons do, for a VM Shikari can't reach or when you'd rather do it by hand.

   A running machine also has two in-browser consoles. **Console** is an interactive shell (through `utmctl exec` / `docker exec` / `tart exec`) and needs nothing extra. **Desktop** is a graphical VNC console: UTM's own display is SPICE rather than VNC, so Shikari can't auto-discover it — the first time you open Desktop it asks for the machine's VNC endpoint (`host:port`, which must be loopback or private), which it then saves and bridges noVNC to. Stand up a VNC display on the VM (a QEMU `-vnc` target, or a VNC server inside the guest) to use it. Both consoles are owner/admin-only and survive a dropped connection for a few minutes.

3. Turn on the logging native to Windows that detections rely on (an elevated PowerShell):

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
auditpol /set /category:"Logon/Logoff","Account Management","Object Access","Policy Change","Privilege Use","DS Access" /success:enable /failure:enable
```

4. Sysmon is optional. Native logging is what most estates have, and Emulate can count without it, but a recording with Sysmon shows both: install it with a community configuration (SwiftOnSecurity's or Olaf Hartong's sysmon-modular).
5. To record Defender's rows, run the Windows onboarding script from part 2 and check the device appears under **Assets → Devices**.
6. Microsoft Defender Antivirus will block many atomics. Either leave it on (the recording then shows what Defender stops, which is realistic) or exclude `C:\AtomicRedTeam` to let the tests run to completion. Decide per run and name the run after it (`-Run win11-av-on`).
7. Install PowerShell 7 and Atomic Red Team (part 6).
8. Take a snapshot called `ready`.

## 4. Ubuntu VM

1. Install Ubuntu Server 24.04 with OpenSSH. Snapshot `clean`.
2. auditd with ATT&CK-focused rules:

```bash
sudo apt update && sudo apt install -y auditd
curl -sL https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules | sudo tee /etc/audit/rules.d/audit.rules >/dev/null
sudo augenrules --load && sudo systemctl restart auditd
sudo auditctl -l | head
```

3. PowerShell 7 (Microsoft's package repository):

```bash
source /etc/os-release
wget -q https://packages.microsoft.com/config/ubuntu/$VERSION_ID/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb && sudo apt update && sudo apt install -y powershell
```

4. To record Defender's rows, run the Linux installer script from part 2 with the onboarding package, then `mdatp health` should show `healthy: true` and `licensed: true`.
5. Install Atomic Red Team (part 6). Snapshot `ready`.

## 5. macOS VM

1. On the MacBook:

```bash
brew install cirruslabs/cli/tart
tart clone ghcr.io/cirruslabs/macos-sequoia-base:latest atomic-mac
tart run atomic-mac
```

   Sign in with the image's default account (in Cirrus Labs' README) and change its password. Shut down and `tart clone atomic-mac atomic-mac-clean` as the `clean` snapshot.
2. In the VM: install Homebrew, then `brew install --cask powershell`.
3. eslogger (built into macOS 13 and later) needs **Full Disk Access** for the app the script runs in: **System Settings → Privacy & Security → Full Disk Access**, add Terminal (and `pwsh` if prompted).
4. To record Defender's rows, install the macOS package and onboarding package from part 2, and approve the system extensions and Full Disk Access it asks for. `mdatp health` should be healthy.
5. Install Atomic Red Team (part 6). Shut down and `tart clone atomic-mac atomic-mac-ready`.

## 6. Atomic Red Team, and running the recorder

On each VM, in PowerShell 7 (elevated on Windows, `sudo pwsh` on Linux and macOS):

```powershell
Install-Module invoke-atomicredteam -Scope AllUsers -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

Copy `scripts/telemetry/record-atomics.ps1` from Shikari to the VM, then run it with the techniques to record:

```powershell
# Windows (elevated pwsh)
./record-atomics.ps1 -Techniques T1003.001,T1053.005,T1059.001,T1547.001,T1218.011,T1112,T1070.001,T1490 -Run win11-av-on
```

```bash
# Ubuntu
sudo pwsh ./record-atomics.ps1 -Techniques T1053.003,T1136.001,T1098.004,T1548.001,T1070.003,T1059.004,T1105,T1543.002,T1222.002,T1082 -Run ubuntu-auditd
# macOS
sudo pwsh ./record-atomics.ps1 -Techniques T1543.001,T1543.004,T1547.015,T1037.002,T1059.002,T1555.001,T1553.001,T1564.001,T1053.003,T1056.002 -Run mac-sequoia
```

`-Techniques` also takes a file with one technique ID per line. Other options: `-Settle 20` (seconds of logging after each test), `-Timeout 120`, `-NoCleanup`, `-Out <folder>` (default `./shikari-lab`). Each test's logs land in `shikari-lab/<run>/<technique>-<test>/`, and `manifest.json` is saved after every test, so a run that stops part-way is still usable.

| Platform | Each test's files |
|---|---|
| Windows | `events.xml`: Security, System, Application, PowerShell, Sysmon, Task Scheduler, WMI, Defender, BITS and RDP session events |
| Linux | `audit.log` (auditd), `journal.log` (the systemd journal) |
| macOS | `es.ndjson` (Endpoint Security), `unified.ndjson` (the unified log), `plists.ndjson` (launch agents, daemons and login hooks added, changed or removed) |

Revert the VM to `ready` after each run.

## 6a. Recording a custom or novel execution

Atomic Red Team only covers behaviours someone has already written an atomic for. To build your own dataset for a **novel or undocumented technique**, a custom procedure variant, or anything no public corpus covers, use `scripts/telemetry/record-custom.ps1`. It wraps an arbitrary command instead of an ART test, captures the identical per-platform telemetry, and writes the same layout — so it grounds detection fields exactly as an ART run does, including for behaviours with no public procedure example.

Because it executes whatever you hand it — unvetted, possibly malicious — it **refuses to run unless the machine is a designated lab host**: set `SHIKARI_LAB_HOST=1`, create `~/.shikari-lab-host`, or pass `-IAmADisposableLabHost`. Designate only a snapshot-and-revert VM or an `sbx` microVM, never a host that matters.

```bash
# Map it to a best-fit (sub-)technique...
sudo pwsh ./record-custom.ps1 -ScriptPath ./variant.sh -Name 'per-second cron' -Mapping T1053.003 -MappingKind sub -Notes 'schedule ART does not cover'
# ...or record it as explicitly novel/unmapped
sudo SHIKARI_LAB_HOST=1 pwsh ./record-custom.ps1 -Command 'rundll32 .\payload.dll,Start' -Name 'novel dll persistence' -MappingKind novel
```

Each execution lands in `shikari-lab/<run>/custom-<n>/`; call it again with the same `-Run` to add more to one run. The manifest entry is marked `custom`, carries your mapping (or `novel`), the command and your notes, and round-trips through **Update** like any other recording. After Update it appears in the **Custom & novel recordings** panel on the Emulate page — mapped ones also feed the technique views, novel/unmapped ones only the panel, since they have no technique to file under.

Each panel row has **Generate detection**, which builds SIEM queries grounded in that recording's *observed* telemetry — the fields its events actually held — rather than MITRESaw evidence, with no AI. That's how you get a detection for a behaviour no public corpus describes. It produces queries for all four SIEMs — Google SecOps (YARA-L), Defender XDR (KQL), Splunk (SPL) and Elastic (ES|QL) — from the bespoke indicator mappings.

## 7. Into Shikari

1. Copy the run folder from the VM to Shikari's `data/telemetry/lab/` (scp, a shared folder, or `tart` file sharing):

```bash
scp -r user@vm:shikari-lab/ubuntu-auditd data/telemetry/lab/
```

2. If the VM was onboarded to Defender, wait an hour for its telemetry to arrive, then fetch each test's Device* rows:

```bash
python -m shikari.telemetry --mde-export data/telemetry/lab/win11-av-on
```

3. On the Emulate page, **Update** (or `python -m shikari.telemetry --build --source lab`). The run appears as **Your lab**, with `lab:<run>/<technique>-<test>` recordings. Choose your platform under **Platforms** to see what your own logging records of each technique, and check a group's detections against it.

`data/telemetry/` is gitignored: the recordings carry your VMs' and tenant's names and never leave Shikari's machine.

## Troubleshooting

| Problem | Fix |
|---|---|
| `eslogger: Not permitted` | Full Disk Access for the terminal, and run as root (`sudo pwsh`) |
| No `audit.log` on Linux | `sudo systemctl status auditd`; the rules loaded (`sudo auditctl -l`) |
| A test's folder is empty | It didn't run on this platform, or its prerequisites failed: the console shows the warning |
| `--mde-export`: 403 | Admin consent wasn't granted for `ThreatHunting.Read.All`, or the secret expired |
| `--mde-export`: 0 rows | Defender hasn't caught up yet (wait longer), or the device name differs from the manifest's `host` |
| A UTM VM won't boot — `QEMULauncher` crashes at launch (sandbox/`libsecinit` trap) | The VM is on a volume mounted `noowners` (common for external drives). Enable ownership: `sudo diskutil enableOwnership /Volumes/<name>` (or Finder → Get Info → untick *Ignore ownership on this volume*), then re-open the VM in UTM. Or keep the VM on the internal disk |
| UTM crashes on launch on macOS 26/27 (`libswift_Concurrency`, `swift_task_isCurrentExecutor`) | UTM 5.0.8's stable build predates that macOS; install the newer beta from [mac.getutm.app](https://mac.getutm.app/). Shikari's clone and headless `utmctl` work regardless; the GUI is only needed to build a VM from an ISO |
