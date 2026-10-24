# Recording a lab

Step by step: set up disposable Windows, Linux and macOS test machines, run Atomic Red Team on them, and bring each test's logs, and Defender for Endpoint's own rows, into [Emulate](19-emulate.md) as **Your lab**. Public recordings cover Windows well but have nothing recorded by Defender for Endpoint and no macOS unified log; this fills both.

The quickest path is [Emulate → Lab](19-emulate.md#lab-machines-from-inside-archer): create a machine, set logging on and install Atomic Red Team, snapshot it, then **Record** the techniques — Archer runs the atomics in the machine, pulls the logs into `data/telemetry/lab/`, reverts and rebuilds **Your lab** for you. This page is the manual walkthrough of the same steps, and the only path for a machine Archer doesn't manage (an x64 Windows host, physical hardware, or a cloud VM):

| In Archer | Depends on |
|---|---|
| **Your lab** on the Emulate page | A run in `data/telemetry/lab/` — **Record**, or a run copied in (part 7) |
| Genuine Defender XDR rows (`MDE Device…` logs) | A machine onboarded to Defender (part 2) and `--mde-export` (part 6) |
| macOS unified log, Endpoint Security and plist recordings | The macOS VM (part 5) |

The atomics change the machines they run on. Run them only on VMs you can throw away, and take a snapshot first.

## 1. What you need

| | Where | Notes |
|---|---|---|
| Windows 11 VM | Intel Mac Mini | Windows 11 Enterprise evaluation ISO (free, time-limited). x64, so not the ARM MacBook |
| Ubuntu Server 24.04 VM | Intel Mac Mini | |
| macOS VM | ARM MacBook | Tart (free) runs macOS VMs on Apple Silicon |
| Hypervisor on the Mac Mini | | VMware Fusion (free for personal use) or VirtualBox |
| A Defender for Endpoint trial tenant | Microsoft | Only for Defender's own rows; the native logs need nothing |
| Archer's machine | | Where the runs end up |

Give each VM 4 GB of RAM and 60 GB of disk, and a NAT network with internet access (the atomics download their prerequisites).

## 2. The Defender trial tenant (optional, for Defender's rows)

1. Start a Microsoft Defender for Endpoint Plan 2 trial (the Microsoft 365 admin centre's trials, or Microsoft's Defender for Endpoint trial page). It makes a new tenant (`yourname.onmicrosoft.com`); check the trial's current length when you sign up and plan the runs inside it.
2. In the Defender portal (security.microsoft.com), wait for the tenant to provision (it can take a few hours), then **Settings → Endpoints → Onboarding**, and download the onboarding package for each OS you'll onboard: Windows (local script), Linux server (the installer script), macOS (the installation package and the onboarding package).
3. Register an app for Archer to read Advanced Hunting through Microsoft Graph. In the Entra admin centre:
   - **App registrations → New registration**: name it `archer-telemetry`, single tenant, no redirect URI.
   - **API permissions → Add → Microsoft Graph → Application permissions → `ThreatHunting.Read.All`**, then **Grant admin consent**.
   - **Certificates & secrets → New client secret**; copy the value now (it's shown once).
   - Note the **Directory (tenant) ID** and **Application (client) ID** from the Overview page.
4. On Archer's machine, put them in your shell profile (never in the repository):

```bash
export ARCHER_MDE_TENANT_ID="<directory (tenant) id>"
export ARCHER_MDE_CLIENT_ID="<application (client) id>"
export ARCHER_MDE_CLIENT_SECRET="<client secret value>"
```

## 3. Windows VM

1. Install Windows 11 Enterprise evaluation. Take a snapshot called `clean`.
2. Turn on the logging native to Windows that detections rely on (an elevated PowerShell):

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
auditpol /set /category:"Logon/Logoff","Account Management","Object Access","Policy Change","Privilege Use","DS Access" /success:enable /failure:enable
```

3. Sysmon is optional. Native logging is what most estates have, and Emulate can count without it, but a recording with Sysmon shows both: install it with a community configuration (SwiftOnSecurity's or Olaf Hartong's sysmon-modular).
4. To record Defender's rows, run the Windows onboarding script from part 2 and check the device appears under **Assets → Devices**.
5. Microsoft Defender Antivirus will block many atomics. Either leave it on (the recording then shows what Defender stops, which is realistic) or exclude `C:\AtomicRedTeam` to let the tests run to completion. Decide per run and name the run after it (`-Run win11-av-on`).
6. Install PowerShell 7 and Atomic Red Team (part 6).
7. Take a snapshot called `ready`.

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

Copy `scripts/telemetry/record-atomics.ps1` from Archer to the VM, then run it with the techniques to record:

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

`-Techniques` also takes a file with one technique ID per line. Other options: `-Settle 20` (seconds of logging after each test), `-Timeout 120`, `-NoCleanup`, `-Out <folder>` (default `./archer-lab`). Each test's logs land in `archer-lab/<run>/<technique>-<test>/`, and `manifest.json` is saved after every test, so a run that stops part-way is still usable.

| Platform | Each test's files |
|---|---|
| Windows | `events.xml`: Security, System, Application, PowerShell, Sysmon, Task Scheduler, WMI, Defender, BITS and RDP session events |
| Linux | `audit.log` (auditd), `journal.log` (the systemd journal) |
| macOS | `es.ndjson` (Endpoint Security), `unified.ndjson` (the unified log), `plists.ndjson` (launch agents, daemons and login hooks added, changed or removed) |

Revert the VM to `ready` after each run.

## 7. Into Archer

1. Copy the run folder from the VM to Archer's `data/telemetry/lab/` (scp, a shared folder, or `tart` file sharing):

```bash
scp -r user@vm:archer-lab/ubuntu-auditd data/telemetry/lab/
```

2. If the VM was onboarded to Defender, wait an hour for its telemetry to arrive, then fetch each test's Device* rows:

```bash
python -m archer.telemetry --mde-export data/telemetry/lab/win11-av-on
```

3. On the Emulate page, **Update** (or `python -m archer.telemetry --build --source lab`). The run appears as **Your lab**, with `lab:<run>/<technique>-<test>` recordings. Choose your platform under **Platforms** to see what your own logging records of each technique, and check a group's detections against it.

`data/telemetry/` is gitignored: the recordings carry your VMs' and tenant's names and never leave Archer's machine.

## Troubleshooting

| Problem | Fix |
|---|---|
| `eslogger: Not permitted` | Full Disk Access for the terminal, and run as root (`sudo pwsh`) |
| No `audit.log` on Linux | `sudo systemctl status auditd`; the rules loaded (`sudo auditctl -l`) |
| A test's folder is empty | It didn't run on this platform, or its prerequisites failed: the console shows the warning |
| `--mde-export`: 403 | Admin consent wasn't granted for `ThreatHunting.Read.All`, or the secret expired |
| `--mde-export`: 0 rows | Defender hasn't caught up yet (wait longer), or the device name differs from the manifest's `host` |
