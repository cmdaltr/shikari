# Emulate

**Build → Emulate** shows which logs record each ATT&CK technique, taken from attacks emulated and recorded in public labs, and checks your detections' indicators against those recordings. No AI is involved and nothing is sent to your SIEM.

## Plan an emulation

The page opens on a planner. Pick a target — a **group**, a **CVE** or a **technique** — and Shikari assembles a plan to review before you act: for each technique, the most appropriate recorded dataset to validate against, the matching Atomic Red Team test (where a local atomics checkout is configured), the log sources to collect (native OS logs first, then Sysmon and EDR), the OS platforms to run on, and the SIEMs to validate in (your Profile SIEMs).

**Deploy** doesn't run anything in-app yet — running atomics and collecting telemetry is [recording a lab](20-recording-a-lab.md) (coming soon). For now it exports the plan two ways: a **run sheet** (a Markdown table of what to run, collect and validate) and a **MACATable TOML** for [MACAT](https://www.macat.io) to run on your lab and push to VECTR. Record the outcomes in an [assessment](23-threat-library-assessments.md).

The recorded-telemetry views below the planner are the evidence layer: they're where you confirm which logs actually captured each technique, and whether your detections' indicators appear in them.

## Where the recordings come from

| Source | Licence | What it is |
|---|---|---|
| [Splunk attack_data](https://github.com/splunk/attack_data) | Apache-2.0 | Atomic Red Team and tool runs in Splunk's Attack Range. Maintained |
| [Security-Datasets (OTRF)](https://github.com/OTRF/Security-Datasets) | MIT | Empire, Covenant and tool runs in OTRF's lab. Last updated March 2024 |
| [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | CC0-1.0 | Windows event log samples of attacks, one .evtx per attack, filed by technique. Maintained |
| [macOS-ATTACK-DATASET](https://github.com/sbousseaden/macOS-ATTACK-DATASET) | GPL-3.0 | macOS attacks recorded with Elastic Endpoint (2021), filed by tactic; the technique of each file is Shikari's reading of its name. Built on your machine only, never committed |

Each recording is one tool run in a lab with logging on (Sysmon, Windows auditing, PowerShell, cloud audit logs, auditd, syslog), mapped to ATT&CK by the people who recorded it. It shows that a technique can be recorded and by which log, for that tool in that lab, not every way the technique can be done.

Splunk attack_data also holds Linux (auditd, syslog, auth.log, Sysmon for Linux) and macOS (osquery's Endpoint Security process events and launchd plists) recordings. The first three sources ship with Shikari: `shikari/data/telemetry_datasets.json` (each recording's techniques and event types) and `shikari/data/telemetry_values.json.gz` (the distinct values of the fields detections match on). **Update** on the page (admins) or the command below fetches only the recordings the sources have changed since:

```
python -m shikari.telemetry --build                  # all four
python -m shikari.telemetry --build --source macos   # or splunk, otrf, evtx
```

A full build downloads about 1.2 GB. Splunk's logs are read up to 3 MB each: the median is 10 KB, but a few captures run to hundreds of MB of lab background.

The **Indicator check** tile says whether detections can be checked: green **Ready**, orange **Starting…** while an update runs, red **Unavailable** when the field values aren't on this machine, blue **Error** when the last update failed.

## Defender XDR's own alerting (Microsoft GUIDE)

[GUIDE](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction) (CDLA-Permissive-2.0) is Microsoft's set of 13.7 million Defender XDR alerts and evidence rows from 5,216 organisations over two weeks, each alert with its ATT&CK techniques and the customer's triage grade. Its values are anonymised, so it says nothing about what an attack looks like in the logs; it says whether Defender XDR alerts on a technique out of the box, how widely, and how often rightly. With Defender XDR as the SIEM, the technique view gets a **Defender alerts** filter, and a technique's detail (select its row) gives its alerts, detectors, organisations, grades, alert categories and evidence types. A technique Defender seldom alerts on, or mostly gets wrong, is where a custom detection earns its keep.

The summary ships with Shikari (`shikari/data/telemetry_guide.json`). To rebuild it, download the zip from Kaggle (a free account; the API token in `~/.kaggle/access_token` works too) and:

```
python -m shikari.telemetry --guide ~/Downloads/microsoft-security-incident-prediction.zip
```

## Lab: machines from inside Shikari

The **Lab** section (admins) installs, creates and manages the containers and VMs a recording runs on, without leaving Shikari. It drives three engines: **Docker** and **Tart** create Linux and macOS machines from an image; **UTM** (QEMU) runs Windows 11 on ARM and other OSes, but has no create-from-image, so you build that VM in the UTM app once and Shikari then manages, snapshots, provisions and records it. (Tart can't run Windows — Apple's Virtualization.framework only takes Linux and macOS guests.) It detects and guides; it doesn't install hypervisors itself. The first time Shikari drives UTM, grant it Automation access to UTM when macOS asks.

The **host card** names this machine's OS and CPU and each engine's state:

| Engine | Runs | Where |
|---|---|---|
| Docker (or OrbStack) | Linux containers | any host |
| Tart | macOS and Linux VMs | Apple Silicon only |

An engine that's missing shows the exact install command to copy. **Create a machine** lists one card per OS this host can run, the image chosen for its CPU: on an Apple Silicon Mac, Ubuntu (a Docker container or a Tart VM) and macOS (a Tart VM), with a Create button per platform. Each card says what it records, so it ties back to the telemetry above.

Windows is the exception, because UTM has no create-from-image. The Windows card offers two ways to get a machine: **Clone existing** copies a Windows VM you've already built (via `utmctl clone` — instant on APFS until the disk diverges), and the clone inherits its OS and set-up; **From ISO** is a guided build — Shikari verifies that a downloaded file is a genuine Windows 11 ARM64 installer (a read-only check of the ISO, no hash), then you build the VM in UTM once and it appears under Your machines. After the first one, Clone is the quick path. A **Clone** button on each UTM machine row does the same copy.

**Your machines** lists every container and VM on the host — the ones Shikari made and any made outside it — with a dot for running or stopped. Per machine: **Start/Stop**, **Snapshot**, **Revert**, **Set up**, **Logs** and **Delete**. Delete and Revert confirm first; both are irreversible.

**Set up** provisions a machine in place, each step run inside it:

| Step | Linux | macOS | Windows |
|---|---|---|---|
| Turn on audit logging | auditd with ATT&CK rules | notes Endpoint Security / unified log (eslogger needs Full Disk Access, granted in System Settings) | Security, PowerShell and audit policy |
| Install PowerShell 7 | from Microsoft's installer | via Homebrew | already present |
| Install Atomic Red Team | Invoke-AtomicRedTeam and the atomics | same | same |

These change the machine, so snapshot it first — the section says so, and Revert puts it back. On a Tart VM the steps run through its guest agent (the Cirrus Labs base images include it); a custom image without it is reported rather than failing silently.

Nothing a hypervisor doesn't already expose is sent anywhere, and the machine names Shikari tracks stay in `data/lab/` (gitignored).

Beyond the Atomic recorder, the Lab also runs **CALDERA operations** against an agent group — chained emulation with a real implant (sandcat), captured over the agent's own C2 and checked against your saved detections and correlations. See [CALDERA operations](25-caldera.md).

## Recording your own lab

No public set of attacks recorded by Defender for Endpoint, or by macOS's unified log, exists that Shikari has found, so the gaps are filled by recording your own. A machine's **Record** button (admins) drives this from inside Shikari: give it the ATT&CK technique IDs, it copies `scripts/telemetry/record-atomics.ps1` into the machine, runs the atomics, pulls each test's logs back into `data/telemetry/lab/<run>`, reverts the machine to the snapshot you name, and rebuilds **Your lab**. **Preview** shows exactly what a run would do and runs nothing; the run itself is gated on confirming the machine is snapshotted and disposable.

The same script runs by hand on any disposable test machine (PowerShell 7, elevated) and saves each test's logs:

| Platform | Recorded |
|---|---|
| Windows | Security, System, PowerShell, Sysmon if installed, Task Scheduler, WMI, Defender and BITS events |
| Linux | auditd (`/var/log/audit`) and the systemd journal |
| macOS | Endpoint Security events (eslogger; the terminal needs Full Disk Access), the unified log, and launch agents, daemons and login hooks added, changed or removed |

```
sudo pwsh ./record-atomics.ps1 -Techniques T1053.003,T1543.001,T1059.004
```

If the machine is onboarded to Defender for Endpoint, fetch Defender's own rows for each test once they've arrived (usually within the hour), through Microsoft Graph's Advanced Hunting. It needs an app registration with `ThreatHunting.Read.All` (application, admin consented) in `SHIKARI_MDE_TENANT_ID`, `SHIKARI_MDE_CLIENT_ID` and `SHIKARI_MDE_CLIENT_SECRET`:

```
python -m shikari.telemetry --mde-export data/telemetry/lab/<run>
```

If you ran the script by hand, copy the run's folder to `data/telemetry/lab/` and press **Update**; **Record** does this copy for you. The step-by-step setup, from the Defender trial tenant to each VM, is [Recording a lab](20-recording-a-lab.md). Your recordings appear as **Your lab**; they hold your hosts' and tenant's names, so `data/telemetry/` is gitignored and they never leave the machine.

## Filters

The filter card applies to whichever view is open below it, and shows only the filters that view uses.

| Filter | What it picks |
|---|---|
| SIEM | Google SecOps or Defender XDR: whose UDM event types or tables are shown, and in the group view, whose detections. Defaults to your first SIEM under Environment → SIEM platforms |
| Indicators | Free text. By technique: techniques whose recorded events hold a field value containing it (`…` gaps match their parts in order). By group: detections with an indicator containing it |
| Techniques | Search by ID or name |
| Groups | Groups you've hunted. By technique or data source: the techniques their detections are for |
| Data sources | The SIEM's tables or UDM event types |
| Logs | Recorded event types: Sysmon 1, Security 4688 |
| Collection | Which kinds of logging count: Native OS logs, Sysmon, EDR, osquery, Cloud and SaaS. For Google SecOps the default leaves out Sysmon, which is deployed far less than native logging. For Defender XDR it's kept: Sysmon's recordings stand in for the MDE sensor, which records the same process, file, network, registry and image-load activity without Sysmon installed |
| Defender alerts | With Defender XDR as the SIEM: techniques it alerts on mostly rightly (half or more true positives), mostly not, or not at all (GUIDE) |
| Platforms | Windows, Linux, macOS, ESXi, Cloud and SaaS: only the logs from these platforms count, so Linux shows what Linux logging records of each technique |
| Seen | By group only: Seen, Not seen, No recordings, No indicators, or any noisy indicator |

## Telemetry

Where the recordings come from (above), and the views over them. **Update** (admins, or `python -m shikari.telemetry --build`) fetches what the sources have changed since. The **Organise by** control switches the view between technique, group and data source; the Filters card at the top of the page applies to whichever is open.

### Organise by technique

Every recorded technique, 20 to a page. The **Recordings** column shows the total; **Datasets** breaks that down per source, the count sitting on each dataset's logo; **Platforms** shows the OS icons the technique was recorded on (the Linux penguin for Linux generally, the Ubuntu mark only for Ubuntu); and **Logs** lists the **logs** at least half its recordings hold, and, beneath them, those logs' tables or UDM event types for the chosen SIEM: the logs you have to ingest to see it. Only the kinds of logging chosen under Collection count, so with Sysmon left out a technique shows what native logging alone records; one none of whose recordings hold the chosen logs is marked **No recording holds the chosen logs**, a gap for that kind of logging. Select a row for every event type its recordings hold and the recordings themselves. An event type marked **common** turns up in 40% or more of a source's recordings (Security 4688, Sysmon 1), so it's a hint that the event is lab background as much as the attack; it's never taken out.

### Organise by group

Your detections for the chosen SIEM, for the groups picked in Filters (your latest hunt when none are). Each detection's indicators are matched against the field values of its technique's recordings:

| Status | Meaning |
|---|---|
| Seen | A recorded event of the attack contains at least one indicator; the tag names the log and shows the source's logo |
| Not seen | The technique has recordings, but none contain the detection's indicators |
| No recordings | No source recorded the technique |
| No indicators | The detection has no literal indicators to look for |

An indicator is **noisy** when recordings of five or more other techniques contain it too: it matches the lab's ordinary activity as well as the attack. The same check is a tool, `noisy_indicators`, for the [agents](15-agents-and-ask-shikari.md) and any MCP client: give it a detection's match values, or a technique whose own recorded values it should vet, and it says which are poor discriminators. The Library audit agent uses it; Ask Shikari has it too.

Not seen isn't proof a detection is wrong: the recording may have used another tool or procedure. It's a cheap first look before testing against your own SIEM.

### Organise by data source

Each table or UDM event type for the chosen SIEM, with how many techniques it records (counting it for a technique when at least half the technique's recordings hold it), the recorded logs it comes from, and the techniques. A technique opens in the technique view.

## Limits

- Four labs, each with their own logging policy: an event type missing from the recordings may just not have been collected.
- Until you record your own, Defender XDR tables are mapped from the Windows, Linux and macOS events that record the same activity, and macOS has no unified log recordings.
- GUIDE's grades are its customers' triage, two weeks of it; a technique's sub-techniques without figures of their own show their parent's.
- The Windows event ID, auditd and cloud log mappings are in `shikari/mappings/telemetry_map.json`; an event type not listed there shows without a table.
- Recording Atomic Red Team in your own lab, with Defender for Endpoint's own rows and the macOS unified log, is coming soon: the tooling is in place and the steps are in [Recording a lab](20-recording-a-lab.md), but no run has been recorded yet.
