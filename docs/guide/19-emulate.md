# Emulate

**Build → Emulate** shows which logs record each ATT&CK technique, taken from attacks emulated and recorded in public labs, and checks your detections' indicators against those recordings. No AI is involved and nothing is sent to your SIEM.

## Where the recordings come from

| Source | Licence | What it is |
|---|---|---|
| [Splunk attack_data](https://github.com/splunk/attack_data) | Apache-2.0 | Atomic Red Team and tool runs in Splunk's Attack Range. Maintained |
| [Security-Datasets (OTRF)](https://github.com/OTRF/Security-Datasets) | MIT | Empire, Covenant and tool runs in OTRF's lab. Last updated March 2024 |
| [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | CC0-1.0 | Windows event log samples of attacks, one .evtx per attack, filed by technique. Maintained |
| [macOS-ATTACK-DATASET](https://github.com/sbousseaden/macOS-ATTACK-DATASET) | GPL-3.0 | macOS attacks recorded with Elastic Endpoint (2021), filed by tactic; the technique of each file is Archer's reading of its name. Built on your machine only, never committed |

Each recording is one tool run in a lab with logging on (Sysmon, Windows auditing, PowerShell, cloud audit logs, auditd, syslog), mapped to ATT&CK by the people who recorded it. It shows that a technique can be recorded and by which log, for that tool in that lab, not every way the technique can be done.

Splunk attack_data also holds Linux (auditd, syslog, auth.log, Sysmon for Linux) and macOS (osquery's Endpoint Security process events and launchd plists) recordings. The first three sources ship with Archer: `archer/data/telemetry_datasets.json` (each recording's techniques and event types) and `archer/data/telemetry_values.json.gz` (the distinct values of the fields detections match on). **Update** on the page (admins) or the command below fetches only the recordings the sources have changed since:

```
python -m archer.telemetry --build                  # all four
python -m archer.telemetry --build --source macos   # or splunk, otrf, evtx
```

A full build downloads about 1.2 GB. Splunk's logs are read up to 3 MB each: the median is 10 KB, but a few captures run to hundreds of MB of lab background.

The **Indicator check** tile says whether detections can be checked: green **Ready**, orange **Starting…** while an update runs, red **Unavailable** when the field values aren't on this machine, blue **Error** when the last update failed.

## Defender XDR's own alerting (Microsoft GUIDE)

[GUIDE](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction) (CDLA-Permissive-2.0) is Microsoft's set of 13.7 million Defender XDR alerts and evidence rows from 5,216 organisations over two weeks, each alert with its ATT&CK techniques and the customer's triage grade. Its values are anonymised, so it says nothing about what an attack looks like in the logs; it says whether Defender XDR alerts on a technique out of the box, how widely, and how often rightly. With Defender XDR as the SIEM, the technique view gets a **Defender XDR alerts** column (alerts, organisations, share graded true positive) and filter, and a technique's detail gives its detectors, grades, alert categories and evidence types. A technique Defender seldom alerts on, or mostly gets wrong, is where a custom detection earns its keep.

The summary ships with Archer (`archer/data/telemetry_guide.json`). To rebuild it, download the zip from Kaggle (a free account; the API token in `~/.kaggle/access_token` works too) and:

```
python -m archer.telemetry --guide ~/Downloads/microsoft-security-incident-prediction.zip
```

## Recording your own lab

No public set of attacks recorded by Defender for Endpoint, or by macOS's unified log, exists that Archer has found, so the gaps are filled by recording your own. `scripts/telemetry/record-atomics.ps1` runs Atomic Red Team tests on a **disposable** test machine (PowerShell 7, elevated) and saves each test's logs:

| Platform | Recorded |
|---|---|
| Windows | Security, System, PowerShell, Sysmon if installed, Task Scheduler, WMI, Defender and BITS events |
| Linux | auditd (`/var/log/audit`) and the systemd journal |
| macOS | Endpoint Security events (eslogger; the terminal needs Full Disk Access), the unified log, and launch agents, daemons and login hooks added, changed or removed |

```
sudo pwsh ./record-atomics.ps1 -Techniques T1053.003,T1543.001,T1059.004
```

If the machine is onboarded to Defender for Endpoint, fetch Defender's own rows for each test once they've arrived (usually within the hour), through Microsoft Graph's Advanced Hunting. It needs an app registration with `ThreatHunting.Read.All` (application, admin consented) in `ARCHER_MDE_TENANT_ID`, `ARCHER_MDE_CLIENT_ID` and `ARCHER_MDE_CLIENT_SECRET`:

```
python -m archer.telemetry --mde-export data/telemetry/lab/<run>
```

Copy the run's folder to `data/telemetry/lab/` and press **Update**. Your recordings appear as **Your lab**; they hold your hosts' and tenant's names, so `data/telemetry/` is gitignored and they never leave the machine.

## Filters

The filter card applies to whichever view is open below it, and shows only the filters that view uses.

| Filter | What it picks |
|---|---|
| SIEM | Google SecOps or Defender XDR: whose UDM event types or tables are shown, and in the group view, whose detections. Defaults to your first SIEM under Profile → SIEM platforms |
| Indicators | Free text. By technique: techniques whose recorded events hold a field value containing it (`…` gaps match their parts in order). By group: detections with an indicator containing it |
| Techniques | Search by ID or name |
| Groups | Groups you've hunted. By technique or data source: the techniques their detections are for |
| Data sources | The SIEM's tables or UDM event types |
| Logs | Recorded event types: Sysmon 1, Security 4688 |
| Collection | Which kinds of logging count: Native OS logs, Sysmon, EDR, osquery, Cloud and SaaS. For Google SecOps the default leaves out Sysmon, which is deployed far less than native logging. For Defender XDR it's kept: Sysmon's recordings stand in for the MDE sensor, which records the same process, file, network, registry and image-load activity without Sysmon installed |
| Defender XDR alerts | With Defender XDR as the SIEM: techniques it alerts on mostly rightly (half or more true positives), mostly not, or not at all (GUIDE) |
| Platforms | Windows, Linux, macOS, ESXi, Cloud and SaaS: only the logs from these platforms count, so Linux shows what Linux logging records of each technique |
| Seen | By group only: Seen, Not seen, No recordings, No indicators, or any noisy indicator |

## Telemetry by technique

Every recorded technique, 20 to a page, with its recordings per source, the **logs** at least half its recordings hold, and those logs' tables or UDM event types for the chosen SIEM: the logs you have to ingest to see it. Only the kinds of logging chosen under Collection count, so with Sysmon left out a technique shows what native logging alone records; one none of whose recordings hold the chosen logs is marked **No recording holds the chosen logs**, a gap for that kind of logging. Select a row for every event type its recordings hold and the recordings themselves. An event type marked **common** turns up in 40% or more of a source's recordings (Security 4688, Sysmon 1), so it's a hint that the event is lab background as much as the attack; it's never taken out.

## Telemetry by group

Your detections for the chosen SIEM, for the groups picked in Filters (your latest hunt when none are). Each detection's indicators are matched against the field values of its technique's recordings:

| Status | Meaning |
|---|---|
| Seen | A recorded event of the attack contains at least one indicator; the tag names the log and shows the source's logo |
| Not seen | The technique has recordings, but none contain the detection's indicators |
| No recordings | No source recorded the technique |
| No indicators | The detection has no literal indicators to look for |

An indicator is **noisy** when recordings of five or more other techniques contain it too: it matches the lab's ordinary activity as well as the attack.

Not seen isn't proof a detection is wrong: the recording may have used another tool or procedure. It's a cheap first look before testing against your own SIEM.

## Telemetry by data source

Each table or UDM event type for the chosen SIEM, with how many techniques it records (counting it for a technique when at least half the technique's recordings hold it), the recorded logs it comes from, and the techniques. A technique opens in the technique view.

## Limits

- Four labs, each with their own logging policy: an event type missing from the recordings may just not have been collected.
- Until you record your own, Defender XDR tables are mapped from the Windows, Linux and macOS events that record the same activity, and macOS has no unified log recordings.
- GUIDE's grades are its customers' triage, two weeks of it; a technique's sub-techniques without figures of their own show their parent's.
- The Windows event ID, auditd and cloud log mappings are in `archer/mappings/telemetry_map.json`; an event type not listed there shows without a table.
- Running Atomic Red Team in your own lab (a Linux container, then a Windows VM) is the next stage of [#22](https://github.com/cmdaltr/archer/issues/22).
