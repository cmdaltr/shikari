# CALDERA operations

Run a [CALDERA](https://github.com/mitre/caldera) operation from **Emulate → Lab** (in the web app and the desktop app) or the `lab/caldera` [console module](17-console-api-mcp.md), pull back what each step ran, and check your saved detections and correlations against it ([#30](https://github.com/cmdaltr/shikari/issues/30)). Shikari drives the CALDERA server you run in your lab. It never ships an agent or a C2 of its own.

## Why CALDERA as well as Atomic Red Team

[Recording a lab](20-recording-a-lab.md) runs Atomic Red Team tests one technique at a time, each with its default inputs, from a local PowerShell session. That's the right tool for validating a single detection. It can't test two things that correlations depend on:

| Need | Atomic Red Team in Shikari | CALDERA |
|---|---|---|
| Fact chaining: one step's output feeds the next step's arguments | No. Each test runs standalone with default inputs | Yes. The `atomic` planner runs abilities in order, and the facts each step collects fill later steps' `#{fact}` placeholders |
| Implant behaviour: a beaconing agent taking tasks over a C2 channel | No. Tests run in a local shell | Yes. The sandcat agent is a real implant, so detections keyed on its process lineage and beaconing are exercised |
| Running on more than one host in one operation | One machine per run | An agent group spans hosts |

Building either into Shikari would make it an implant framework, so CALDERA does that part and Shikari does the detection side. Atomic Red Team stays the per-technique path. Shikari leaves out CALDERA's `atomic` plugin, its import of Atomic Red Team, when choosing an ability, unless no other ability runs the technique.

Pushing detections into CALDERA was dropped from #30: CALDERA has nowhere to take a detection.

## Connecting

### Provision it in one go (local macOS)

On a macOS host you run Shikari on yourself, the **Provision** button on the CALDERA card stands the whole lab up for you: it installs OrbStack, builds and runs a disposable CALDERA server, enrols agents, and saves the server and key to your profile — the in-app equivalent of `scripts/telemetry/caldera-lab.sh`. A step that needs you (your password for Homebrew, OrbStack's first launch) shows exactly what to do and carries on by itself once it's done, re-checking every 10 seconds. Nothing detonates during provisioning.

It's deliberately narrow — an **admin** account, a **macOS** host, and the opt-in `SHIKARI_ALLOW_LAB_PROVISION=1` in the environment — so it can never fire on a shared server, where the host isn't your own machine. The **local desktop app** sets that flag for you (it runs its own server on your machine); running Shikari any other way, set it yourself, e.g. in `.envrc` or before `shikari start`. Without all three gates you get the manual **Deploy** guide instead, and the server-side options below.

Once a lab is up, the button turns green and reads **Re-provision** (run it again), with **De-provision** beside it to tear the lab down — stop the server, delete the agents, and remove CALDERA from your profile.

### Set it by hand

The usual way is in the app: **Profile → API Keys → Emulation Tools**. Set the CALDERA server URL and your red API key there — the key is encrypted at rest (Fernet), like your SIEM and AI keys, and is scoped to your own account. The **Verify the server's TLS certificate** toggle is on by default; turn it off only for a lab server with a self-signed certificate.

Two server-side alternatives, for a shared instance or an unattended run, take precedence over the per-user setting:

```yaml
# bespoke/config.yaml (gitignored) — an instance-wide default
caldera:
  url: "https://caldera.lab:8888"
  api_key: "<red API key from CALDERA's local.yml>"
  verify_tls: true
```

`CALDERA_URL` and `CALDERA_API_KEY` in the environment override both the per-user setting and the file (handy for a throwaway run). Wherever it comes from, the key goes only in CALDERA's `KEY` header: it is never logged, returned by Shikari's API or written to a manifest. Using it needs the Operational analyst role, like the rest of Lab.

Once connected, the CALDERA card on **Emulate → Lab** shows the **agent topology**: the server (with its host's OS icon and hostname) and every agent beneath it, each labelled by paw with its OS icon, the environment it runs in (Docker, Tart, UTM, OrbStack) and its group. Click an agent to act on it — start, stop or delete it when Shikari manages its machine, or forget it either way. An agent enrolled outside Shikari is drawn dashed and greyed, so it's clear which machines Shikari can drive.

## Adding agents

You don't have to leave Shikari to add an agent. **+ Add agent** on the CALDERA card either provisions a fresh disposable machine and enrols it, or enrols one you already have:

- **Provision** — pick the OS (Linux or macOS; for Linux a full **Tart VM** or a light **Docker container**) and Shikari creates the managed machine, boots it, and runs a sandcat agent in it, as one background job.
- **Enrol** — run a sandcat agent on any running machine Shikari already manages, a UTM Windows VM you've built included.

The machine pulls the architecture-correct agent itself and runs it detached (systemd on Linux, launchd on macOS, a hidden process on Windows), so nothing streams over the hypervisor's guest agent — the amd64 default would fail on an arm64 Tart VM, so the right `architecture` is requested. macOS needs a base image with the Tart guest agent (the cirruslabs images ship it).

Names follow a convention so the lab stays legible: an `shi-` prefix always, a `cal-` marker when the machine is provisioned for CALDERA, then an OS+version tag — `shi-cal-ubu24`, `shi-cal-rky10`, `shi-cal-mac15`, `shi-win11`, with a `-N` suffix on a clash. The tag is the distro+version actually provisioned (`ubu24` tracks cirruslabs' 24.04 base — it becomes `ubu26` once a 26.04 base ships; `rky10` is Rocky Linux 10; `mac15` is Sequoia; `win11` is Windows 11). Linux offers Ubuntu (Tart VM or Docker container) and Rocky (Docker container only — cirruslabs ships no Rocky Tart base). **Your machines** sorts Windows, then macOS, then Linux, hides Rivendell's own VMs (`rivendell-*`), and marks each as a CALDERA **agent** or **not enrolled**.

The same from the command line:

```
shikari caldera provision linux              # a Tart Ubuntu VM, enrolled
shikari caldera provision linux --engine docker
shikari caldera provision linux --distro rocky   # a Rocky 10 Docker container, enrolled
shikari caldera provision macos              # needs a cirruslabs base
shikari caldera enrol tart shi-cal-ubu24    # enrol a machine Shikari manages
shikari caldera list                         # managed machines, and which are agents
```

The web, the desktop app (the same UI) and the CLI share one backend source for the naming and group convention, so they can't drift. For a throwaway lab from scratch, `scripts/telemetry/caldera-lab.sh` still does the whole bring-up end to end (`up` for the server and OrbStack Linux agents, `win <vm>` for a UTM Windows VM, `mac <vm>` for a Tart macOS VM), or deploy sandcat from CALDERA's own UI.

## Planning and running

**Plan an operation** takes ATT&CK techniques, a threat group or a CVE (resolved as [Emulate's planner](19-emulate.md) resolves them) and an agent group. Planning reads CALDERA's abilities and agents and changes nothing on CALDERA. For each technique it picks one ability whose executor an agent in the group can run. It prefers an exact technique match, then a sub-technique, then CALDERA's own plugins over its Atomic import. The plan then lists:

| Line | Means |
|---|---|
| Create adversary … | The abilities, in order |
| Start operation … | The group, its agents, planner `atomic`, obfuscator `plain-text`, closing when done |
| `T1057 Process discovery on windows/psh: …` | Each step's command template. `#{fact}` placeholders are filled by CALDERA at run time, so the exact command is only known afterwards |
| No runnable ability for … | Gaps: techniques no ability runs on these agents |

**Run operation** needs the plan and the confirmation that the agents are disposable. It creates the adversary, starts the operation, waits for it to finish and collects it, as one background job with the Lab's log.

**Collect an existing operation** pulls one started in CALDERA itself, by its id.

## What's collected

`data/telemetry/caldera/<operation>/manifest.json` holds, for every link: technique, ability, the command as it actually ran, host and paw, platform and executor, status, decide/collect/finish times, and the decoded output (the first 20,000 characters). It stays on this machine: `data/telemetry/` is gitignored.

Each operation also becomes a recording source, **CALDERA**, one dataset per technique, whose `CommandLine` values are the commands that ran. That's how they show on the Recorded telemetry views beside the other recordings.

### Capturing the endpoint's logs

A command line overstates a detection: the query runs on what the endpoint logged. Under **Capture the endpoint's logs afterwards** choose how, and once collected Shikari runs `scripts/telemetry/capture-window.ps1` on the agent's host. The script runs nothing but log readers. It reads each step's window (decide minus 5 s, to finish plus 20 s for clock skew and late events) back from the same logs the [lab recorder](20-recording-a-lab.md) uses, and imports them as a **Your lab** run named `caldera-<operation>`.

Two ways to reach the host:

- **Via the agent, over CALDERA** (any OS, no machine to set up): the capture runs as a one-ability CALDERA operation on the agent that just ran, which returns the whole run back in its own link result. Nothing but the sandcat agent and the REST API is needed — no host Lab manages, no hypervisor access, and nothing installed on the host: Windows reads its logs with the built-in PowerShell, Linux and macOS with the native shell. This is the zero-touch path and works wherever the agent runs.
- **Via a lab machine Lab manages** (the hypervisor-exec path): pick the machine the agent runs on, and Lab pushes and runs the script over its engine (Docker, tart or UTM). Use this when you'd rather not run an extra CALDERA operation.

| OS | Captured after the fact |
|---|---|
| Windows | Security, System, PowerShell, Sysmon, Task Scheduler, WMI, Defender, BITS (`events.xml`) |
| Linux | auditd by record epoch (`audit.log`), the journal (`journal.log`) |
| macOS | The unified log (`unified.ndjson`). Endpoint Security and the launch-item diff only exist live, so they aren't captured |

Either way it runs only log readers. Over the agent, nothing is installed: Windows uses the built-in Windows PowerShell (5.1) and Linux/macOS the native shell (`journalctl`/auditd, `log show`). The lab-machine path runs `capture-window.ps1`, so a non-Windows managed machine needs PowerShell 7 (Lab's **Set up**). Capturing via the agent handles every host the operation ran on in one pass — a separate **Your lab** run per host; the lab-machine path captures one managed host at a time.

For how the capture hooks into Shikari step by step and exactly where each operation's results land, see [CALDERA endpoint-log capture on a Windows host](../features/CALDERA_WINDOWS_CAPTURE.md).

## The check

**Check** on a collected operation is static: no AI and no SIEM. It works at two levels.

| Level | Asks | Status |
|---|---|---|
| Technique | Do any of the saved detections' `indicators` for that technique (or its parent or sub-techniques) appear in what the step left: the captured logs when there are any, and the command it ran | **matched**, **missed**, or **no detections**, plus the steps no detection matched |
| Correlation | For each saved correlation in `data/correlate/` whose techniques all ran: did every part's detection match a step, on one host, within the correlation's window (`within 1h` in its query)? | **fired**, **half-fired** (names the parts that didn't match), **missed** |

The order the parts matched in is shown, not required: ATT&CK tactics aren't a sequence. Indicators appearing means a detection would plausibly have fired. The query's other conditions aren't evaluated, so a hit count against your real SIEM is still the final word.

## Limits

- One ability per technique per operation. Run another operation for the alternatives.
- The CALDERA API's planner and fact-source lookups go by the shipped names, `atomic` and `basic`.
