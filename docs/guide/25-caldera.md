# CALDERA operations

Run a [CALDERA](https://github.com/mitre/caldera) operation from **Emulate → Lab**, pull back what each step ran, and check your saved detections and correlations against it ([#30](https://github.com/cmdaltr/archer/issues/30)). Archer drives the CALDERA server you run in your lab. It never ships an agent or a C2 of its own.

## Why CALDERA as well as Atomic Red Team

[Recording a lab](20-recording-a-lab.md) runs Atomic Red Team tests one technique at a time, each with its default inputs, from a local PowerShell session. That's the right tool for validating a single detection. It can't test two things that correlations depend on:

| Need | Atomic Red Team in Archer | CALDERA |
|---|---|---|
| Fact chaining: one step's output feeds the next step's arguments | No. Each test runs standalone with default inputs | Yes. The `atomic` planner runs abilities in order, and the facts each step collects fill later steps' `#{fact}` placeholders |
| Implant behaviour: a beaconing agent taking tasks over a C2 channel | No. Tests run in a local shell | Yes. The sandcat agent is a real implant, so detections keyed on its process lineage and beaconing are exercised |
| Running on more than one host in one operation | One machine per run | An agent group spans hosts |

Building either into Archer would make it an implant framework, so CALDERA does that part and Archer does the detection side. Atomic Red Team stays the per-technique path. Archer leaves out CALDERA's `atomic` plugin, its import of Atomic Red Team, when choosing an ability, unless no other ability runs the technique.

Pushing detections into CALDERA was dropped from #30: CALDERA has nowhere to take a detection.

## Connecting

Put the connection in `bespoke/config.yaml`, which is gitignored:

```yaml
caldera:
  url: "https://caldera.lab:8888"
  api_key: "<red API key from CALDERA's local.yml>"
  verify_tls: true
```

`CALDERA_URL` and `CALDERA_API_KEY` in the environment override the file. The key goes only in CALDERA's `KEY` header: it is never logged, returned by Archer's API or written to a manifest. Using it needs the Operational analyst role, like the rest of Lab.

Deploy sandcat agents on your lab machines from CALDERA itself, and put them in a group. The CALDERA card on **Emulate → Lab** shows the server, its groups and their platforms.

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

A command line overstates a detection: the query runs on what the endpoint logged. Choose the lab machine the agent runs on under **Capture logs afterwards**, and once collected Archer runs `scripts/telemetry/capture-window.ps1` in that machine. The script runs nothing but log readers. It reads each step's window (decide minus 5 s, to finish plus 20 s for clock skew and late events) back from the same logs the [lab recorder](20-recording-a-lab.md) uses, and imports them as a **Your lab** run named `caldera-<operation>`.

| OS | Captured after the fact |
|---|---|
| Windows | Security, System, PowerShell, Sysmon, Task Scheduler, WMI, Defender, BITS (`events.xml`) |
| Linux | auditd by record epoch (`audit.log`), the journal (`journal.log`) |
| macOS | The unified log (`unified.ndjson`). Endpoint Security and the launch-item diff only exist live, so they aren't captured |

Capturing needs the machine to be one Lab manages. It runs only log readers: on Windows under the built-in Windows PowerShell (5.1), on Linux and macOS under PowerShell 7 (Lab's **Set up**). An operation that ran on several hosts is captured one host at a time.

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
