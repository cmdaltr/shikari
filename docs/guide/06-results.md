# Results

Every hunt, report and company-profile run ends on a Results page: its detections, correlations, attack flow and a threat briefing. Later you can open it again from the [Library](07-library.md), [Flows](09-flows.md) or Profile → Timeline.

**Showing: Latest run / All runs** switches between the newest run of this group, report or CVE and every run of it combined.

## From top to bottom

| Section | What it shows |
|---|---|
| Threat briefing | Coverage (how many of the group's techniques you detect), the weakest stage of the attack, and the gaps to close first. Gaps are ranked by how early they come in the attack, then by how many correlations they're part of. Worked out without AI. **Write a summary with AI** adds an optional written summary using the Ask Archer provider |
| Outside your technology stack | For a technique, CVE or report hunt: what you asked for that your [technology stack](16-profile-and-settings.md#technology-stack) doesn't have. It was generated anyway |
| Techniques that produced nothing | Each technique the run couldn't build a detection for, and why (usually "no indicators in ATT&CK", or outside your technology stack) |
| Metrics | Counts of detections, correlations, techniques and tactics, with an estimate of analyst time saved. The time and cost figures are estimates from fixed rates, not measurements |
| Key | What each badge means (below) |
| Detections | One card per detection, grouped by SIEM |
| Correlations | Queries chained across techniques and tactics (below) |
| Attack flow | The group's techniques laid out by tactic, marked detected or not |
| IOC flow | For a report: its indicators in the order the intrusion used them |
| Validation | A four-step checklist to work through before deploying anything |

## Detection cards

Each card has the detection's name, its ATT&CK technique and tactics, severity, a confidence score, and its query. **View Query** opens it; **Copy Query** copies it.

| Badge | Meaning |
|---|---|
| Enhanced with OSINT | Indicators from public detection rules were merged into the query (OSINT Enhancement) |
| Compared with OSINT | Built from public rules because ATT&CK gave the technique no indicators. Review these first |
| Referenced | Shaped by a reference query from `bespoke/llm_references` |
| Mapping changed | Someone changed the technique or tactics it maps to, with a comment. Hover for ATT&CK's default; **Restore default** puts it back |

Confidence is High (75–100%), Medium (50–74%) or Low (below 50%). It's based on how specific the indicators are, whether the log source is commonly collected, and how narrowly the query targets the behaviour.

With LOL datasets on, a card also lists the LOLBAS, LOLDrivers or LOLRMM entries it drew on. With OSINT Enhancement on, it lists known false positives taken from public rules for the same technique.

## Correlations

A correlation joins several detections into one query that fires when the steps of an attack happen together on the same host or account within a time window. Each shows:

| Field | Meaning |
|---|---|
| Relevance | How strongly the techniques belong together in this group's attacks (only correlations above the threshold in Profile → Config are kept) |
| Time window | How close together the events must be |
| Tactics | The stages of the attack it spans |
| Tables / Event types / Indexes | The data sources it needs |

**Show Combined Query** shows the single chained query, and **Each technique's query** lists the queries it was built from. The chain at the top names each technique once.

A technique isn't correlated with itself: its `DeviceFileEvents` and `DeviceProcessEvents` queries on the same host aren't a chain of two techniques. Nor is a detection whose values are all bare built-in binaries (`wmic.exe` matches anything on its own) or all Windows API names (`OpenThread` never appears in a process command line).

The combined query is built from its detections' queries, so the indicators OSINT Enhancement merged into them are in it too. Under the queries, a correlation also lists what its detections' enrichment found: the false positives the public Elastic and Splunk rules for those techniques document, and the LOLBAS, LOLDrivers and LOLRMM entries behind added indicators, each tagged with its technique. **View OSINT Enhancement Details** shows the public rules they were compared with. The false positives are guidance for tuning, not exclusions: the public rules describe them in prose ("administrators may legitimately use runas"), so Archer doesn't turn them into query conditions.

Detection files are shared between groups and runs. When a later run rewrites one after the correlation was built, the card says so: the queries shown for each technique are current, the combined query isn't. **Regenerate** (or hunting the group again) rebuilds it.

Hunting a group again also takes the group off any detection its earlier runs made that this run didn't: a technique ATT&CK no longer attributes to it, a table a query no longer uses, or a query a check now refuses. A detection no other group uses is deleted; one edited by hand is kept. So the group's results, downloads and correlations hold only what its latest run produced, plus your edits.

Google SecOps rules already combine every follow-on technique into one rule, so the Results page only merges Defender XDR correlations that share a first technique.

## Precision checks

Before a detection is written, Archer removes conditions that parse but can't fire for the right reason, and keeps the rest of the query. A query left with no condition isn't written.

| Check | Example | What happens |
|---|---|---|
| A protocol alone | `Protocol has "DNS"` for File and Directory Discovery | Removed: it matches every DNS lookup |
| A string operator on a number | `RemotePort has "135"` | Removed; ports are compared as numbers (`RemotePort == 135`) |
| A documentation stand-in | `mstsc.exe /v:{hostname}`, `C:\Users\[Username]\AppData` | The text around it is kept and the stand-in matches anything: `has_all("mstsc.exe", "/v:")`, or `.*?` in YARA-L. Real text such as bcdedit's `{default}` is left alone |
| An ordinary word as a whole value | `has "copy"`, `has "dir"` | Removed from the list. Inside `has_all` it only narrows, so it stays |
| The same condition twice | | Removed |
| Only the event type | a YARA-L rule on every `PROCESS_LAUNCH` | Not written |
| Only a port | `RemotePort == 3389` | Kept, reported: it matches all traffic on that port |
| A table the technique can't reach | a Windows-only technique on `CloudAppEvents` | Reported |

The same checks run in the agents' `check_query` tool, reported with the static checks as `PREC-*`, and a query the [repair agent](15-agents-and-ask-archer.md) saves must pass their errors.

## Attack flow

Each column is a tactic in kill-chain order; each card is a technique, with the SIEMs that detect it or **No detection**. Arrows are correlations: the first technique seen before the second on the same host. Hover or select a card to trace its links.

You can rearrange the flow before saving or exporting it:

| To | Do |
|---|---|
| Move a technique to another tactic | Drag its card onto that tactic. A card moved to a tactic ATT&CK doesn't give it is marked **moved**; its detections keep their own mapping |
| Reorder techniques in a tactic | Drag the card up or down its column |
| Reorder the tactics | Drag a tactic's name along the others |
| Link two techniques | Drag the dot on a card's edge onto another card. Drawn links are purple and listed as **drawn** |
| Remove a link | Click it, or × beside it in the card's details |
| Place a card freely | Hold Option/Alt while dragging |
| Do it from the keyboard | Focus a card and press Alt with the arrow keys: along its tactic, or to the next tactic. On a tactic's name, Alt+arrows move the tactic |

The toolbar also filters by SIEM, hides undetected techniques, hides selected cards, and switches orientation and direction. **Undo** (⌘/Ctrl-Z) reverses any change and **Reset** restores the generated flow. Once the run is in your Library, edits are saved with it. **STIX** downloads the flow as shown, moved techniques and drawn links included, as an Attack Flow 2.x bundle for the CTID Attack Flow Builder.

## Buttons

| Button | What it does |
|---|---|
| Download All | A zip of the detections and correlations that are ticked (all of them unless you untick some): `detections/` holds each detection's YAML, `correlations/` each correlation's YAML and the group's index (`<group>.json`), and `attack_flows/` the flow. Files are named for the technique and the table or index (`At_DeviceProcessEvents.yaml`), or the query language where there's one file per SIEM: `UDM`, `KQL`, `SPL` or `ESQL` (`At_UDM.yaml`, `PowerShell_and_At_KQL.yaml`). The Validation checklist must be ticked first |
| Save to Library | Saves the run's detections and correlations to your [Library](07-library.md), and its attack flow to [Flows](09-flows.md) |
| Generate Report | A Word, PDF or HTML report of the run |
| Run Emulation | Coming soon. [Emulate](19-emulate.md) shows which logs record each technique and checks this run's indicators against recorded attacks |
| Regenerate | Runs it again and rewrites every detection, including ones edited by hand or by the repair agent |
| New Analysis | Back to the Home page |

Leaving the page before downloading or saving asks you to confirm.

## Before you deploy

Archer's queries are a starting point, not production rules. The Validation section's four steps: check the logic matches the technique, run the query in your SIEM to confirm the syntax, check the field and table names match your schema, and assess false positives. Run new queries in monitoring mode before alerting on them.
