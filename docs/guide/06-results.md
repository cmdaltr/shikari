# Results

Every hunt, report and company-profile run ends on a Results page: its detections, correlations, attack flow and a threat briefing. Later you can open it again from the [Library](07-library.md), [Flows](09-flows.md) or Profile → Timeline.

**Showing: Latest run / All runs** switches between the newest run of this group, report or CVE and every run of it combined.

## From top to bottom

| Section | What it shows |
|---|---|
| Threat briefing | Coverage (how many of the group's techniques you detect), the weakest stage of the attack, and the gaps to close first. Gaps are ranked by how early they come in the attack, then by how many correlations they're part of. Worked out without AI. **Write a summary with AI** adds an optional written summary using the Ask Archer provider |
| Techniques that produced nothing | Each technique the run couldn't build a detection for, and why (usually "no indicators in ATT&CK") |
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

**Show Combined Query** shows the single chained query.

## Buttons

| Button | What it does |
|---|---|
| Download All | A zip of every detection (YAML) and correlation |
| Save to Library | Saves the run's detections and correlations to your [Library](07-library.md), and its attack flow to [Flows](09-flows.md) |
| Generate Report | A Word, PDF or HTML report of the run |
| Run Emulation | Not available yet |
| Regenerate | Runs it again and rewrites every detection, including ones edited by hand or by the repair agent |
| New Analysis | Back to the Home page |

Leaving the page before downloading or saving asks you to confirm.

## Before you deploy

Archer's queries are a starting point, not production rules. The Validation section's four steps: check the logic matches the technique, run the query in your SIEM to confirm the syntax, check the field and table names match your schema, and assess false positives. Run new queries in monitoring mode before alerting on them.
