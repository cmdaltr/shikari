# Results

Each group, report or CVE has one page in two views:

| View | When you see it | What it shows |
|---|---|---|
| **Interim results** | Where every hunt, report and company-profile run lands | What that run produced, to review and save to the Library. **All results for …** at the top opens the other view |
| **Results** | From the [Library](07-library.md) (choose a group, then **Results →**), [Flows](09-flows.md), Anatomy, [Campaigns](26-campaigns.md) or Profile → Timeline | Everything the group has across every run: briefing, detections, correlations, playbooks and attack flow |

When a group has had more than one run, **Showing: Interim: latest run / All results** switches between them. The address is `/results?group_name=<group>`; the interim view adds `&run=latest`.

The Library holds what you've saved; this page shows what the runs generated. Detections already in your Library are marked **In Library** (or *In Library (1/3)* when only some of a card's files are), and so are saved correlations. The top of Detections says how many are saved, with a link to the group in the Library.

## From top to bottom

Every section starts collapsed: click its title to open it, and it stays open next time. The **Key** button at the bottom right opens the key over whatever you're reading.

| Section | What it shows |
|---|---|
| Threat briefing | Coverage (how many of the group's techniques you detect), the weakest stage of the attack, and the gaps to close first. Gaps are ranked by how early they come in the attack, then by how many correlations they're part of. Worked out without AI. **Write a summary with AI** adds an optional written summary using the Ask Shikari provider |
| Anatomy workflow | How the attack runs: ways in, toolkit, actions, where it goes; each step marked detected or not (below) |
| Outside your technology stack | For a technique, CVE or report hunt: what you asked for that your [technology stack](16-profile-and-settings.md#technology-stack) doesn't have. It was generated anyway |
| Techniques that produced nothing | Each technique the run couldn't build a detection for, and why (usually "no indicators in ATT&CK", or outside your technology stack) |
| Metrics | Counts of detections, correlations, techniques and tactics, with an estimate of analyst time saved. The time and cost figures are estimates from fixed rates, not measurements |
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
| Tactics | Every tactic its techniques sit under (a technique can have several), in ATT&CK column order. A number is how many of its techniques share that tactic. Highlighted tactics are ones only one technique brings: what the correlation spans beyond a single technique. Hover a tactic to see its techniques |
| Tables / Event types / Indexes | The data sources it needs |

**Show Combined Query** shows the single chained query, and **Each technique's query** lists the queries it was built from. The chain at the top names each technique once.

Nor are two techniques from one procedure: a parent technique ATT&CK attributes to the group (Gallmaker's **T1027** Obfuscated Files or Information) has one detection holding its sub-techniques' indicators, and a sub-technique detection left over from an earlier run isn't paired with its parent or siblings unless ATT&CK attributes it to the group in its own right. A technique isn't correlated with itself: its `DeviceFileEvents` and `DeviceProcessEvents` queries on the same host aren't a chain of two techniques. Nor is a detection whose values are all bare built-in binaries (`wmic.exe` matches anything on its own) or all Windows API names (`OpenThread` never appears in a process command line).

The combined query is built from its detections' queries, so the indicators OSINT Enhancement merged into them are in it too. Under the queries, a correlation also lists what its detections' enrichment found: the false positives the public Elastic and Splunk rules for those techniques document, and the LOLBAS, LOLDrivers and LOLRMM entries behind added indicators, each tagged with its technique. **View OSINT Enhancement Details** shows the public rules they were compared with. The false positives are guidance for tuning, not exclusions: the public rules describe them in prose ("administrators may legitimately use runas"), so Shikari doesn't turn them into query conditions.

Detection files are shared between groups and runs. When a later run rewrites one after the correlation was built, the card says so: the queries shown for each technique are current, the combined query isn't. **Regenerate** (or hunting the group again) rebuilds it.

Hunting a group again also takes the group off any detection its earlier runs made that this run didn't: a technique ATT&CK no longer attributes to it, a table a query no longer uses, or a query a check now refuses. A detection no other group uses is deleted; one edited by hand is kept. So the group's results, downloads and correlations hold only what its latest run produced, plus your edits.

Most correlations are a pair of techniques. A **chain** joins three, shown with `+` between them: all three on the same host within the window, in any order, since ATT&CK tactics are goals rather than steps. Chains are built from pairs that scored (A with B, B with C), and each technique in one has to bring a tactic the other two don't, so a technique with four tactics, such as Cloud Accounts, can't make up the spread on its own. A technique is in at most three chains, and two techniques are together in only one, so the chains aren't the same pair with a different third technique. A chain that adds a tactic the others don't cover comes first, and each tactic the pairs reach is sure of three pairs above the threshold, so the pairs and chains reach further than the few multi-tactic techniques that score highest. Google SecOps and Defender XDR have chains; a chain fires far less often than a pair, so treat one as a high-confidence lead next to its pairs rather than a replacement for them.

## Cross-vendor playbooks

A correlation joins detections within one SIEM, because across SIEMs there's no single query — YARA-L, KQL, SPL and ES\|QL don't splice. **Cross-vendor playbooks** take the chains that span two or more of your SIEMs and lay them out as a sequence instead: each stage with the per-SIEM query that detects it, the entity fields to join the stages on (host, user, IP, process hash — named for each SIEM), and the time window. You run each stage where that telemetry actually lives and join on the keys, in a SOAR or by hand — it's a playbook, not a query. Built from the same chains, so no AI and nothing new to tune.

## Precision checks

Before a detection is written, Shikari removes conditions that parse but can't fire for the right reason, and keeps the rest of the query. A query left with no condition isn't written.

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

The same checks run in the agents' `check_query` tool, reported with the static checks as `PREC-*`, and a query the [repair agent](15-agents-and-ask-shikari.md) saves must pass their errors.

## Quality and false-positive risk

Each card carries two badges, worked out without AI (`shikari/validation/quality.py`). Hover either for its reasons.

**Quality A–F** scores the detection out of 100:

| Factor | Points | What earns them |
|---|---|---|
| Validity | 25 | The static checks pass: it parses, uses known tables and fields, has no placeholders |
| Precision | 25 | The precision checks above pass (KQL, UDM and YARA-L; SPL and ES\|QL get 20) |
| Specificity | 20 | Several values, command-line arguments rather than bare names, paths or hashes |
| Context | 15 | Description, severity, tactics, technique and data connector are all there |
| Evidence | 15 | Indicators traced to the procedure, plus reference queries or OSINT |

A is 85 and up, B 70, C 55, D 40, F below that.

**FP risk: low, medium or high** predicts how much ordinary activity it will match before you deploy it. The risk goes up for:

- bare built-in binaries, generic words, a port or protocol on its own;
- a high-volume source (process launches, network events) matched on one value or none;
- false positives the community's Elastic and Splunk rules document for the same technique and tools. Those notes are listed in the tooltip for triage.

The risk goes down for hash matches and for exclusions of known-good activity.

**Cost: medium or high** appears when the query is expensive to run, read from the query itself (`shikari/validation/cost.py`). The tooltip says why and how to fix it. Causes include:

- no time bound;
- KQL `contains`, or SPL and ES|QL leading wildcards, which scan every value;
- a regex where a term would do, or one unanchored at both ends;
- joins, subsearches and transactions;
- every table or index;
- lower-casing a column to compare it;
- filtering after an aggregation.

Scheduled detections run every few minutes, so a high one is worth fixing before deployment.

When several queries share a card, it shows the weakest: the lowest grade, the highest risk and the highest cost. The Library shows the same badges. `/api/results/<run>` returns them as `quality`, `fp_risk` and `cost`. [Detections as code](22-detections-as-code.md#check-detections-in-ci) gates pull requests on them. `python -m shikari.validation.quality <files>` prints them for detection files. Hit counts ([#16](https://github.com/cmdaltr/shikari/issues/16)) will measure false positives against the SIEM itself.

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

## Anatomy workflow

How the attack runs, in the style of the DFIR Report's workflow diagrams, built without AI. It shows no ATT&CK technique IDs or tactics: the diagram is the operation, the detection cards carry the mapping.

For a group, from ATT&CK's procedures, left to right:

| Node | What it holds |
|---|---|
| The group | Its ATT&CK ID and how many campaigns |
| **Exploit**, **Phishing**, **Credentials** | Its ways in, side by side: the CVEs it exploits; the services it phishes through; the accounts and remote access it signs in with (Azure, AWS, VPN) |
| **Toolkit** | Its tools, grouped: frameworks, stealers, web shells, RATs, ransomware, remote access, exfiltration tools, built-in tools |
| **Actions** | What it does once in, in plain words: steals logins, moves across the network, gains admin rights, keeps access, hides its tracks, looks around, gathers data, takes data out, encrypts or destroys, extorts. The ones the reporting describes most come first; it isn't an order. Who does each is in the click panel |
| **Cloud**, **Messaging**, **Code and storage** | Where it goes, side by side: cloud tenants, hosting and tunnels; messaging apps; code and paste sites and cloud storage. Each link says what it does there (uploads to, beacons to, collects from) |

A service it gets in through isn't repeated where it goes.

For a CVE, from its research, one line per CVE: the attacker (or the ATT&CK group known to exploit it) → the public or named exploit → the CVE with its product and CVSS score → the worker process the code runs in → the shell it starts → the infrastructure the advisories name.

A CVE chain longer than six nodes snakes back along the next line. A step is teal when this run detects most of what's behind it, red when it mostly doesn't; for a CVE, the exploit step counts the exploit request detection, the worker and shell steps the runtime shell detection, and the infrastructure step the IOC sweep. Select a node for everything in it and what the reporting says, or a step for how much of it is detected.

Once the run is in your Library, its anatomy is also on [Detections → Anatomy](09-flows.md#anatomy).

## Buttons

| Button | What it does |
|---|---|
| Download All | A zip of the detections and correlations that are ticked (all of them unless you untick some): `detections/` holds each detection's YAML, `correlations/` each correlation's YAML and the group's index (`<group>.json`), and `attack_flows/` the flow. Files are named for the technique and the table or index (`At_DeviceProcessEvents.yaml`), or the query language where there's one file per SIEM: `UDM`, `KQL`, `SPL` or `ESQL` (`At_UDM.yaml`, `PowerShell_and_At_KQL.yaml`, and a chain's three names: `CloudAccounts_and_ModifyRegistry_and_PowerShell_UDM.yaml`). The Validation checklist must be ticked first |
| Save to Library | Saves the run's detections and correlations to your [Library](07-library.md), and its attack flow to [Flows](09-flows.md) |
| Generate Report | A Word, PDF or HTML report of the run |
| Run Emulation | Opens Build → Emulate → Lab with the CALDERA planner filled in for this group or CVE ([CALDERA operations](25-caldera.md)): plan, run on disposable agents, then check these detections against what ran. For a report or technique run it opens the Lab without a target |
| Regenerate | Runs it again and rewrites every detection, including ones edited by hand or by the repair agent |
| New Analysis | Back to the Home page |

Leaving the page before downloading or saving asks you to confirm.

## Before you deploy

Shikari's queries are a starting point, not production rules. The Validation section's four steps: check the logic matches the technique, run the query in your SIEM to confirm the syntax, check the field and table names match your schema, and assess false positives. Run new queries in monitoring mode before alerting on them.
