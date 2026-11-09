# Threat library and assessments

Shikari already knows which groups matter to you (Company profile), what they do (MITRESaw), what you detect (Library, Coverage) and which logs record each technique (Emulate). What it didn't have is the record of **testing** — which procedures you ran, whether they were blocked, logged or alerted, and what changed afterwards. The threat library and assessments add that, VECTR-style. No AI is involved, and nothing is executed here: running atomics in a lab is stages 2 and 3 of the lab recording work.

**Build → Assessments** holds both on one page: a **Threat library** tab for the test cases, and a **Campaigns** tab for the assessments that run them.

## Threat library

The Threat library tab turns ranked groups into test cases. Pick a company profile — its recommended groups — or name a single group. Shikari reads MITRESaw's procedures for those groups and makes one test case per procedure: the technique, the procedure text, the indicators, and the matching Atomic Red Team test where a local atomics checkout is configured (`ATOMIC_REDTEAM_PATH`).

Test cases sort by **prevalence** — how many of the chosen groups use the technique — so the ones the most relevant adversaries rely on come first. Each row shows how many of your detections already cover the technique, linking to them. The library is per user; building again adds only what's new.

## Campaigns

The Campaigns tab is where assessments live: a name, a target, an operator and a run date, grouping test cases. Add the library's cases (optionally filtered to one tactic), then record two outcomes per technique:

- **Red** — what the attack did: not run, executed, failed, or blocked.
- **Blue** — what the defence saw: not assessed, not logged, logged, alerted, or prevented.

Record the detection that fired and any notes alongside. Each row links to the logs the technique needs (Emulate) and the detections you have for it (Library); a **logged, no alert** outcome offers a detection hunt for that technique, since that's exactly the gap worth closing.

## Progress and export

Outcomes export three ways:

- **CSV** — a flat row per technique with both outcomes, the detection and notes.
- **ATT&CK Navigator layer** — the matrix scored by blue outcome, shading from "not logged" through "logged" and "alerted" to "prevented".
- **Report (Word or PDF)** — the document to hand the client or the SOC at the end of the campaign (#42).

## The assessment report

**Report (Word)** and **Report (PDF)** build the same report: a title page, then Table of Contents, Executive Summary, Scope, Assumptions, Findings, Risks, Recommendations, Conclusions and Appendices, each page after the title carrying the Shikari header and a numbered footer. It's set in Calibri in the logo's and the bateleur's colours, with charts of the outcomes, the techniques as an ATT&CK matrix, a risk heat map and a card per finding. Word fills in the contents' page numbers when it opens the file (say yes to updating fields).

Everything in it is computed from the recorded outcomes and the detection library; no AI writes it. Two optional paragraphs are yours: open **Report text** above the table and type an executive summary or a conclusion, and they lead those sections.

- **Risk** is likelihood × impact, each 1–3: likelihood from the red outcome (executed 3, failed 2, blocked 1), impact from the blue (not logged 3, logged 2, alerted or prevented 1). Critical is 9, High 6, Medium 3–4, Low 1–2. Tests not run or not assessed aren't rated.
- **Gaps** are the techniques logged but not alerted on, or not logged at all, each with the library's detections for it, or none. A logged gap with a library detection is ready to close by deploying it; a technique that wasn't logged needs its logging turned on first.
- **AI-assisted content** is marked †: a library detection written with an AI model (an LLM-written bespoke detection), and every section that cites one. The standard disclaimer for it closes the report.
- **Lab runs** whose techniques overlap the assessment's are listed in an appendix, with the export-pack command that replays them into a SIEM.

The PDF uses Calibri where the machine has it (Office on macOS or Windows) or Carlito, its metric twin on Linux (`fonts-crosextra-carlito`); without either it falls back to Helvetica. The Word file always names Calibri.

## Export for MACAT

**Export for MACAT** (Threat library tab) downloads your test cases as a MACATable library TOML — the format [MACAT](https://www.macat.io) imports. Each test case becomes a `[[lib_procedures]]` entry tagged with the technique, tactic and attributing group, with the matching Atomic Red Team GUID noted so MACAT pairs it with the ART procedure it already syncs. Shikari's test cases are intelligence, not runnable commands, so the export carries procedure metadata, not executable steps — MACAT runs the Atomic and pushes results to VECTR. It's a one-way, offline file; Shikari takes no dependency on MACAT.

## Notes

- Storage is the existing SQLite database, per user. No organisation data goes into git.
- VECTR JSON import/export is a later addition; for now test cases are built from MITRESaw, not imported.
