# Threat library and assessments

Archer already knows which groups matter to you (Company profile), what they do (MITRESaw), what you detect (Library, Coverage) and which logs record each technique (Emulate). What it didn't have is the record of **testing** — which procedures you ran, whether they were blocked, logged or alerted, and what changed afterwards. The threat library and assessments add that, VECTR-style. No AI is involved, and nothing is executed here: running atomics in a lab is stages 2 and 3 of the lab recording work.

**Build → Assessments** holds both on one page: a **Threat library** tab for the test cases, and a **Campaigns** tab for the assessments that run them.

## Threat library

The Threat library tab turns ranked groups into test cases. Pick a company profile — its recommended groups — or name a single group. Archer reads MITRESaw's procedures for those groups and makes one test case per procedure: the technique, the procedure text, the indicators, and the matching Atomic Red Team test where a local atomics checkout is configured (`ATOMIC_REDTEAM_PATH`).

Test cases sort by **prevalence** — how many of the chosen groups use the technique — so the ones the most relevant adversaries rely on come first. Each row shows how many of your detections already cover the technique, linking to them. The library is per user; building again adds only what's new.

## Campaigns

The Campaigns tab is where assessments live: a name, a target, an operator and a run date, grouping test cases. Add the library's cases (optionally filtered to one tactic), then record two outcomes per technique:

- **Red** — what the attack did: not run, executed, failed, or blocked.
- **Blue** — what the defence saw: not assessed, not logged, logged, alerted, or prevented.

Record the detection that fired and any notes alongside. Each row links to the logs the technique needs (Emulate) and the detections you have for it (Library); a **logged, no alert** outcome offers a detection hunt for that technique, since that's exactly the gap worth closing.

## Progress and export

Outcomes export two ways:

- **CSV** — a flat row per technique with both outcomes, the detection and notes.
- **ATT&CK Navigator layer** — the matrix scored by blue outcome, shading from "not logged" through "logged" and "alerted" to "prevented".

## Notes

- Storage is the existing SQLite database, per user. No organisation data goes into git.
- VECTR JSON import/export is a later addition; for now test cases are built from MITRESaw, not imported.
