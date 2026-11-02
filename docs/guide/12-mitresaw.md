# MITRESaw

**Intel → MITRESaw** is the procedure data behind Shikari's threat briefings and detections. [MITRESaw](https://github.com/cmdaltr/MITRESaw) walks ATT&CK and, for every group, lists each technique it uses, how the technique reaches the group, and the indicators in the procedure text.

## The procedures

The header shows the ATT&CK version, and how many groups, techniques and procedures the current build holds, and when it was built.

| Control | What it does |
|---|---|
| Update | Collects only the groups the latest ATT&CK release changed |
| Full rebuild | Collects every group (about 30 minutes) |
| Stop | Stops a run. The next run carries on from the last finished batch of 20 groups |
| Download CSV / XLSX | The procedures as a spreadsheet; the XLSX is the evidence report |

One rebuild runs at a time, and each is checked against Shikari's own walk of ATT&CK.

The procedures table can be searched and filtered by group, technique, tactic and attribution:

| Attribution | Meaning |
|---|---|
| Group's own | ATT&CK documents the group using the technique directly |
| Through a campaign | One of the group's campaigns used it |
| Through software | Software the group (or its campaigns) uses implements it |

## OSINT repositories

The public detection-rule repositories Shikari searches while generating, with each one's status. They're cloned under `data/repos` on start-up and kept up to date. LOLBAS, LOLDrivers and LOLRMM are listed too: they're used with the LOL datasets option, and only for binaries, drivers and RMM tools a group is seen using.

## Indicator exclusions

Values MITRESaw should leave out of the indicators it extracts (for example a word that keeps turning up in procedure text but means nothing as an indicator), each with a reason. Matching ignores case. Exclusions apply to groups collected from then on; run a **Full rebuild** to apply them to every group.
