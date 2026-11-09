# Library

**Detections → Library** holds every detection and correlation you've saved with **Save to Library** on a [Results](06-results.md) page. It's your working set: search it, filter it, tag it and export it. Every section starts collapsed: click its title to open it, and it stays open next time.

## Finding things

| Control | What it does |
|---|---|
| Search detections | Matches names, techniques and query text |
| Groups | Show the detections from particular groups, reports or CVEs. With one chosen, **Results →** beside it opens the group's [Results](06-results.md). `/library?group=APT29` opens the Library with it chosen |
| Vendors | Google SecOps, Defender XDR, Splunk, Elastic |
| Tactics, Techniques | Narrow to parts of ATT&CK |
| Active Filters | What's applied; clear any of them here |

The Metrics card at the top totals what's in the Library: detections, correlations, techniques, tactics, and an estimate of analyst time saved. The time and cost figures are estimates from fixed rates.

## Detections and correlations

Cards are the same as on the Results page: badges, confidence, **View Query**, and OSINT details where the detection used them. The **ATT&CK Flow** section links each saved group, report or CVE to its attack flow on [Flows](09-flows.md). The **Anatomy** section links each saved threat group or CVE to its anatomy on [Detections → Anatomy](09-flows.md#anatomy).

## Acting on several at once

Tick detections or correlations (**Select All** / **Deselect All**), then:

| Action | What it does |
|---|---|
| Manage Tags | Add tags, edit them, or remove them all. Tags are free text, separated by commas |
| Export | JSON, CSV, XML, Word (full report with formatting) or PDF; choose one or several |
| Delete | Removes them from the Library. Can't be undone |

## Limits

The Library keeps what was saved: regenerating a run doesn't change Library copies until you save it again.
