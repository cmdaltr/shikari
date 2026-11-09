# Campaigns

**Intel → Campaigns** (`/campaigns`) profiles an emerging campaign that ATT&CK doesn't describe yet, from the reports about it. Give it the campaign's name and the URLs of a few reports; it reads each one, merges what they say, and saves the result as a campaign you can report on and generate detections for. It replaces ETHAN's campaign research.

## Researching a campaign

| Control | What it does |
|---|---|
| Campaign name | What the campaign is called. Its detections are saved in the library as `Campaign_<name>` |
| Report URLs | One per line. Up to 10 sources are read |
| Also search | Adds the reports Shikari's source archive and the news searches find for the name (the same search as the Feed) |
| AI analyst profile | Optional, off by default. A model from your profile reads the sources and writes a profile |

Each source goes through the same analyser as **Analyse → URL**: ATT&CK technique IDs and the commands that imply them, the indicators, the ATT&CK groups it names, and its publication date from the page's metadata. The sources are then merged:

| Part | How it's built |
|---|---|
| Techniques | Every technique any source describes, ordered by how many sources describe it, with whether the library already has a detection for it (from any group) |
| Groups | The ATT&CK groups the sources name, with how many name each. The campaign isn't attributed beyond that |
| Timeline | The sources by publication date; the earliest is the campaign's *first reported* date |
| Indicators | IPs, domains and hashes, each triaged (below), plus the commands, registry keys, files and software the sources give |

## Indicator triage

An indicator is triaged by the age of the newest source that cites it, on the day of the research.

| Triage | Meaning |
|---|---|
| Active | An IP or domain from a source no more than 90 days old, or a hash from one no more than 365 days old |
| Likely burned | Older than that. Search historical logs for it; don't expect it in new activity |
| Infrastructure pattern | A CIDR range, a wildcard domain or an ASN: it describes infrastructure, not one host |
| Age unknown | No source citing it gives a publication date. Treated as active |

## What you can do with a campaign

| Button | What it does |
|---|---|
| Report (Word), Report (PDF) | The campaign intelligence report under the TLP label you choose: executive summary, sources, attribution, timeline, techniques with a coverage matrix, triaged indicators, detections, appendices |
| Generate detections | Builds detections for every technique and the indicators not triaged as burned (tick *include burned indicators* for all of them), through the same pipeline as Analyse, saved under the campaign's name |
| Master hunt query (.kql) | Once the detections exist: one Defender XDR advanced hunting query over them, ranking devices by how many of the campaign's techniques they show ([SIEM export packs](../features/SIEM_EXPORT_PACKS.md#master-hunt-query-defender-xdr)) |

## AI

Without AI, everything above is extracted from the sources. With an AI provider chosen, the profile adds a summary, the actor and how confident the sources are, motivation, the events the sources describe, tooling and victims. The prompt tells the model to use only the sources. Everything it writes is marked **†** on the page and in the report, and the report ends with the AI disclaimer. If the model's answer can't be parsed, the campaign is saved without it.

## Data and limits

Campaigns are saved as JSON in `data/campaigns/`. A source behind a login, a paywall or bot protection can't be read; it is listed with the reason. The triage windows are rules of thumb, not evidence: an IP from a year-old report can still be live. Techniques are only as good as the sources: a report that cites no technique IDs and gives no commands contributes indicators only.
