# Coverage

**Detections → Coverage** shows which ATT&CK techniques you have queries for. Every section starts collapsed: click its title to open it, and it stays open next time. It has two layers, switched with the buttons above the matrix:

| Layer | What it counts |
|---|---|
| Reference queries | Your production-tested queries in `bespoke/llm_references/`. Archer uses them as templates and examples when it generates, so this is the coverage it has to learn from |
| My detections | Detections you've generated and saved, by the ATT&CK mapping in force. A mapping changed by hand shows with a dashed amber outline |

## The page

| Section | What it shows |
|---|---|
| Totals | Total queries, techniques covered, and queries per SIEM |
| Filters | Number of queries, vendor, tactic, platform, and a search box. A collapsed Filters card shows "N active" when filters still apply |
| Coverage by Tactic | One card per tactic; open one to see its covered techniques, coloured by how many queries each has |
| ATT&CK Matrix | Every Enterprise technique under each tactic. A technique counts its sub-techniques' queries too. **Expand all sub-techniques** and **Covered only** change the view |
| Coverage by Technique / Platform | Compact cards: by technique (ID, name, SIEMs, platforms) or by platform (SIEMs, technique and query counts, the techniques). **Export** downloads the cards as CSV, with any filters applied |
| Coverage Gaps | Techniques with queries for one SIEM but not another |
| Cloud coverage | ATT&CK's cloud techniques by provider: AWS, Azure, GCP, and Identity & SaaS. Each cell lists the SIEMs with a saved detection over that provider's logs, **gap** where there's none, or n/a where the technique doesn't apply. **Gaps only** keeps the rows with a gap |

## Cloud coverage

Cloud coverage reads your saved detections, not the reference queries, and ignores the layer buttons. A technique applies to AWS, Azure and GCP when ATT&CK lists IaaS among its platforms, and to Identity & SaaS when it lists Identity Provider, SaaS or Office Suite. A detection counts for a provider when it reads that provider's logs:

| Provider | What counts |
|---|---|
| AWS | CloudTrail: the `AWS_CLOUDTRAIL` log type, `logs-aws.*`, the AWS index |
| Azure | The Activity Log: `AzureActivity`, `logs-azure.activitylogs-*`, the Azure index |
| GCP | Cloud Audit Logs: `GCP_AUDIT`, `logs-gcp.*`, the GCP index |
| Identity & SaaS | Entra ID and Okta sign-in and audit logs, Defender's identity tables, the identity index |

Defender's `CloudAppEvents` carries every cloud connected to Defender for Cloud Apps, so a detection on it counts for all three IaaS providers unless its query names one. A detection for a sub-technique counts for its parent too. The same table is at `GET /api/coverage/cloud`.

## Limits

Reference coverage only reflects what's in `bespoke/llm_references/`, which is your own, gitignored folder. A new installation has none until you add some: see [BESPOKE.md](../BESPOKE.md).
