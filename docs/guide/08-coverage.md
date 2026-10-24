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

## Limits

Reference coverage only reflects what's in `bespoke/llm_references/`, which is your own, gitignored folder. A new installation has none until you add some: see [BESPOKE.md](../BESPOKE.md).
