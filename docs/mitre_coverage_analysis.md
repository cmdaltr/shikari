# How Complete is Your MITRE ATT&CK Data? A Deep Dive into Technique Coverage

> **TL;DR:** While building and testing [Archer](https://github.com/your-org/archer) — an automated multi-SIEM detection generation platform — we ran a close inspection of how MITRE ATT&CK data is structured and what it takes to extract *complete* group technique coverage from it. Using Scattered Spider (G1015) as our test case, a naive STIX extraction returns just **36 techniques**. The ATT&CK website shows **64**. Follow all three MITRE-official attribution paths and you reach **150**. This post explains why, and how to do it right.

---

## 1. Background

Archer generates detection rules for every MITRE ATT&CK technique attributed to a threat group — across Splunk, Microsoft Defender for Endpoint, Elastic, and Google SecOps simultaneously. Getting that attribution right is foundational: miss a technique and you miss a detection.

During development and testing we used Scattered Spider (G1015) as a benchmark group. It's well-documented, actively tracked, and has a wide spread of techniques across many tactics — a good stress test for any detection pipeline. We wanted to know: how many techniques does MITRE officially attribute to Scattered Spider, and are we capturing all of them?

The answer turned out to be more interesting than expected.

---

## 2. The Numbers

### Scattered Spider (G1015) — Technique Count by Extraction Method

| Extraction method | Unique techniques | % of full coverage |
|------------------|------------------|--------------------|
| Naive STIX parse (descriptions-only) | **36** | 24% |
| STIX direct attribution | **64** | 43% |
| All three MITRE attribution paths | **150** | 100% |

A naive extraction — the kind you'd write in an afternoon — yields only **24% of the full picture**. Even a careful direct-attribution query misses more than half.

---

## 3. Reproducing the Numbers

### Method 1 — Naive extraction (descriptions only)

Many STIX parsing examples you'll find online filter to relationships that have a prose `description` field. It seems reasonable — you want procedure examples, after all. Let's count:

```bash
# Count unique technique IDs for G1015 from a descriptions-filtered CSV
grep "G1015" data/mitre_procedures.csv \
  | cut -d',' -f1 \
  | sort -u \
  | wc -l
# → 36
```

The 36 techniques returned:

```
T1003.003  T1006      T1018      T1021.007  T1068      T1074
T1083      T1087.002  T1098.003  T1114      T1133      T1136
T1204      T1213.003  T1213.005  T1217      T1219      T1484.002
T1486      T1530      T1538      T1539      T1552.001  T1552.004
T1553.002  T1556.006  T1556.009  T1564.008  T1567.002  T1578.002
T1580      T1598      T1598.004  T1621      T1656      T1657
```

### Method 2 — Direct STIX attribution (no description filter)

Query the STIX bundle directly for all `intrusion-set --[uses]--> attack-pattern` relationships for the group, with no description requirement:

```python
import json

with open("archer/data/cache/enterprise-attack.json") as f:
    bundle = json.load(f)

objects = bundle["objects"]
tech_objs = {o["id"]: o for o in objects if o.get("type") == "attack-pattern"}

# Find Scattered Spider's STIX object ID
group = next(
    o for o in objects
    if o.get("type") == "intrusion-set" and "Scattered Spider" in o.get("name", "")
)
print("STIX ID:", group["id"])
# → intrusion-set--44d37b89-a739-4810-9111-0d2617a8939b

# Walk all direct uses relationships
tech_ids = set()
for o in objects:
    if (o.get("type") == "relationship"
            and o.get("relationship_type") == "uses"
            and o.get("source_ref") == group["id"]):
        t = tech_objs.get(o.get("target_ref"))
        if t:
            for ref in t.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tech_ids.add(ref["external_id"])

print(f"Direct STIX attributions: {len(tech_ids)}")
# → 64
```

This matches the [attack.mitre.org/groups/G1015](https://attack.mitre.org/groups/G1015/) page. But it still misses 86 techniques.

### Method 3 — All three attribution paths

```python
from archer.mitre.retrieve import retrieve_techniques

techniques = retrieve_techniques(bundle_obj, group["id"])
# → 193 relationship tuples → 150 unique technique IDs
```

Archer's `retrieve_techniques()` follows all three paths described below. For Scattered Spider: **150 unique techniques**.

### Identifying the gap between Method 1 and Method 2

The 29 techniques present in the STIX bundle but absent from a descriptions-only extraction:

```python
stix_direct = { "T1016", "T1021.001", "T1021.004", "T1041", "T1059.001",
                "T1059.004", "T1069", "T1069.002", "T1070.008", "T1078",
                "T1078.004", "T1082", "T1087", "T1090", "T1098", "T1105",
                "T1114.003", "T1219.002", "T1490", "T1543.002", "T1555.005",
                "T1562.001", "T1572", "T1583.001", "T1585.001", "T1588.001",
                "T1588.002", "T1589", "T1598.003" }

naive_csv = { "T1003.003", "T1006", "T1018", ... }  # 36 from above

print(sorted(stix_direct - naive_csv))
# → 29 techniques silently dropped
```

Notable absences: **T1078.004** (Valid Accounts: Cloud — one of Scattered Spider's most-used TTPs), **T1059.001** (PowerShell), **T1562.001** (Impair Defenses: Disable AV), **T1572** (Protocol Tunnelling).

---

## 4. Why the Gap Exists: How MITRE Models Technique Attribution

MITRE ATT&CK uses a graph data model (STIX 2.1). Techniques are not directly listed on a group — they are *inferred* by traversing relationships. There are three distinct paths:

```
┌───────────────────────────────────────────────────────────────────┐
│                  MITRE ATT&CK Attribution Graph                    │
├───────────────────────────────────────────────────────────────────┤
│                                                                     │
│  PATH 1 — Direct                                                    │
│  Scattered Spider ──[uses]──► T1621 (MFA Fatigue)                  │
│                                                                     │
│  PATH 2 — Via Software                                              │
│  Scattered Spider ──[uses]──► Mimikatz (tool)                      │
│                    Mimikatz ──[uses]──► T1003.001 (LSASS Memory)   │
│                                                                     │
│  PATH 3 — Via Campaign                                              │
│  C0027 (campaign) ──[attributed-to]──► Scattered Spider            │
│  C0027 ──[uses]──► T1566.001 (Spearphishing Attachment)            │
│                                                                     │
└───────────────────────────────────────────────────────────────────┘
```

### Path 1 — Direct (`intrusion-set` → `uses` → `attack-pattern`)

The group directly uses the technique. This is what the ATT&CK website shows in the "Techniques Used" table and what a direct STIX query returns: **64 techniques** for Scattered Spider.

Many of these relationships have no `description` field — they were added to reflect observed behaviour without a specific cited procedure example. Filtering them out on description presence silently drops them.

### Path 2 — Via Software (`intrusion-set` → `uses` → `tool/malware` → `uses` → `attack-pattern`)

Scattered Spider's toolkit includes **ScreenConnect**, **AnyDesk**, **Splashtop**, **Mimikatz**, **Raccoon Stealer** and others. Each software object in ATT&CK carries its own technique mappings. Walking the two-hop path reveals an additional **68 techniques** not in the direct set.

This is the biggest contributor to the gap and the most commonly missed path in extraction scripts.

### Path 3 — Via Campaign (`campaign` → `attributed-to` → `intrusion-set` + `campaign` → `uses` → `attack-pattern`)

MITRE ATT&CK records major threat activity clusters as named **campaigns** (e.g. C0027 for Scattered Spider). Techniques attributed to those campaigns are linked to the group via the `attributed-to` relationship. This path adds another **18 techniques**.

---

## 5. Full Attribution Breakdown for Scattered Spider

| Attribution path | Techniques | Example |
|-----------------|-----------|---------|
| Direct (Path 1) | 64 | T1621 — MFA Fatigue |
| Via Software (Path 2) | 68 | T1003.001 via Mimikatz |
| Via Campaign (Path 3) | 18 | T1566.001 via Campaign C0027 |
| **Total unique** | **150** | |

### Techniques of note now captured via software and campaign paths

| Technique | Name | Path | Significance |
|-----------|------|------|-------------|
| T1003.001 | OS Credential Dumping: LSASS | Via Mimikatz | High-fidelity credential theft |
| T1555.003 | Credentials from Password Stores: Browsers | Via software | Browser credential harvest |
| T1566.001 | Spearphishing Attachment | Via C0027 | Initial access vector |
| T1059.003 | Windows Command Shell | Via software | Execution |
| T1547.001 | Registry Run Keys | Via software | Persistence |
| T1550.002 | Pass the Hash | Via software | Lateral movement |
| T1070.001 | Clear Windows Event Logs | Via software | Defence evasion |

---

## 6. Three Common Mistakes When Extracting ATT&CK Data

Building Archer required us to get this right. Here are the three mistakes that cause incomplete coverage:

### Mistake 1 — Filtering on description presence

```python
# This silently drops valid attributions with no procedure text
if not relationship.get("description"):
    continue
```

MITRE adds technique attributions without prose descriptions all the time — particularly for techniques attributed via software or for recently updated groups. **Drop this filter entirely.** The description field is informational, not a signal of attribution validity.

### Mistake 2 — Skipping tools and malware

```python
# This misses the entire software expansion path
if source_obj.get("type") != "intrusion-set":
    continue
```

The two-hop software path is where the majority of the hidden techniques live. For Scattered Spider it accounts for 68 out of 150 techniques — 45% of the total. You must walk `group → [uses] → software → [uses] → technique`.

### Mistake 3 — Ignoring campaign attribution

The `campaign` object type was added to ATT&CK relatively recently (v12, October 2022). Many scripts written before then never added support for it. If your extraction code doesn't handle `attributed-to` relationships from campaigns, you'll miss the C0027 path for Scattered Spider and equivalent paths for other groups.

---

## 7. Data Sources

When building Archer's extraction pipeline, we evaluated three official MITRE sources. No third-party advisories or supplementary reports were used — everything comes directly from MITRE:

### Source 1 — STIX Bundle (primary)

```
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

- Current version: ATT&CK **v18.1** (released 2025-11-13)
- The canonical source. The older `mitre/cti` repository is now legacy — `attack-stix-data` is the authoritative repo.
- Contains all objects and relationships needed to traverse all three attribution paths.

### Source 2 — XLSX Relationships Spreadsheet (cross-reference)

```
https://attack.mitre.org/docs/attack-excel-files/v18.1/enterprise-attack/enterprise-attack-v18.1-relationships.xlsx
```

- Tabular export of all ATT&CK relationships, independently generated from the STIX bundle.
- Used to cross-validate STIX parsing: load the XLSX, diff against extracted pairs, confirm zero gaps.
- Our cross-reference against 19,431 XLSX pairs found **zero discrepancies** — the STIX bundle is complete.

### Source 3 — ATT&CK Navigator (informational only)

The [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) is a visualisation tool. It generates group layer JSON files **dynamically from STIX** — there are no pre-built per-group layer files in the `mitre-attack/attack-navigator` repository. For programmatic extraction, Navigator layers add nothing beyond what the STIX bundle already contains.

---

## 8. Archer's Extraction Pipeline

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              Archer MITRE Extraction Pipeline                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. Download STIX bundle (mitre-attack/attack-stix-data)         │
│     ↓                                                            │
│  2. Index objects by type                                        │
│     (groups, techniques, software, campaigns)                    │
│     ↓                                                            │
│  3. Walk Path 1 — direct group→technique                        │
│  4. Walk Path 2 — group→software→technique                       │
│  5. Walk Path 3 — campaign→group + campaign→technique            │
│     ↓                                                            │
│  6. Cross-reference against XLSX (validation)                    │
│     ↓                                                            │
│  7. Emit CSV (delegated to MITRESaw)                             │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Output CSV schema

Archer now delegates CSV generation to MITRESaw (included as a git submodule). The output CSV has 12 columns:

```
group_sw_id, group_sw_name, group_sw_description,
technique_id, technique_name, technique_description,
tactic, platforms, framework,
procedure_example, evidence, detectable_via
```

The `evidence` column contains a JSON dict of extracted indicators (commands, registry keys, file paths, CVEs, ports, software names, event IDs). The `detectable_via` column lists mapped log sources for each technique.

### Key implementation principles

| Principle | Rationale |
|-----------|-----------|
| No description filter | Procedure descriptions are informational, not attribution indicators |
| Walk all three paths | 57% of techniques for a typical group come via software or campaign |
| Use `attack-stix-data` | `mitre/cti` is the legacy repo — use the canonical source |
| Version-pin the bundle | Use explicit version URLs (e.g. `enterprise-attack-18.1.json`) for reproducibility |
| XLSX cross-reference | Independent validation — confirms STIX parse is complete |

---

## 9. Validation

Running the pipeline against all 172 groups in ATT&CK v18.1:

```bash
python scripts/data/extract_mitre_procedures.py
```

```
Downloaded ATT&CK v18.1 (24,772 objects)
Loaded 19,431 relationship pairs from XLSX

Indexed: 187 groups, 835 techniques, 787 software objects, 52 campaigns

Attribution breakdown:
  PATH 1 direct:            5,211 rows
  PATH 2 via software:      20,248 rows
  PATH 3 via campaign:        609 rows
  Total unique rows:         26,068

✓ XLSX cross-reference: all XLSX group→technique pairs present in STIX

Scattered Spider (G1015) unique techniques: 150

Overall summary:
  Unique techniques: 575
  Unique groups:     172
  Unique tactics:    14

✓ Saved 26,068 rows to data/mitre_procedures.csv
```

### Screenshot placeholder: Coverage comparison bar chart
![Coverage comparison: naive vs direct vs full pipeline](screenshots/coverage_comparison.png)
*36 (naive) → 64 (direct STIX) → 150 (all three paths) for Scattered Spider*

### Scattered Spider — full technique list (150)

```
T1003.001  T1003.002  T1003.003  T1003.004  T1003.005  T1003.006
T1003.007  T1003.008  T1005      T1006      T1012      T1014
T1016      T1018      T1020      T1021.001  T1021.004  T1021.005
T1021.007  T1027.007  T1027.013  T1030      T1033      T1041
T1046      T1047      T1048.002  T1048.003  T1055      T1056.001
T1057      T1059.001  T1059.003  T1059.004  T1068      T1069
T1069.002  T1069.003  T1070.001  T1070.004  T1070.008  T1071.001
T1074      T1078      T1078.004  T1082      T1083      T1087
T1087.001  T1087.002  T1087.003  T1087.004  T1090      T1090.003
T1095      T1098      T1098.001  T1098.003  T1098.005  T1102
T1105      T1106      T1112      T1113      T1114      T1114.003
T1119      T1124      T1125      T1133      T1134      T1134.005
T1135      T1136      T1140      T1190      T1195      T1204
T1204.002  T1207      T1213      T1213.002  T1213.003  T1213.005
T1217      T1219.002  T1221      T1222.001  T1484.002  T1486
T1489      T1490      T1491.001  T1518      T1530      T1538
T1539      T1543.002  T1546.015  T1547.001  T1547.005  T1548.002
T1550.002  T1550.003  T1552.001  T1552.004  T1553.002  T1555
T1555.001  T1555.003  T1555.004  T1555.005  T1556.006  T1556.009
T1558.001  T1558.002  T1560      T1560.001  T1561.001  T1562.001
T1564      T1564.003  T1564.008  T1566.001  T1566.004  T1567
T1567.002  T1568.002  T1570      T1572      T1573.001  T1573.002
T1578.002  T1580      T1583.001  T1585.001  T1588.001  T1588.002
T1589      T1589.001  T1598      T1598.001  T1598.003  T1598.004
T1614      T1621      T1649      T1656      T1657      T1680
```

---

## 10. MITRESaw — Integrated ATT&CK Extraction

**[MITRESaw](https://github.com/cmdaltr/MITRESaw)** is included as a git submodule in Archer (at `MITRESaw/`). It is the single source of truth for MITRE ATT&CK procedure extraction — Archer delegates all CSV and XLSX generation to MITRESaw rather than duplicating the extraction logic.

### How Archer uses MITRESaw

Archer runs MITRESaw via `archer.mitre.procedures.run_mitresaw()`:

```bash
python MITRESaw/MITRESaw.py -d -E -R
```

This produces:
- `mitre_procedures.csv` — 12-column CSV with all group-technique mappings, extracted indicators, and log source mappings
- `mitre_procedures.xlsx` — Styled evidence report with atomic indicators and fetched reference material

The output is copied to `data/mitre_procedures.csv` and `data/mitre_procedures.xlsx`.

### What MITRESaw does

For each threat actor, MITRESaw:
- Extracts all technique attribution rows via all three STIX paths (direct, via software, via campaign)
- Identifies searchable indicators (ports, Windows event IDs, registry keys, commands, CVEs) from procedure descriptions
- Maps techniques to log sources (Windows event logs, Sysmon, Zeek, cloud audit logs, etc.)
- Generates a styled XLSX evidence report with one row per atomic indicator
- Fetches and extracts content from all citation sources (blog posts, reports, advisories)

### The connection to this research

MITRESaw was originally derived from Archer's `archer.mitre.procedures` module. The three-path walking logic described in this analysis is what justified building it. Now that MITRESaw has matured into a more feature-rich tool (with indicator extraction, log source mapping, evidence reports, and reference collection), the dependency has been inverted — Archer imports MITRESaw as the upstream source.

---

## 11. Key Takeaways

1. **The MITRE ATT&CK website and STIX bundle agree on 64 direct attributions for Scattered Spider.** Any extraction returning fewer than that is losing data at parse time, almost always due to a description filter.

2. **57% of Scattered Spider's full technique surface comes via software and campaign paths.** If your tooling doesn't walk these paths, your detection coverage appears much lower than it actually is — and your gap analysis shows false positives.

3. **The description field is not an attribution signal.** Filter on it for display purposes if you want prose, but never use it to decide whether an attribution is valid.

4. **`mitre-attack/attack-stix-data` is now the canonical STIX source.** The old `mitre/cti` repository still exists and mirrors the data, but `attack-stix-data` is the authoritative home going forward.

5. **XLSX and STIX agree completely.** Our cross-reference of 19,431 XLSX relationship pairs against STIX found zero gaps — the STIX bundle is a complete representation of ATT&CK's data model.

---

## References

- [Scattered Spider (G1015) — MITRE ATT&CK](https://attack.mitre.org/groups/G1015/)
- [ATT&CK STIX Data Repository (canonical)](https://github.com/mitre-attack/attack-stix-data)
- [ATT&CK v18.1 Enterprise STIX Bundle](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-18.1.json)
- [ATT&CK v18.1 Relationships XLSX](https://attack.mitre.org/docs/attack-excel-files/v18.1/enterprise-attack/enterprise-attack-v18.1-relationships.xlsx)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Working with ATT&CK — MITRE](https://attack.mitre.org/resources/working-with-attack/)
