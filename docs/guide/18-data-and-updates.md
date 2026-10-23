# Data and updates

Archer downloads public data, keeps it up to date by itself, and stores everything you make under `data/` in the project folder. Your own data is never committed to git.

## What Archer downloads, and when

| Data | Source | Updated | Stored in |
|---|---|---|---|
| MITRE ATT&CK Enterprise | `mitre-attack/attack-stix-data` on GitHub | On every start, if a new release is out | `data/cache/enterprise-attack.json` |
| MITRESaw procedures | Built from the ATT&CK bundle | When ATT&CK changes (changed groups only), or from the [MITRESaw](12-mitresaw.md) page | `data/mitre_procedures.csv`, `.xlsx` |
| OSINT detection rules | Public SecOps, Sentinel, Splunk and Elastic rule repositories | On every start | `data/repos/` |
| LOLBAS, LOLDrivers, LOLRMM | lolol.farm projects | At most once a day | `data/repos/lol/`, `data/cache/lol_index.json` |
| Recent CVEs | NVD and CISA KEV | On every start and daily: CVEs published in the last 30 days, marked when they're in KEV. A hunted CVE is kept past the 30 days for its results, but no longer listed | `data/feed/cves.json` |
| CVE research | NVD, the CVE's references, GitHub PoCs | When a CVE is first hunted, then cached. Each daily refresh also researches up to 60 in advance: KEV CVEs first, then those naming a product in anyone's technology stack | `data/cache/cve/` |
| Threat Feed | The feed sources' RSS and Atom feeds | On every start, on Refresh now, and when the Feed is opened six hours after the last collection | `data/feed/` |
| Recorded attack telemetry | Splunk attack_data, OTRF Security-Datasets, EVTX-to-MITRE-Attack | Committed; changed recordings fetched from the [Emulate](19-emulate.md) page or `python -m archer.telemetry --build` | `archer/data/telemetry_*` |
| Defender XDR alerting per technique | Microsoft GUIDE (Kaggle) | Committed; rebuilt by `python -m archer.telemetry --guide` | `archer/data/telemetry_guide.json` |
| Your lab's recordings | `scripts/telemetry/record-atomics.ps1` on your test machines | When you add a run | `data/telemetry/lab/` (never committed) |
| World map, flags | Natural Earth; flag-icons (MIT) | Committed; rebuilt only by `scripts/data/` | `static/images/`, `static/vendor/flag-icons/` |

Starting with `archer-cli start --skip-index` skips rebuilding the OSINT technique index, for a faster start.

## What you make

| What | Where |
|---|---|
| Accounts, Library, settings, encrypted API keys | `data/archer.db` (SQLite) and `data/.encryption_key` |
| Generated detections (YAML) | `data/groups/`: `<Technique>_<table or index>.yaml`, or `<Technique>_UDM.yaml` (and `KQL`, `SPL`, `ESQL`) where there's one file per SIEM |
| Correlations | `data/correlate/<group>.json` (the index) and one YAML per correlation in `data/correlate/<group>/`: `<A>_and_<B>[_and_<C>]_<UDM, KQL, SPL or ESQL>.yaml` (three names for a chain) |
| Run records and progress | `data/runs/`, `data/progress/` |
| Attack flows, IOC flows, briefings | `data/attack_flows/`, `data/ioc_flows/`, `data/briefings/` |
| Uploaded reports and their extractions | `data/uploads/`, `data/blog_analysis/` |
| Feed posts, research archive, added sources | `data/feed/` |

Files made before the query-language names (`_GoogleSecOps.yaml`, `_MicrosoftThreatProtection.yaml`, `_DefenderXDR.yaml`) are renamed, along with the names the correlation indexes and run records hold, by:

```bash
python -m archer.build.migrate_names            # --dry-run to see what it would do
```

## Your organisation's own material

The `bespoke/` folder holds what's specific to your organisation: AI prompt templates, query templates, index and table mappings, and reference queries. Its folders are committed empty and its files are gitignored, so none of it reaches git. See [BESPOKE.md](../BESPOKE.md).

## Backing up

Copy `data/archer.db`, `data/.encryption_key` (without it, stored API keys can't be read) and `bespoke/`. Everything else is rebuilt or re-downloaded.
