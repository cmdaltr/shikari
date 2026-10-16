# Data and updates

Archer downloads public data, keeps it up to date by itself, and stores everything you make under `data/` in the project folder. Your own data is never committed to git.

## What Archer downloads, and when

| Data | Source | Updated | Stored in |
|---|---|---|---|
| MITRE ATT&CK Enterprise | `mitre-attack/attack-stix-data` on GitHub | On every start, if a new release is out | `data/cache/enterprise-attack.json` |
| MITRESaw procedures | Built from the ATT&CK bundle | When ATT&CK changes (changed groups only), or from the [MITRESaw](12-mitresaw.md) page | `data/mitre_procedures.csv`, `.xlsx` |
| OSINT detection rules | Public SecOps, Sentinel, Splunk and Elastic rule repositories | On every start | `data/repos/` |
| LOLBAS, LOLDrivers, LOLRMM | lolol.farm projects | At most once a day | `data/repos/lol/`, `data/cache/lol_index.json` |
| CVE records | NVD | When a CVE is first hunted, then cached | `data/cache/cve/` |
| Threat Feed | The feed sources' RSS and Atom feeds | On every start, on Refresh now, and when the Feed is opened six hours after the last collection | `data/feed/` |
| World map, flags | Natural Earth; flag-icons (MIT) | Committed; rebuilt only by `scripts/data/` | `static/images/`, `static/vendor/flag-icons/` |

Starting with `archer start --skip-index` skips rebuilding the OSINT technique index, for a faster start.

## What you make

| What | Where |
|---|---|
| Accounts, Library, settings, encrypted API keys | `data/archer.db` (SQLite) and `data/.encryption_key` |
| Generated detections (YAML) | `data/groups/` |
| Correlations | `data/correlate/` |
| Run records and progress | `data/runs/`, `data/progress/` |
| Attack flows, IOC flows, briefings | `data/attack_flows/`, `data/ioc_flows/`, `data/briefings/` |
| Uploaded reports and their extractions | `data/uploads/`, `data/blog_analysis/` |
| Feed posts, research archive, added sources | `data/feed/` |

## Your organisation's own material

The `bespoke/` folder holds what's specific to your organisation: AI prompt templates, query templates, index and table mappings, and reference queries. Its folders are committed empty and its files are gitignored, so none of it reaches git. See [BESPOKE.md](../BESPOKE.md).

## Backing up

Copy `data/archer.db`, `data/.encryption_key` (without it, stored API keys can't be read) and `bespoke/`. Everything else is rebuilt or re-downloaded.
