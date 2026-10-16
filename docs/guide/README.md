# Archer User Guide

Archer turns threat intelligence into detection queries. Give it a threat group, a CVE, a list of ATT&CK techniques, a threat report or a company's domain, and it works out which **MITRE ATT&CK** techniques apply, pulls the indicators ATT&CK and public detection rules document for them, and writes queries for your SIEMs. It also groups those queries into correlations, draws the attack flow, and tells you what you can't yet detect.

AI is optional. Everything in this guide works without it unless the page says otherwise.

Each page below covers one part of Archer in the same order: what it's for, how to use it, every option, where its data comes from, and its limits.

## Where everything is

The menu bar has three menus (Detections, Intel, Build), then Profile and Help. The Home page has four tabs.

| Part of Archer | Where | What it's for | Guide |
|---|---|---|---|
| Running Archer | Terminal | Start, stop and update Archer; sign in | [Running Archer](01-running-archer.md) |
| Hunt | Home → Hunt | Detections for a threat group, a CVE or ATT&CK techniques | [Hunt](02-hunt.md) |
| Analyse | Home → Analyse | Detections from a report: a URL or an uploaded file | [Analyse](03-analyse.md) |
| Profile (company) | Home → Profile | The threat groups likely to target a company, then their detections | [Company profile](04-company-profile.md) |
| Research | Home → Research | Find groups by keyword and compare their techniques | [Research](05-research.md) |
| Results | Opens after a run | A run's detections, correlations, attack flow and briefing | [Results](06-results.md) |
| Library | Detections → Library | Everything you've saved, with filters, tags and exports | [Library](07-library.md) |
| Coverage | Detections → Coverage | Which techniques the reference queries and your detections cover | [Coverage](08-coverage.md) |
| Flows | Detections → Flows | Every saved attack flow: what you can and can't detect | [Flows](09-flows.md) |
| Feed | Intel → Feed | This week's threat research, tagged; search all research | [Threat Feed](10-threat-feed.md) |
| Cyber Powers | Intel → Cyber Powers | National cyber capability, attribution and targeting on a map | [Cyber Powers](11-cyber-powers.md) |
| MITRESaw | Intel → MITRESaw | ATT&CK procedures and their indicators; OSINT repository status | [MITRESaw](12-mitresaw.md) |
| Manual | Build → Manual | Write detections from your own TTPs, one technique at a time | [Manual](13-manual.md) |
| Regex | Build → Regex | Test a regex and check it for the SIEM it will run in | [Regex](14-regex.md) |
| Agents and Ask Archer | Build → Agents; the chat button | AI that repairs queries, answers questions, triages reports | [Agents and Ask Archer](15-agents-and-ask-archer.md) |
| Profile (settings) | Profile | Your account, SIEMs, industries, country, API keys, MFA, users | [Profile and settings](16-profile-and-settings.md) |
| Console, API and MCP | Terminal | Everything above without the browser | [Console, API and MCP](17-console-api-mcp.md) |
| Data and updates | — | What Archer downloads, when, and where it keeps it | [Data and updates](18-data-and-updates.md) |
| Terms | — | ATT&CK, IOC, correlation, OSINT and the rest | [Glossary](glossary.md) |

Emulate (Build → Emulate) is marked **Soon**: adversary emulation isn't available yet.

## Which SIEMs

| SIEM | Query language | Status |
|---|---|---|
| Google SecOps | YARA-L 2.0 | Generated |
| Microsoft Defender XDR | KQL (advanced hunting) | Generated |
| Splunk | SPL | Switched off for now; reference queries and coverage still shown |
| Elastic | EQL / ES\|QL | Switched off for now |

To generate for fewer SIEMs, tick the ones you want under Profile → SIEM platforms. Adding a SIEM is covered in [SIEM onboarding](../SIEM_ONBOARDING.md).

## What uses AI

Nothing uses AI unless you choose it. These are the places you can:

| Feature | Without AI | With AI |
|---|---|---|
| Hunt, Analyse, Company profile | Queries from ATT&CK, OSINT and LOL datasets | Also queries written by a model, one call per procedure |
| Report extraction (Analyse) | Regex extraction of TTPs and IOCs | A model reads the report too |
| Company profile | Wikidata, the homepage, OSINT sources | Deeper analysis by a model |
| Threat briefing (Results) | Prioritised techniques and gaps | An optional written summary |
| Ask Archer, Agents | Not available | Required |

Archer asks before a hunt whether to use AI, and remembers your answer if you tick **Remember this choice**. Choose providers and models under Profile → API Keys.

## Other documentation

The guide is the place to start. Deeper material:

- [GETTING_STARTED.md](../../GETTING_STARTED.md): installation in full, mapping files, bespoke settings
- [Documentation index](../DOCS_INDEX.md): architecture, correlation engine, OSINT internals, AI and RAG, scripts
- The in-app **Help** page (`/how-it-works`): the pipeline explained with diagrams
