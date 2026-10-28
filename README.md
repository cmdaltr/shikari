<div align="center">
<a href="https://github.com/cmdaltr/archer">
<img src="static/images/archer_banner.png" alt="Archer - Automated Multi-Vendor Threat HUNTING & DETECTION SUITE" width="600px" height="600px">
</a>
</div>

<br>

Archer automates threat hunting and detection engineering from MITRE ATT&CK. Give it a threat group, CVE or threat report and it generates, validates and correlates detections for Google SecOps (YARA-L), Microsoft Defender (KQL) and Elastic (ES\|QL), with coverage mapping, attack flows and MITRESaw procedure intel. AI is optional.

## 🛠️ Setup and Usage

**📘 User guide, one page per part of Archer: [docs/guide](docs/guide/README.md)**

**📖 Setup instructions: [GETTING_STARTED.md](GETTING_STARTED.md)**

**⌨️ Usage instructions and guidance: [USAGE.md](docs/USAGE.md)**

### Running Archer

```bash
./archer-cli install  # once: links `archer-cli` into ~/bin
archer-cli start      # background; restarts Archer (and Ollama) if they crash
archer-cli status
archer-cli logs -f
archer-cli restart
archer-cli stop
```

`archer-cli start` runs a small supervisor (`archer/service.py`) that starts uvicorn and, if Ollama is installed but not running, `ollama serve`. If either dies, it's started again (1s, then backing off to 60s; it gives up after 6 failed starts in a row, e.g. a port clash). Options are remembered: `--port`, `--no-reload`, `--no-ollama`, `--ollama-models DIR` (an external volume that isn't mounted falls back to Ollama's default folder rather than creating an empty one). `archer-cli serve` runs the server in the foreground without the supervisor; `archer-cli docker ...` is `docker compose` with the project's compose file. The same command has the console (`archer-cli console`), a dry-run preview (`archer-cli preview <group>`), the MCP server (`archer-cli mcp`) and the pipeline without the server (`archer-cli offline generate|correlate|hunt`).

### Desktop App

Installers for macOS, Windows and Linux are on the Releases page: they bundle everything, with no Python or checkout needed. Each connects to your organisation's Archer server (users type its address, or IT sets it by MDM or Group Policy) or runs Archer on that computer. See [desktop/README.md](desktop/README.md). From a checkout instead:

```bash
pip install -e '.[desktop]'      # pywebview, for a native window
archer-cli app install --dock    # macOS: ~/Applications/Archer.app, kept in the Dock
archer-cli app install           # Linux: application menu entry (~/.local/share/applications)
archer-cli app uninstall
```

On Windows, from the repository: `.venv\Scripts\python archer\desktop.py install` adds Start menu and desktop shortcuts (pin to the taskbar from the Start menu).

The app launches this checkout's `.venv`, so it updates with `git pull`; it isn't a frozen copy. Opening it starts the server if it isn't running and shows Archer in its own window. Quitting stops a server the app started and leaves one from `archer-cli start` alone. Without pywebview it uses a Chrome/Edge/Brave app window, or the default browser. On Linux the native window also needs GTK (`python3-gi gir1.2-webkit2-4.1`) or Qt. If the repository sits in OneDrive on macOS, the first launch asks for permission to access files in OneDrive; allow it. Icons are built from `archer.png` by `desktop/make_icons.py`.

---
<br>

## ✨ Features

### Core Capabilities
- 🎯 **MITRE ATT&CK Integration** - Automated detection generation from threat group TTPs
- 📤 **File Upload & Intelligence Extraction** - Upload threat intel files (PDF, TXT, JSON, CSV, XLSX, YARA, DOCX) for automatic TTP/IOC extraction
- 🌐 **Blog Analysis** - Paste a threat intel blog URL and extract TTPs/IOCs automatically
- 📰 **Threat Feed** - A searchable wall of the last 7 days of vendor and government research (26 sources, and admins can add their own), each post tagged with targeted industries, the attacker's nation, and opportunistic or financial motive; a keyword search of all research at any date; and watchlists, saved searches that flag new matching posts (optionally by email). No AI involved ([details](#threat-feed))
- 🌍 **Cyber Powers** - IISS cyber power tiers, ATT&CK attribution confidence and targeting on an Equal Earth world map ([guide](docs/guide/11-cyber-powers.md))
- 🧪 **Regex tester** - Test a pattern on your own text and check it for Defender XDR and SecOps (RE2), Splunk (PCRE) or Elastic (Lucene), with per-SIEM escaping ([guide](docs/guide/14-regex.md))
- 🧬 **Emulate** - Which logs record each technique, from 1,694 attacks recorded in public labs (Windows, Linux, macOS, ESXi and cloud): native OS logs first, with Sysmon and EDR optional; your detections' indicators checked against the recordings; and Defender XDR's own alerting per technique from Microsoft's GUIDE dataset. Recording your own lab is coming soon ([guide](docs/guide/19-emulate.md))
- 🧱 **Technology stack** - Group hunts leave out techniques and procedures for platforms and products you don't run (Profile → Technology stack)
- 🪚 **MITRESaw** - Every group's ATT&CK procedures and the indicators in them, rebuilt as ATT&CK changes ([guide](docs/guide/12-mitresaw.md))
- 🗺️ **Attack Flows** - Every flow saved to your library on one page: pick a group, report or CVE to open its ATT&CK flow
- 🔍 **Multi-Platform Support** - Google SecOps (YARA-L), Microsoft Defender (KQL) and Elastic (ES\|QL); Splunk is switched off for now ([onboarding](docs/SIEM_ONBOARDING.md))
- 🔗 **STIX / TAXII & MISP** - Import a STIX 2.1 bundle, a TAXII collection or a MISP event as a hunt input, and export a run as a STIX 2.1 bundle ([guide](docs/guide/21-stix-taxii-misp.md))
- 🧾 **Detections as code** - Commit a run's detections to a git repo and diff two commits to see what a Regenerate changed; dry-run push to Defender XDR / SecOps ([guide](docs/guide/22-detections-as-code.md))
- 🎛️ **Threat library & assessments** - Intelligence-led test cases from a profile's ranked groups, run in assessments that record red and blue outcomes, with CSV and ATT&CK Navigator export ([guide](docs/guide/23-threat-library-assessments.md))
- 🧠 **Heuristic and AI-Powered Correlations** - Semantic analysis and query correlation with per-technique chained queries; each correlation carries its detections' OSINT enrichment and says when a part's query has changed since
- 🛡️ **Threat Briefing** - ATT&CK prioritisation grounded in real MITRE data and your detection coverage gaps
- 🧹 **IOC sweeps** - Report and CVE indicators as sweep queries: a known-good list, files in system folders matched only when written, and IPs and domains that expire after 90 days ([details](docs/guide/03-analyse.md#what-the-ioc-sweep-leaves-out-or-narrows))
- 🔬 **Research Tab** - Actor technique consolidation with keyword/country filtering, tactic filtering, and professional XLSX export
- 💬 **Ask Archer** - Conversational Q&A panel for ATT&CK questions and SIEM query generation
- 🌐 **Web UI & CLI** - VirusTotal-inspired tabbed interface plus command-line tools
- 🖥️ **Interactive Console (`archer-cli console`)** - Metasploit-style interactive shell with module selection, options, tab-completion
- 🤖 **Agents** - Detection repair, Ask Archer with tools, and intel triage: a model in a loop with Archer's tools, with approval for anything that changes something ([docs](docs/agents/README.md))
- 🔌 **MCP Server (`archer-cli mcp`)** - Archer's tools and agent prompts for Claude Code, Claude Desktop or any MCP client
- 🎯 **RAG Fidelity Enhancement** - Improve query quality using 3,400+ community detection examples ([docs](docs/rag/README.md))
- 🏢 **Organization-Specific Customization** - Bespoke sample searches and global exclusions for your environment

### Additional Features

- **Detection Validation** - Test queries against containerized SIEMs with sample events ([docs](docs/features/RUNTIME_VALIDATION.md))
- **Detection Library** - Save, search, tag, share, and export your generated detections
- **Company Profiling** - Industry-aware threat landscape analysis for targeted detection
- **CVE Hunting** - Generate detections from CVE IDs with NVD enrichment
- **Query Execution** - Splunk API client (code implemented, see [UNTESTED.md](docs/other/UNTESTED.md)); Defender XDR planned with hit counts (#16)
- **Running atomics from Archer** - Coming soon; [record a lab](docs/guide/20-recording-a-lab.md) on your own VMs for now (#22)
- **Threat library with red and blue outcomes (VECTR-style)** - Built (Build → Assessments, #24); CALDERA and MACAT integration are feature requests ([#30](https://github.com/cmdaltr/archer/issues/30), [#31](https://github.com/cmdaltr/archer/issues/31))

### Security & User Management
- 🔐 **Enterprise Authentication** - Bcrypt password hashing, session management, MFA support (TOTP)
- 🛡️ **Security Features** - Rate limiting, CSRF protection, account lockout, audit logging
- 👥 **Admin User Management** - Complete CRUD API for user accounts (create, read, update, deactivate)
- 📧 **Email Integration** - SMTP-based password reset with secure token delivery
- 🔑 **API Key Encryption** - Fernet encryption for stored SIEM/AI API credentials
- 📊 **Comprehensive Audit Logs** - Track all authentication events and admin actions
- 🔒 **Role-Based Access Control** - Admin and Standard user roles with granular permissions

---
<br>

### Threat Feed

The Threat Feed (Intel → Feed, or `intel/feed` in the console) is a wall of the last seven days of research, one card per post: title, a two-to-three sentence description, and tags. The search box matches titles and descriptions; the filters show posts relevant to you (your industries, plus anything opportunistic or financially motivated), your industries only, opportunistic or financial only, or everything. Set your industries in Profile → Threat Feed industries. **Analyse in Archer** opens a post on the Home page's Analyse tab.

The feed is collected in the background every time Archer starts, whenever you press **Refresh now**, and when the Feed is opened six hours after the last collection; while any watchlist exists, every six hours. **Watch** saves a search as a watchlist: posts that match it later are flagged on the Feed and counted on the menu, and can be emailed. Only posts it hasn't seen are fetched and analysed, so a refresh with nothing new takes about ten seconds. No AI is involved: tags come from regular expressions over the text and ATT&CK's own group data.

Sources (RSS/Atom): Microsoft Threat Intelligence, Google Threat Intelligence (Mandiant), Unit 42, Cisco Talos, CrowdStrike, SentinelLABS, Kaspersky Securelist, ESET WeLiveSecurity, Proofpoint, The DFIR Report, Red Canary, Huntress, Elastic Security Labs, CISA, NCSC (UK), Recorded Future, Trend Micro Research, Rapid7, FortiGuard Labs, Symantec Threat Hunter, Volexity, Zscaler ThreatLabz, Sekoia, Group-IB, Bitdefender Labs and JPCERT/CC. Admins can add their own.

**Search all research** finds a campaign, tool or actor name ("GhostAction", "RedSun") at any date. It searches three places. First, Archer's archive of every post its sources' feeds have carried (data/feed/archive.json); every collection adds the whole of each feed, so some sources reach back to 2016 and the archive grows from then on. Second, ATT&CK's groups, software and campaigns, by name, alias or description. Third, optionally, Google News and Bing News. Web results are de-duplicated, English only, and kept only when they read as security stories. The web search sends the keyword to Google and Bing, so it is a checkbox. Results are cached for an hour.

Tags are taken from the post's title and its technical paragraphs only: a paragraph with a technique ID, hash, IP, defanged domain, file name, command-line tool, registry key or command-line switch, and the paragraph either side. A CVE makes a paragraph technical only when the post has one of those other indicators too, because newsletters and policy pieces cite CVEs in passing. A passing mention in a policy piece or a reading list doesn't count.

| Tag | From |
|---|---|
| Industries | The targeting in ATT&CK of each group named there (name or alias); the industries most of a nation's ATT&CK groups target (30% or more), when activity is attributed to China, Russia, Iran or North Korea ("China-nexus", "DPRK", "Russian GRU"); and industries the post itself names twice or in its title |
| Nation | Attribution to China, Russia, Iran or North Korea there, and the nexus of each named group |
| Opportunistic | Supply-chain or package-registry compromise, reported exploitation, ransomware-as-a-service, infostealers, botnets, malvertising and fake updates, initial access brokers |
| Financially motivated | Ransomware, extortion, BEC, crypto theft or mining, banking trojans, carding, or a named group whose ATT&CK objective is financial |

Posts with no technique ID, IOCs or named group, and no CVE alongside another indicator (product news, webinars, newsletters), aren't shown.

### Techniques that can't produce a detection

About 318 of ATT&CK's 697 techniques name no command, file, registry key or other indicator in their description or in any group's procedure examples (**T1190**, **T1566.001**, much of Reconnaissance and Resource Development). The standard pipeline can't build a query for them; only AI or OSINT can. Archer keeps that list in `archer/data/technique_yield.json`, rebuilt when ATT&CK's version changes:

- A technique hunt whose techniques are all on the list, run without AI or OSINT, is refused with the reason instead of producing an empty run; `hunt/technique` says which techniques will produce nothing before it starts.
- Every run records the techniques that produced nothing and why, shown at the top of its results page.
- With AI, a technique the model has returned no queries for on three runs in a row is skipped (no prompt spent) until a call succeeds or the list is reset.

```bash
.venv/bin/python -m archer.build.technique_yield              # both lists
.venv/bin/python -m archer.build.technique_yield --reset-llm  # forget the AI list
```

## 📚 Documentation & Resources

### Archer Documentation

**📖 [Complete Documentation Index](docs/DOCS_INDEX.md)** - Browse all documentation by category

**Quick Links:**
- **Getting Started:** [GETTING_STARTED.md](GETTING_STARTED.md) | [Mapping Setup](GETTING_STARTED.md#step-4-configure-mapping-files-critical) | [User Guide](docs/guide/README.md)
- **Interactive Console:** [archer-cli console Guide](#-interactive-console-archer-cli-console)
- **Usage:** [Where everything is, and the CLI](docs/USAGE.md) | [Auto-Generated API Docs](http://localhost:8000/docs)
- **Research:** [Actor consolidation and XLSX export](docs/guide/05-research.md)
- **Threat Briefing:** [On the Results page](docs/guide/06-results.md) | [API Reference](docs/features/API_INTEGRATION_GUIDE.md#workflow-8-threat-briefing)
- **Ask Archer:** [Agents and Ask Archer](docs/guide/15-agents-and-ask-archer.md)
- **Emulate:** [Recorded telemetry](docs/guide/19-emulate.md) | [Recording a lab (coming soon)](docs/guide/20-recording-a-lab.md)
- **Agents & MCP:** [Agents guide](docs/agents/README.md) | [Minimal agent example](examples/agents/minimal_agent.py)
- **API Integration:** [API Integration Guide](docs/features/API_INTEGRATION_GUIDE.md)
- **Correlation Tuning:** [Correlation Engine](docs/architecture/CORRELATION_ENGINE.md) | [Quick Reference](docs/architecture/CORRELATION_QUICK_REFERENCE.md)
- **Features:** [Security](docs/features/SECURITY_FEATURES.md) | [AI Training](docs/ai/AI_TRAINING.md) | [OSINT](docs/features/OSINT_INTEGRATION.md)
- **RAG Enhancement:** [RAG User Guide](docs/rag/RAG_USER_GUIDE.md) | [Implementation Guide](docs/rag/FIDELITY_IMPLEMENTATION_GUIDE.md)
- **Testing:** [Test Suite](tests/README.md) | [Run Tests](tests/run_all_tests.sh)
- **Architecture:** [Performance](docs/architecture/PERFORMANCE_ARCHITECTURE.md) | [Schema Normalization](docs/architecture/SCHEMA_NORMALIZATION.md)

### External Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [VECTR](https://vectr.io/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

---
<br>

## 🖥️ Interactive Console (archer-cli console)

`archer-cli console` is a Metasploit-style interactive shell for building detection queries, running correlations and hunting techniques.

### Launch

```bash
archer-cli console
```

### Modules

Local modules run in the console's own process. Server modules drive a running Archer server through `archer/client.py`, the same client the MCP server and agents use, so they run exactly what the web app runs: the profile's AI assignment and call cap, IOC sweeps, IOC flow and the latest-run view.

| Module | Runs | Description |
|--------|------|-------------|
| `generate` | local | Generate detections for a threat group (`MODE llm` uses the profile's detection provider: `PROVIDER`, `MODEL`, `MAX_CALLS`) |
| `correlate` | local | Build correlation queries from existing detection YAMLs (`MIN_RELEVANCE`) |
| `hunt` | local | Look up a technique and compile its detections |
| `emulate` | local | Adversary emulation (coming soon) |
| `hunt/group` | server | Group hunt with AI, OSINT, merging, SIEM exclusions, validation and an optional briefing |
| `hunt/cve` | server | CVE hunt: exploitation detections plus IOC sweeps from the CVE's references |
| `hunt/technique` | server | Technique hunt across every group that uses the techniques |
| `intel/report` | server | Extract TTPs and IOCs from a report URL or file and hunt them (`MODE all \| iocs \| review`) |
| `intel/company` | server | Profile a company from OSINT and hunt the groups that target it |
| `intel/feed` | server | This week's research, tagged by industry, nation and motive; `SEARCH` titles and descriptions, `SHOW relevant\|all` (`INDUSTRIES list` to choose yours) |
| `research/actors` | server | Find actors by keyword (country, industry) and consolidate their techniques; XLSX export |
| `ai/ask` | server | Ask Archer |
| `ai/briefing` | server | Threat briefing: prioritised techniques and coverage gaps |
| `ai/settings` | server | Show or change the AI provider and model for Ask and detection generation |
| `results` | server | A run's detections, correlations and IOC flow; zip download |
| `agent/repair` | server | Agent: fix a run's queries that won't parse or can't match, re-checking each fix |
| `agent/ask` | server | Agent: Ask Archer with tools (library, coverage, ATT&CK, hunts) |
| `agent/triage` | server | Agent: triage a threat report into coverage gaps, hunts and a briefing |
| `agent/history` | server | Recent agent runs (kept across restarts); replay one, or `CONTINUE true` to carry on an interrupted or stopped one (**only on the provider it started on**) |

Server modules sign in with `ARCHER_TOKEN`, an API token from Profile → Security → API Tokens (works with MFA), or with `ARCHER_EMAIL` and `ARCHER_PASSWORD` (the console prompts for anything unset), against `ARCHER_URL` (default `http://127.0.0.1:8000`). Agents take `PROVIDER` and `MODEL` too. `PROVIDER assigned` uses the hunt choice you remembered in the web app, otherwise your detection assignment; `PROVIDER none` runs without AI.

### Commands

| Command | Description |
|---------|-------------|
| `use <module>` | Select a module |
| `show modules` | List available modules |
| `show options` | Display current module's configurable options |
| `set <OPT> <val>` | Set a module option |
| `unset <OPT>` | Clear a module option |
| `run` | Execute the selected module |
| `search <domain> <term>` | Search across bespoke, mitre, library, or all |
| `info` | Show module details |
| `back` | Deselect current module |
| `exit` | Exit the console |

Tab-completion is supported for commands, module names, option names, and option values.

### Example Session

```
$ archer-cli console

archer-cli > use generate
archer-cli (generate) > set GROUP APT29
  GROUP => APT29
archer-cli (generate) > set MODE llm
  MODE => llm
archer-cli (generate) > set CORRELATE true
  CORRELATE => True
archer-cli (generate) > show options

  Module options (generate):

  Name                 Current Value             Required   Description
  ----                 -------------             --------   -----------
  GROUP                APT29                     yes        Threat group name
  MODE                 llm                       no         Query generation mode
  CORRELATE            True                      no         Run correlation after generation
  HYPOTHESIS                                     no         Optional hypothesis
  LOL                  True                      no         LOLBAS, LOLDrivers and LOLRMM for tools the group is seen using
  OSINT                False                     no         Enable OSINT enhancement
  OSINT_COMPARE        False                     no         Enable OSINT comparison

archer-cli (generate) > run
[*] Generating detections for APT29 (mode: llm)
...
```

### Search

Search across three domains from the console:

| Domain | What it searches |
|--------|-----------------|
| `bespoke` | Prompts, detection templates, reference queries, mapping files |
| `mitre` | ATT&CK techniques, groups, software (from cached STIX data) |
| `library` | Generated detection YAMLs in `data/groups/` and correlations in `data/correlate/` |
| `all` | All three domains |

```
archer-cli > search mitre PowerShell
archer-cli > search library APT29
archer-cli > search bespoke credential
archer-cli > search all T1059
```

Results are colour-coded by type (technique, group, software, detection, correlation, reference) with highlighted search terms.

### Server Module Example

```
archer-cli > use hunt/cve
archer-cli (hunt/cve) > set CVE CVE-2024-3400
archer-cli (hunt/cve) > run
  Run started: CVE-2024-3400
  … detections
  … complete

  2 detections across 1 techniques (GoogleSecOps: 1, MicrosoftThreatProtection: 1)
  IOC sweeps: GoogleSecOps, MicrosoftThreatProtection
  IOC flow (58 IOCs, 1 links) from references for CVE-2024-3400 (unit42.paloaltonetworks.com, www.volexity.com)
    Staging / download (7)
  → Payload / execution (31)
  → Infrastructure (role not stated) (20)
```

### Query Generation Modes

The `generate` module supports three modes via `set MODE <mode>`:

| Mode | Description |
|------|-------------|
| `standard` | Default — uses Archer's built-in indicator extraction and platform validation |
| `llm` | Sends bespoke prompt templates + technique data to the detection provider in your profile (Profile → API Keys), capped at the profile's max LLM calls per run |
| `fallback` | Template-based query builder — maps MITRESaw evidence indicators to SIEM fields using bespoke mapping files, no LLM needed |

---
<br>

## 🤝 Contributing

Feel free to open issues or submit pull requests to improve Archer.

---
<br>

## 📝 License

This project is licensed under the MIT License. See the LICENSE file for details.
