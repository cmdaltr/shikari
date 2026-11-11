# Getting Started with Shikari

Installing Shikari, signing in, and the configuration it needs before its queries fit your environment. Once it's running, the [user guide](docs/guide/README.md) covers every page.

## Prerequisites

- **Git**: `brew install git` (macOS), `apt install git` (Ubuntu/Debian), or [Git for Windows](https://git-scm.com/download/win).
- **Either** Docker Desktop (includes Compose; WSL2 on Windows) **or** Python 3.11 or later.
- Optional: [Ollama](https://ollama.com) for local AI, or an API key for a cloud model. Shikari works without AI.

## Capabilities and dependencies

Shikari's core runs on Python alone, or in Docker, with nothing optional added: hunts, report analysis, company profiles and exposure maps, research, SIEM query generation for all four platforms, ATT&CK traversal and MITRESaw, Coverage, Flows, the Library, Detections as code, the threat feed, Cyber Powers, and IOC search with STIX, TAXII and MISP import and export. The maps render as server-side SVG and geolocate over a public HTTP service, and STIX, TAXII and MISP are handled with `samarkand` and `requests` — all core dependencies, so none of this needs an extra.

Everything else is opt-in. Each capability below is simply unavailable when its tool is missing; nothing breaks the app.

| Capability | Needs | Without it |
|---|---|---|
| Emulate lab — Linux containers (Ubuntu, Rocky 10) | Docker or OrbStack on the host | the Lab tab loads; container machine types are greyed out |
| Emulate lab — macOS / Linux VMs | Tart (Apple Silicon only) | those machine types are unavailable |
| Emulate lab — Windows VM | UTM | the Windows machine type is unavailable |
| CALDERA operations | Docker (CALDERA itself runs as a container) | the Lab → CALDERA panel is inert |
| AI: Ask Shikari, Agents, AI-written queries, threat briefings | a cloud model API key, or Ollama; local in-process models also need `pip install 'shikari[local-ai]'` | AI is opt-in and off by default; everything else is unaffected |
| Desktop app window (`shikari app`) | `pip install 'shikari[desktop]'` (Linux also needs GTK or Qt) | run Shikari in a browser instead |

Rocky 10 is the sharpest case: it runs only as a Docker container, so a host without Docker loses both Rocky and the Ubuntu container — its Tart VM and the other machines still work. The `analysis`, `viz` and `geo` extras in `pyproject.toml` are for ancillary notebook and offline tooling; no page in the app requires them.

## Install

**Just using Shikari?** The desktop installers on the Releases page (macOS, Windows, Linux) need no Git, Python or Docker. Each connects to your organisation's Shikari server or runs Shikari on that computer: see [desktop/README.md](desktop/README.md). The rest of this page is for running Shikari from a checkout, including as the central server those apps connect to.

```bash
git clone https://github.com/cmdaltr/shikari.git
cd shikari
```

**Option A: Docker**

```bash
docker compose up --build  # or: shikari docker up --build, once shikari is installed
docker compose down        # stop
```

Data lives in Docker volumes and survives restarts.

**Option B: local Python**

```bash
python3 -m venv .venv            # add --copies if the checkout is in a synced folder (OneDrive, Dropbox)
source .venv/bin/activate
pip install -r requirements.txt
./bin/shikari install  # once: puts `shikari` on your PATH (~/.local/bin)
shikari start      # background, restarted if it crashes
shikari status | shikari logs -f | shikari restart | shikari stop
```

Day-to-day running, start-up options and what Shikari updates when it starts: [Running Shikari](docs/guide/01-running-shikari.md).

## Sign in

Open `http://localhost:32453`.

### Default login

The default administrator is part of the configuration:

```
Email: admin@shikari.app
Password: BigGameHunter
```

Change the password after the first sign-in (Profile → Security). More administrators:

```bash
python scripts/admin/create_admin.py                       # local
docker compose exec shikari python scripts/admin/create_admin.py   # Docker
python scripts/admin/reset_password.py                     # a forgotten password
```

## Tell Shikari about your environment

### SIEMs

Shikari generates for **Google SecOps** (YARA-L 2.0), **Microsoft Defender XDR** (KQL), **Splunk** (SPL) and **Elastic** (ES|QL). Choose yours under **Profile → SIEM platforms**; Shikari generates only for those.

### Mapping files

Query generation reads mapping files from `bespoke/mappings/`: index and table names, field mappings, and which indicators each log source can see. A new install starts with generic ones: at start-up Shikari copies in whatever is missing from `shikari/mappings/defaults/` (Splunk set up for CEF-formatted indexes and sourcetypes; see [its README](shikari/mappings/defaults/README.md)) and never overwrites a file that's there. Replace them with your organisation's own. Those are gitignored, because they describe your estate, so keep a copy somewhere safe.

```
bespoke/mappings/
  indicatorMapping.json
  techniquePlatformIndicators.json
  schemas/   schemaMDE.json, schemaGoogleSecOps.json (and Splunk, Elastic)
  sources/   platforms.json, dataSources.json, entityMappings.json, logSourceCategories.json
```

The server lists any missing file at start-up ("N required bespoke mapping file(s) absent"). The wizard adds your Defender tables and Splunk indexes to the schema overrides:

```bash
python scripts/validation/setup_mappings.py
```

The full layout, and what each file does: [bespoke/README.md](bespoke/README.md) and [BESPOKE.md](docs/BESPOKE.md).

### Organisation settings (recommended)

```bash
cp bespoke/exclusions.yaml.example bespoke/exclusions.yaml   # global exclusions
cp bespoke/config.yaml.example bespoke/config.yaml           # organisation settings
```

Then, in **Profile**:

| Setting | What it changes |
|---|---|
| SIEM platforms | Which SIEMs Shikari generates for |
| Technology stack | Group hunts leave out techniques and procedures for platforms and products you don't run |
| Threat Feed industries | Which posts the Feed shows as relevant |
| API keys | AI providers and models, and the optional OSINT keys |

Details: [Profile and settings](docs/guide/16-profile-and-settings.md).

## First steps

1. **Hunt a group.** Home → Hunt → type a group ("APT29", "Scattered Spider") → **Hunt**. The [Results](docs/guide/06-results.md) page shows the threat briefing, detections per SIEM, correlations, the attack flow and the IOC flow. Save what you want to the [Library](docs/guide/07-library.md).
2. **Analyse a report.** Home → Analyse → a URL or an uploaded PDF, DOCX or text file. Shikari extracts the techniques and IOCs and hunts them ([Analyse](docs/guide/03-analyse.md)).
3. **See your coverage.** Detections → [Coverage](docs/guide/08-coverage.md): the ATT&CK matrix, coloured by reference queries or your own detections.
4. **Check what your logs can see.** Build → [Emulate](docs/guide/19-emulate.md): which logs record each technique, from attacks recorded in labs, and your detections' indicators checked against them.
5. **Watch the news.** Intel → [Feed](docs/guide/10-threat-feed.md): the week's research, tagged for your industries, with watchlists.

Detections are YAML files, one per technique and SIEM. Copy a query into Defender XDR's custom detection rules or a SecOps rule; Results and the Library also export them.

## Without the browser

```bash
shikari console                               # Metasploit-style console
shikari offline generate "APT29" --correlate  # the pipeline, locally
shikari offline correlate "APT29"             # correlations from its detections
shikari offline hunt "PowerShell"             # one technique, by name or ID
```

The console, the Python client, the REST API (live reference at `http://localhost:32453/docs`) and the MCP server: [Console, API and MCP](docs/guide/17-console-api-mcp.md).

## Troubleshooting

| Problem | Fix |
|---|---|
| Can't sign in with the default login | `python scripts/admin/reset_password.py`, or `scripts/admin/create_admin.py` for a new administrator |
| Queries don't match my SIEM's tables or fields | The mapping files (above): start-up names any that are missing |
| Port 32453 in use | `lsof -i :32453`, or `shikari start --port 8001` |
| Docker won't start | `docker compose logs shikari`; rebuild with `docker compose down -v && docker compose up --build` |
| A page shows old data after an update | `shikari restart --skip-index` |

More: the [documentation index](docs/DOCS_INDEX.md), or open an [issue](https://github.com/cmdaltr/shikari/issues).
