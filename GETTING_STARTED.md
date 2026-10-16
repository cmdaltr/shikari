# Getting Started with Archer

Installing Archer, signing in, and the configuration it needs before its queries fit your environment. Once it's running, the [user guide](docs/guide/README.md) covers every page.

## Prerequisites

- **Git**: `brew install git` (macOS), `apt install git` (Ubuntu/Debian), or [Git for Windows](https://git-scm.com/download/win).
- **Either** Docker Desktop (includes Compose; WSL2 on Windows) **or** Python 3.11 or later.
- Optional: [Ollama](https://ollama.com) for local AI, or an API key for a cloud model. Archer works without AI.

## Install

```bash
git clone https://github.com/cmdaltr/archer.git
cd archer
```

**Option A: Docker**

```bash
docker compose up --build        # or: archer docker up --build, once the archer command is installed
docker compose down              # stop
```

Data lives in Docker volumes and survives restarts.

**Option B: local Python**

```bash
python3 -m venv .venv            # add --copies if the checkout is in a synced folder (OneDrive, Dropbox)
source .venv/bin/activate
pip install -r requirements.txt
./archer-cli install             # once: puts `archer` on your PATH (~/bin)
archer start                     # background, restarted if it crashes
archer status | archer logs -f | archer restart | archer stop
```

Day-to-day running, start-up options and what Archer updates when it starts: [Running Archer](docs/guide/01-running-archer.md).

## Sign in

Open `http://localhost:8000`.

### Default login

The default administrator is part of the configuration:

```
Email: admin@archer.app
Password: £missary_0f_the_G0rg0nite$
```

Change the password after the first sign-in (Profile → Security). More administrators:

```bash
python scripts/admin/create_admin.py                       # local
docker compose exec archer python scripts/admin/create_admin.py   # Docker
python scripts/admin/reset_password.py                     # a forgotten password
```

## Tell Archer about your environment

### SIEMs

Archer generates for **Google SecOps** (YARA-L 2.0) and **Microsoft Defender XDR** (KQL). Splunk and Elastic generation is switched off for now. Choose yours under **Profile → SIEM platforms**; Archer generates only for those.

### Mapping files (required)

Query generation reads your organisation's mapping files from `bespoke/mappings/`: index and table names, field mappings, and which indicators each log source can see. They're gitignored, because they describe your estate, and the repository can't regenerate them: keep a copy somewhere safe.

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
| SIEM platforms | Which SIEMs Archer generates for |
| Technology stack | Group hunts leave out techniques and procedures for platforms and products you don't run |
| Threat Feed industries | Which posts the Feed shows as relevant |
| API keys | AI providers and models, and the optional OSINT keys |

Details: [Profile and settings](docs/guide/16-profile-and-settings.md).

## First steps

1. **Hunt a group.** Home → Hunt → type a group ("APT29", "Scattered Spider") → **Hunt**. The [Results](docs/guide/06-results.md) page shows the threat briefing, detections per SIEM, correlations, the attack flow and the IOC flow. Save what you want to the [Library](docs/guide/07-library.md).
2. **Analyse a report.** Home → Analyse → a URL or an uploaded PDF, DOCX or text file. Archer extracts the techniques and IOCs and hunts them ([Analyse](docs/guide/03-analyse.md)).
3. **See your coverage.** Detections → [Coverage](docs/guide/08-coverage.md): the ATT&CK matrix, coloured by reference queries or your own detections.
4. **Check what your logs can see.** Build → [Emulate](docs/guide/19-emulate.md): which logs record each technique, from attacks recorded in labs, and your detections' indicators checked against them.
5. **Watch the news.** Intel → [Feed](docs/guide/10-threat-feed.md): the week's research, tagged for your industries, with watchlists.

Detections are YAML files, one per technique and SIEM. Copy a query into Defender XDR's custom detection rules or a SecOps rule; Results and the Library also export them.

## Without the browser

```bash
./adfconsole                                   # Metasploit-style console
python archer.py generate "APT29" --correlate  # the pipeline, locally
python archer.py correlate "APT29"             # correlations from its detections
python archer.py hunt "PowerShell"             # one technique, by name or ID
```

The console, the Python client, the REST API (live reference at `http://localhost:8000/docs`) and the MCP server: [Console, API and MCP](docs/guide/17-console-api-mcp.md).

## Troubleshooting

| Problem | Fix |
|---|---|
| Can't sign in with the default login | `python scripts/admin/reset_password.py`, or `scripts/admin/create_admin.py` for a new administrator |
| Queries don't match my SIEM's tables or fields | The mapping files (above): start-up names any that are missing |
| Port 8000 in use | `lsof -i :8000`, or `archer start --port 8001` |
| Docker won't start | `docker compose logs archer`; rebuild with `docker compose down -v && docker compose up --build` |
| A page shows old data after an update | `archer restart --skip-index` |

More: the [documentation index](docs/DOCS_INDEX.md), or open an [issue](https://github.com/cmdaltr/archer/issues).
