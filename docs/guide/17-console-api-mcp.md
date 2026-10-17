# Console, API and MCP

Everything in the web app can be done without a browser. All three talk to a running Archer server as a user, so they use that user's settings, SIEMs and AI keys.

Sign in with an API token from Profile → Security → API Tokens (works with MFA), or an email and password:

```bash
export ARCHER_URL=http://127.0.0.1:8000
export ARCHER_TOKEN=arch_...
```

## The console (`archer-cli console`)

A Metasploit-style shell: choose a module, set its options, run it. Tab completion works throughout.

```bash
archer-cli console
archer-cli > use hunt/group
archer-cli (hunt/group) > set GROUP Scattered Spider
archer-cli (hunt/group) > show options
archer-cli (hunt/group) > run
```

| Module | What it does |
|---|---|
| `hunt/group` | Hunt a threat group as the web app does (OSINT, LOL, AI, correlations, briefing) |
| `hunt/cve` | Hunt a CVE: exploitation detections plus IOC sweeps |
| `hunt/technique` | Hunt ATT&CK techniques across every group that uses them |
| `intel/report` | Extract TTPs and IOCs from a report (URL or file) and hunt them |
| `intel/company` | Profile a company and hunt the groups that target it |
| `intel/feed` | This week's Threat Feed |
| `research/actors` | Find groups by keyword and consolidate their techniques |
| `results` | Show a run's detections, correlations and IOC flow; save them as a zip |
| `ai/ask`, `ai/briefing`, `ai/settings` | Ask Archer, a threat briefing, and the AI assignment |
| `agent/repair`, `agent/ask`, `agent/triage`, `agent/history` | The [agents](15-agents-and-ask-archer.md) |
| `generate`, `correlate`, `hunt` | Run the pipeline locally, without the server |
| `emulate` | Adversary emulation (coming soon) |

The hunt modules share options: `CORRELATE`, `LOL` (on), `OSINT`, `OSINT_COMPARE`, `MERGE_BY_TACTIC`, `MERGE_BY_PARENT`, `EXCLUDE` (SIEMs to leave out), `VALIDATE`, and `PROVIDER`/`MODEL` for AI. `show options` lists each module's own.

## Python client

`archer.client.ArcherClient` is what the console and MCP server use; use it in your own scripts.

```python
from archer.client import ArcherClient

c = ArcherClient()                                   # reads ARCHER_URL and ARCHER_TOKEN
run = c.hunt_group("APT29", provider="", lol=True, osint=True)
c.wait(run)
for d in c.results(run)["detections"]:
    print(d["name"], [q["platform"] for q in d["queries"]])
```

Other methods include `hunt_cve`, `hunt_techniques`, `analyse_url`, `analyse_file`, `generate_from_extraction`, `profile_company`, `hunt_company`, `actors_by_keyword`, `actor_techniques`, `feed`, `threat_briefing`, `ask`, `search_library` and `download_all`.

## REST API

Every page works through the HTTP API. The full, live reference is at `http://localhost:8000/docs`. Worked examples are in [API_INTEGRATION_GUIDE.md](../features/API_INTEGRATION_GUIDE.md).

## MCP server (`archer-cli mcp`)

Gives any MCP client (Claude Code, Claude Desktop, your own agent) Archer's tools and the three agents' instructions as prompts. Tools that change something are marked so the client asks first. Your AI keys stay on the Archer server.

```bash
claude mcp add archer --env ARCHER_TOKEN=arch_... -- archer-cli mcp
```

## Recorded telemetry

The [Emulate](19-emulate.md) page's data from the command line:

```bash
python -m archer.telemetry                             # what's built
python -m archer.telemetry --build                     # fetch what the sources changed
python -m archer.telemetry --build --source lab        # only your lab's runs (or splunk, otrf, evtx, macos)
python -m archer.telemetry --guide <GUIDE zip>         # Defender XDR alerting per technique
python -m archer.telemetry --mde-export data/telemetry/lab/<run>   # Coming soon: a lab run's Defender rows
```

Its API is under `/api/telemetry` (`/status`, `/techniques`, `/technique/{id}`, `/data-sources`, `/search`, `/check?group=`), with `collections` and `platforms` parameters.
