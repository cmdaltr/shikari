# Console, API and MCP

Everything in the web app can be done without a browser. All three talk to a running Shikari server as a user, so they use that user's settings, SIEMs and AI keys.

Sign in with an API token from Profile → Security → API Tokens (works with MFA), or an email and password:

```bash
export SHIKARI_URL=http://127.0.0.1:32453
export SHIKARI_TOKEN=shik_...
```

## The console (`shikari console`)

A Metasploit-style shell: choose a module, set its options, run it. Tab completion works throughout.

```bash
shikari console
shikari > use hunt/group
shikari (hunt/group) > set GROUP Scattered Spider
shikari (hunt/group) > show options
shikari (hunt/group) > run
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
| `ai/ask`, `ai/briefing`, `ai/settings` | Ask Shikari, a threat briefing, and the AI assignment |
| `agent/repair`, `agent/ask`, `agent/triage`, `agent/sweep`, `agent/audit`, `agent/tune`, `agent/history` | The [agents](15-agents-and-ask-shikari.md) |
| `generate`, `correlate`, `hunt` | Run the pipeline locally, without the server |
| `lab/caldera` | Plan, run, collect and check CALDERA operations ([Emulate → Lab](25-caldera.md)); talks to your CALDERA server directly |
| `emulate` | Adversary emulation — the Atomic Red Team recorder (coming soon) |

The hunt modules share options: `CORRELATE`, `LOL` (on), `OSINT`, `OSINT_COMPARE`, `MERGE_BY_TACTIC`, `MERGE_BY_PARENT`, `EXCLUDE` (SIEMs to leave out), `VALIDATE`, and `PROVIDER`/`MODEL` for AI. `show options` lists each module's own.

Provisioning and enrolling CALDERA agents has its own top-level command, `shikari caldera provision|enrol|list` — the CLI half of the web **+ Add agent** flow, sharing the same backend naming and group convention ([CALDERA](25-caldera.md)).

## Python client

`shikari.client.ShikariClient` is what the console and MCP server use; use it in your own scripts.

```python
from shikari.client import ShikariClient

c = ShikariClient()                                   # reads SHIKARI_URL and SHIKARI_TOKEN
run = c.hunt_group("APT29", provider="", lol=True, osint=True)
c.wait(run)
for d in c.results(run)["detections"]:
    print(d["name"], [q["platform"] for q in d["queries"]])
```

Other methods include `hunt_cve`, `hunt_techniques`, `analyse_url`, `analyse_file`, `generate_from_extraction`, `profile_company`, `hunt_company`, `actors_by_keyword`, `actor_techniques`, `feed`, `threat_briefing`, `ask`, `search_library` and `download_all`.

## REST API

Every page works through the HTTP API. The full, live reference is at `http://localhost:32453/docs`. Worked examples are in [API_INTEGRATION_GUIDE.md](../features/API_INTEGRATION_GUIDE.md).

## MCP server (`shikari mcp`)

Gives any MCP client (Claude Code, Claude Desktop, your own agent) Shikari's tools and the six agents' instructions as prompts. Tools that change something are marked so the client asks first. Your AI keys stay on the Shikari server.

A running Shikari server answers MCP itself at `/mcp`, so a client needs no Shikari install: send an API token (Profile → Security → API tokens) and every call runs as that token's owner. Without a valid token the endpoint answers 401.

```bash
claude mcp add --transport http shikari https://<your-shikari-host>/mcp \
  --header "Authorization: Bearer shik_..."
```

Or locally over stdio, from a checkout:

```bash
claude mcp add shikari --env SHIKARI_TOKEN=shik_... -- shikari mcp
```

## Recorded telemetry

The [Emulate](19-emulate.md) page's data from the command line:

```bash
python -m shikari.telemetry                             # what's built
python -m shikari.telemetry --build                     # fetch what the sources changed
python -m shikari.telemetry --build --source lab        # only your lab's runs (or splunk, otrf, evtx, macos)
python -m shikari.telemetry --guide <GUIDE zip>         # Defender XDR alerting per technique
python -m shikari.telemetry --mde-export data/telemetry/lab/<run>   # Coming soon: a lab run's Defender rows
```

Its API is under `/api/telemetry` (`/status`, `/techniques`, `/technique/{id}`, `/data-sources`, `/search`, `/check?group=`), with `collections` and `platforms` parameters.
