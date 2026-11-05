# Using Shikari

Where each task is done, and the command-line tools. Each page of the web app has its own page in the [user guide](guide/README.md); this is the map.

## In the browser

The menu bar has three menus (Detections, Intel, Build), then Profile and Help. The Home page has four tabs.

| To | Go to | Guide |
|---|---|---|
| Hunt a threat group, CVE or ATT&CK techniques | Home → Hunt | [Hunt](guide/02-hunt.md) |
| Get detections from a report (URL or file) | Home → Analyse | [Analyse](guide/03-analyse.md) |
| Find the groups likely to target a company | Home → Profile | [Company profile](guide/04-company-profile.md) |
| Find groups by keyword and compare their techniques | Home → Research | [Research](guide/05-research.md) |
| Read a run's detections, correlations, attack flow, IOC flow and briefing | Opens after a run | [Results](guide/06-results.md) |
| Keep, search, tag and export detections | Detections → Library | [Library](guide/07-library.md) |
| See coverage across ATT&CK | Detections → Coverage | [Coverage](guide/08-coverage.md) |
| See every saved attack flow | Detections → Flows | [Flows](guide/09-flows.md) |
| Read this week's research; watchlists | Intel → Feed | [Threat Feed](guide/10-threat-feed.md) |
| See national cyber capability and targeting | Intel → Cyber Powers | [Cyber Powers](guide/11-cyber-powers.md) |
| Browse ATT&CK procedures and their indicators | Intel → MITRESaw | [MITRESaw](guide/12-mitresaw.md) |
| Write detections from your own TTPs | Build → Manual | [Manual](guide/13-manual.md) |
| Test a regex for a SIEM | Build → Regex | [Regex](guide/14-regex.md) |
| See which logs record each technique; check detections against recorded attacks | Build → Emulate | [Emulate](guide/19-emulate.md) |
| Ask questions; repair queries; triage a report | Build → Agents; the chat button | [Agents and Ask Shikari](guide/15-agents-and-ask-shikari.md) |
| Set SIEMs, technology stack, industries, keys, MFA | Profile | [Profile and settings](guide/16-profile-and-settings.md) |

Running atomics from Shikari itself (**Run Emulation** on Results, `shikari offline emulate`) is **Coming soon**; for now, [record a lab](guide/20-recording-a-lab.md) on your own machines.

## The console, client, API and MCP server

`shikari console`, the Python client (`shikari.client.ShikariClient`), the REST API (live reference at `http://localhost:8000/docs`) and `shikari mcp` all drive a running server as a user: [Console, API and MCP](guide/17-console-api-mcp.md). Worked API examples: [API_INTEGRATION_GUIDE.md](features/API_INTEGRATION_GUIDE.md).

## `shikari offline`: the pipeline without the server

```bash
shikari offline generate "APT29"                     # detections for a group into data/groups
shikari offline generate "APT29" --correlate         # then correlate them
shikari offline generate "APT29" --llm               # with the bespoke prompts and your AI provider (Mode 1)
shikari offline generate "APT29" --no-llm            # template-based fallback (Mode 2)
shikari offline generate "APT29" --hypothesis "..."  # an optional hypothesis for the group
shikari offline correlate "APT29"                    # correlations from the group's detections in data/groups
shikari offline correlate "APT29" --yaml-dir DIR --output FILE --min-queries 2 --max-queries 6 -v
shikari offline hunt "PowerShell"  # a technique by name (partial match) or ID
shikari offline emulate T1059.001  # Coming soon
```

## Recorded telemetry

```bash
python -m shikari.telemetry                             # what's built
python -m shikari.telemetry --build                     # fetch what the sources changed (first run ~1.2 GB)
python -m shikari.telemetry --build --source lab        # just your lab's runs
python -m shikari.telemetry --guide <GUIDE zip>         # Defender XDR alerting per technique (Microsoft GUIDE)
python -m shikari.telemetry --mde-export data/telemetry/lab/<run>   # Coming soon: Defender's rows for a lab run
```

See [Emulate](guide/19-emulate.md) and [Recording a lab](guide/20-recording-a-lab.md).
