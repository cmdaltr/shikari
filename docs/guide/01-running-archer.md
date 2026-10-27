# Running Archer

Installation (Docker or local Python, mapping files, bespoke settings) is in [GETTING_STARTED.md](../../GETTING_STARTED.md). This page is about running it day to day.

## Start, stop and check

Install the `archer-cli` command once, then use it for everything:

```bash
./archer-cli install  # once: puts `archer-cli` on your PATH (~/bin)
archer-cli start      # start in the background
archer-cli status     # what's running, and on which port
archer-cli logs -f    # follow the log
archer-cli restart    # stop, then start
archer-cli stop       # stop Archer, and the Ollama it started
```

`archer-cli start` runs a small supervisor. It starts the web server and, if Ollama is installed but not running, `ollama serve` too. If either stops, the supervisor starts it again, waiting 1 second at first and up to 60 seconds after repeated failures. It gives up after six failed starts in a row (usually a port already in use).

| Option | What it does | Remembered |
|---|---|---|
| `--port 8000` | The port to serve on | Yes |
| `--no-reload` | Don't restart the server when code changes | Yes |
| `--no-ollama` | Don't start Ollama | Yes |
| `--ollama-models DIR` | Where Ollama keeps its models (an external drive that isn't mounted falls back to Ollama's default folder) | Yes |
| `--skip-index` | Don't rebuild the OSINT technique index first: a faster start | No |

`archer-cli serve` runs the server in the foreground with no supervisor. `archer-cli docker ...` runs `docker compose` with the project's compose file.

The same command covers everything else Archer does from a terminal:

| Command | What it does |
|---|---|
| `archer-cli console` | The interactive console: [Console, API and MCP](17-console-api-mcp.md) |
| `archer-cli preview <group>` | A group's queries on stdout, nothing written (`--siem`, `--index`, `--limit`, `--output`) |
| `archer-cli mcp` | Archer's tools for an MCP client, over stdio |
| `archer-cli offline generate\|correlate\|hunt\|emulate` | The pipeline without the server: [USAGE.md](../USAGE.md) |
| `archer-cli clear-cache` | Clear server-side caches and reset browser preferences |
| `archer-cli app install\|uninstall\|open` | Archer as a desktop app (below) |

## As a desktop app

From a checkout, `archer-cli app install` adds Archer to Applications on macOS (`--dock` keeps it in the Dock), or to the application menu on Linux. On Windows, run `.venv\Scripts\python archer\desktop.py install` for Start menu and desktop shortcuts. Opening it starts the server if it isn't running and shows Archer in its own window; quitting stops a server the app started. `archer-cli app uninstall` removes it. For a native window rather than a browser one, `pip install -e '.[desktop]'`.

The installers on the Releases page bundle everything instead, and connect to your organisation's server or run Archer locally: [desktop/README.md](../../desktop/README.md).

## Signing in

Open `http://localhost:8000`. The default administrator is set in the configuration and documented in [GETTING_STARTED.md](../../GETTING_STARTED.md#default-login); change its password after the first sign-in (Profile → Security).

**Continue as Guest** lets someone try Archer without an account. A guest's work isn't saved once the browser closes.

Accounts are created by an administrator (Profile → Users) or by registering at `/register`. Each account can turn on two-factor authentication: see [Profile and settings](16-profile-and-settings.md#security).

## What happens at start-up

Archer brings its data up to date in the background each time it starts. Pages work while this runs.

| What | How |
|---|---|
| MITRE ATT&CK | Checks for a new Enterprise release (a conditional request, cheap when nothing has changed) |
| MITRESaw procedures | Rebuilt for the groups a new ATT&CK release changed |
| OSINT detection repositories | Cloned or updated from upstream |
| LOLBAS, LOLDrivers, LOLRMM | Fetched, at most once a day |
| Threat Feed | Collected on every start (only posts it hasn't seen are fetched); opening the Feed collects again when the last collection is more than six hours old |

Details are in [Data and updates](18-data-and-updates.md).
