# Running Shikari

Installation (Docker or local Python, mapping files, bespoke settings) is in [GETTING_STARTED.md](../../GETTING_STARTED.md). This page is about running it day to day.

## Start, stop and check

Install the `shikari` command once, then use it for everything:

```bash
./bin/shikari install  # once: puts `shikari` on your PATH (~/.local/bin)
# sudo ./bin/shikari install --system   # instead: /usr/local/bin, for all users
shikari start      # start in the background
shikari status     # what's running, and on which port
shikari logs -f    # follow the log
shikari restart    # stop, then start
shikari stop       # stop Shikari, and the Ollama it started
```

`shikari start` runs a small supervisor. It starts the web server and, if Ollama is installed but not running, `ollama serve` too. If either stops, the supervisor starts it again, waiting 1 second at first and up to 60 seconds after repeated failures. It gives up after six failed starts in a row (usually a port already in use).

| Option | What it does | Remembered |
|---|---|---|
| `--port 8000` | The port to serve on | Yes |
| `--no-reload` | Don't restart the server when code changes | Yes |
| `--no-ollama` | Don't start Ollama | Yes |
| `--ollama-models DIR` | Where Ollama keeps its models (an external drive that isn't mounted falls back to Ollama's default folder) | Yes |
| `--skip-index` | Don't rebuild the OSINT technique index first: a faster start | No |

`shikari serve` runs the server in the foreground with no supervisor. `shikari docker ...` runs `docker compose` with the project's compose file.

The same command covers everything else Shikari does from a terminal:

| Command | What it does |
|---|---|
| `shikari console` | The interactive console: [Console, API and MCP](17-console-api-mcp.md) |
| `shikari preview <group>` | A group's queries on stdout, nothing written (`--siem`, `--index`, `--limit`, `--output`) |
| `shikari mcp` | Shikari's tools for an MCP client, over stdio |
| `shikari offline generate\|correlate\|hunt\|emulate` | The pipeline without the server: [USAGE.md](../USAGE.md) |
| `shikari clear-cache` | Clear server-side caches and reset browser preferences |
| `shikari app install\|uninstall\|open` | Shikari as a desktop app (below) |

## As a desktop app

From a checkout, `shikari app install` adds Shikari to Applications on macOS (`--dock` keeps it in the Dock), or to the application menu on Linux. On Windows, run `.venv\Scripts\python shikari\desktop.py install` for Start menu and desktop shortcuts. Opening it starts the server if it isn't running and shows Shikari in its own window; quitting stops a server the app started. `shikari app uninstall` removes it. For a native window rather than a browser one, `pip install -e '.[desktop]'`.

The installers on the Releases page bundle everything instead, and connect to your organisation's server or run Shikari locally: [desktop/README.md](../../desktop/README.md).

## Signing in

Open `http://localhost:8000`. The default administrator is set in the configuration and documented in [GETTING_STARTED.md](../../GETTING_STARTED.md#default-login); change its password after the first sign-in (Profile → Security).

**Continue as Guest** lets someone try Shikari without an account. A guest's work isn't saved once the browser closes.

Accounts are created by an administrator (Profile → Users) or by registering at `/register`. Each account can turn on two-factor authentication: see [Profile and settings](16-profile-and-settings.md#security).

## What happens at start-up

Shikari brings its data up to date in the background each time it starts. Pages work while this runs.

| What | How |
|---|---|
| MITRE ATT&CK | Checks for a new Enterprise release (a conditional request, cheap when nothing has changed) |
| MITRESaw procedures | Rebuilt for the groups a new ATT&CK release changed |
| OSINT detection repositories | Cloned or updated from upstream |
| LOLBAS, LOLDrivers, LOLRMM | Fetched, at most once a day |
| Threat Feed | Collected on every start (only posts it hasn't seen are fetched); opening the Feed collects again when the last collection is more than six hours old |

Details are in [Data and updates](18-data-and-updates.md).
