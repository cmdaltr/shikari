# Running Archer

Installation (Docker or local Python, mapping files, bespoke settings) is in [GETTING_STARTED.md](../../GETTING_STARTED.md). This page is about running it day to day.

## Start, stop and check

Install the `archer` command once, then use it for everything:

```bash
./archer-cli install      # once: puts `archer` on your PATH (~/bin)
archer start              # start in the background
archer status             # what's running, and on which port
archer logs -f            # follow the log
archer restart            # stop, then start
archer stop               # stop Archer, and the Ollama it started
```

`archer start` runs a small supervisor. It starts the web server and, if Ollama is installed but not running, `ollama serve` too. If either stops, the supervisor starts it again, waiting 1 second at first and up to 60 seconds after repeated failures. It gives up after six failed starts in a row (usually a port already in use).

| Option | What it does | Remembered |
|---|---|---|
| `--port 8000` | The port to serve on | Yes |
| `--no-reload` | Don't restart the server when code changes | Yes |
| `--no-ollama` | Don't start Ollama | Yes |
| `--ollama-models DIR` | Where Ollama keeps its models (an external drive that isn't mounted falls back to Ollama's default folder) | Yes |
| `--skip-index` | Don't rebuild the OSINT technique index first: a faster start | No |

`archer serve` runs the server in the foreground with no supervisor. `archer docker ...` runs `docker compose` with the project's compose file.

## Signing in

Open `http://localhost:8000`. The default administrator is set in the configuration and documented in [GETTING_STARTED.md](../../GETTING_STARTED.md#default-login); change its password after the first sign-in (Profile → Security).

**Continue as Guest** lets someone try Archer without an account. A guest's work isn't saved once the browser closes.

Accounts are created by an administrator (Profile → Users) or by registering at `/register`. Each account can turn on two-factor authentication: see [Profile and settings](15-profile-and-settings.md#security).

## What happens at start-up

Archer brings its data up to date in the background each time it starts. Pages work while this runs.

| What | How |
|---|---|
| MITRE ATT&CK | Checks for a new Enterprise release (a conditional request, cheap when nothing has changed) |
| MITRESaw procedures | Rebuilt for the groups a new ATT&CK release changed |
| OSINT detection repositories | Cloned or updated from upstream |
| LOLBAS, LOLDrivers, LOLRMM | Fetched, at most once a day |
| Threat Feed | Collected on every start (only posts it hasn't seen are fetched); opening the Feed collects again when the last collection is more than six hours old |

Details are in [Data and updates](17-data-and-updates.md).
