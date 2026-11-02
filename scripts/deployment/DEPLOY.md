# Deployment Scripts

Scripts for deploying, managing, and maintaining Shikari instances.

## Scripts

### shikari-cli start / stop / restart / status / logs
Bare-metal process management, no Docker required. Stdlib only. `./shikari-cli install` links `shikari-cli` into `~/bin`; the work is in `shikari/service.py`.

**Usage**:
```bash
shikari-cli start [--port PORT] [--no-reload] [--no-ollama] [--ollama-models DIR] [--skip-index]
shikari-cli stop [--force]
shikari-cli restart
shikari-cli status
shikari-cli logs [shikari|ollama|supervisor] [-f]
```

**What they do**:
- `shikari-cli start` launches a supervisor in the background. Its pid file, state and remembered options (`supervisor.pid`, `service.json`, `settings.json`) live in `~/Library/Application Support/Shikari` on macOS (`$XDG_STATE_HOME/shikari/run` on Linux, or `$SHIKARI_STATE_DIR/run`), and logs in `~/Library/Logs/Shikari` (`shikari-cli logs`). They are kept out of the repository because a synced folder such as OneDrive replaces files that are open for writing, which killed the server and the supervisor. It runs uvicorn with `.venv/bin/python`, bound to `0.0.0.0:8000` so reverse proxies (e.g. Caddy via `host.docker.internal`) reach it, and restarts it if it exits: after 1s, backing off to 60s for repeated quick failures, giving up after 6 in a row. If Ollama is installed and nothing answers on port 11434, it also runs `ollama serve` (with `--ollama-models` as `OLLAMA_MODELS`) and restarts that too. Options are remembered in `settings.json` there.
- Before the first start it rebuilds the OSINT technique index (`scripts/data/build_osint_index.py --skip-clone`) if `data/cache/osint_technique_index.json` is missing or more than 24 hours old; `--skip-index` skips it. This only re-indexes what's on disk, and a failure is non-fatal.
- `shikari-cli stop` stops the supervisor, which stops what it started. `--force` also stops an Shikari on the port that was started some other way (matched on `shikari.app` in its command line).
- `shikari-cli status` shows what's running, uptime, crash restarts, and whether `/health` answers.
- `start-shikari.py`, `stop-shikari.py`, `restart-shikari.py` and `status-shikari.py` remain as wrappers for older instructions: `start-shikari.py -b` is `shikari-cli start`, without `-b` it supervises in the foreground (`shikari-cli run`).

**Note**: If your checkout lives inside a OneDrive/Dropbox-synced folder, build the venv with `--copies` (`python3 -m venv --copies .venv`) rather than the default symlink-based venv — cloud-sync clients can flatten venv symlinks into plain text files, breaking `.venv/bin/python3`.

---

### Desktop clients

The desktop installers (`desktop/README.md`; compared with the other ways to run Shikari in `docs/architecture/deployment-comparison.svg`) connect to a central Shikari as clients: a window onto this server, with its users and data. Serve it over HTTPS with a certificate the client machines trust (an internal CA works once deployed to them), then give users the address or set it centrally: an MDM profile for `com.cmdaltr.shikari` with `ServerURL` on macOS, `HKLM\SOFTWARE\Policies\cmdaltr\Shikari\ServerURL` by Group Policy or Intune on Windows, `/etc/shikari/client.json` on Linux. The app checks `/health`, which answers `{"status": "ok", "app": "shikari"}`, before opening it.

---

### docker_entrypoint.py
Docker container entry point that initializes OSINT repositories and starts the web server.

**Usage**: Automatically called by Docker Compose (not meant for manual execution)

**What it does**:
1. Checks if OSINT repositories are initialized
2. Downloads and sets up detection rule repositories if needed:
   - Elastic Detection Rules
   - Splunk Security Content
   - Azure Sentinel / MDE rules
3. Starts the FastAPI application with Uvicorn

**Docker Compose**:
```yaml
services:
  shikari:
    entrypoint: ["python", "scripts/deployment/docker_entrypoint.py"]
    command: ["uvicorn", "shikari.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Note**: First run may take 15-20 minutes to download OSINT repositories. The Azure Sentinel clone in particular needs a long timeout — if a run is killed mid-clone, delete the partial `data/repos/azure_sentinel/` directory before retrying rather than leaving a corrupted `.git` dir in place.

---

### start_clean.py
Start Shikari with a clean database (removes all existing data).

**Usage**:
```bash
python scripts/deployment/start_clean.py
```

**Warning**: This script:
- ⚠️ Deletes the existing database
- ⚠️ Removes all users, detections, and correlations
- ⚠️ Creates a fresh database with default admin account

**Use cases**:
- Development/testing
- Recovering from database corruption
- Starting fresh after major upgrades

**Default admin account** (after clean start):
```
Email: admin@shikari.app
Password: BigGameHunter
```

---

### kill-shikari.py
Forcefully stop all Shikari processes.

**Usage**:
```bash
python scripts/deployment/kill-shikari.py
```

**What it does**:
- Finds all running Shikari/Uvicorn processes
- Terminates them
- Useful when graceful shutdown fails

**Alternatives**:
```bash
# Docker
docker-compose down

# systemd
sudo systemctl stop shikari

# Manual process kill
ps aux | grep uvicorn
kill <pid>
```

---

## Deployment Workflows

### Initial Deployment

**Docker (Recommended)**:
```bash
git clone https://github.com/cmdaltr/shikari.git
cd shikari
docker-compose up --build
```

**Local Python (bare-metal)**:
```bash
git clone https://github.com/cmdaltr/shikari.git
cd shikari
python3 -m venv .venv          # add --copies if this checkout is inside a synced (OneDrive/Dropbox) folder
source .venv/bin/activate
pip install -r requirements.txt
python scripts/validation/setup_mappings.py
shikari-cli start
```

Requires Python 3.11 or 3.12. `requirements.txt` pins `torch==2.2.2` for macOS x86_64 (Intel) wheel compatibility — PyTorch dropped Intel Mac wheel builds after that release, and none of the newer releases have a matching wheel for Python 3.13+ on Intel Macs either.

### Updates

```bash
# Docker
git pull
docker-compose down
docker-compose up --build

# Local Python
git pull
source .venv/bin/activate
pip install -r requirements.txt --upgrade
shikari-cli restart
```

### Clean Restart

```bash
# Stop Shikari
python scripts/deployment/kill-shikari.py  # or docker-compose down

# Clean start
python scripts/deployment/start_clean.py

# Reconfigure
python scripts/validation/setup_mappings.py

# Start
docker-compose up --build  # or shikari-cli start
```

## Troubleshooting

**Reachable at `127.0.0.1:8000` but not via a reverse proxy / hostname (e.g. FlightDeck's `shikari.lab`)**: `shikari-cli start` binds to `0.0.0.0` by default so this shouldn't happen on current versions — but if you're running uvicorn manually, make sure you pass `--host 0.0.0.0`, not `--host 127.0.0.1`. Reverse proxies running in Docker (Caddy via `host.docker.internal`, etc.) connect via a gateway interface, not literal loopback, so a loopback-only bind rejects the connection even though direct `127.0.0.1` access works fine.

**`pip install -r requirements.txt` fails with a `torch` dependency conflict on macOS**: you're likely on an Intel Mac with a Python version newer than 3.12. Install Python 3.11 or 3.12 (`brew install python@3.11`) and rebuild the venv with that interpreter — `torch==2.2.2` (the last Intel-mac-compatible release, pinned in `requirements.txt`) doesn't have wheels for Python 3.13+.

**`.venv/bin/python3` exists but `shikari-cli start` fails with `Exec format error`**: the venv's interpreter binary/symlink got corrupted, typically by a cloud-sync client (OneDrive, Dropbox) rewriting it. Rebuild with `python3 -m venv --copies .venv` to avoid symlinks entirely.

## Related Documentation

- [Docker Deployment](../../docs/features/DOCKER.md)
- [Getting Started](../../GETTING_STARTED.md)
- [Architecture](../../docs/architecture/ARCHITECTURE.md)
