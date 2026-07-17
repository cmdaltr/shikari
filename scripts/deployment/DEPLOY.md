# Deployment Scripts

Scripts for deploying, managing, and maintaining Archer instances.

## Scripts

### start-archer.py / stop-archer.py / restart-archer.py / status-archer.py
Bare-metal process management — no Docker required. Stdlib only.

**Usage**:
```bash
python3 scripts/deployment/start-archer.py [-b|--background] [-p|--port PORT]
python3 scripts/deployment/stop-archer.py
python3 scripts/deployment/restart-archer.py [-b|--background]
python3 scripts/deployment/status-archer.py
```

**What they do**:
- `start-archer.py` uses `.venv/bin/python3` if present, otherwise falls back to the interpreter running the script. Binds to `0.0.0.0:8000` by default so the app is reachable from other machines and from reverse proxies (e.g. Caddy via `host.docker.internal`) — not just `127.0.0.1`.
- `stop-archer.py` finds and terminates running Archer/Uvicorn processes by matching the process command line. If Archer is run alongside other tools (Docker Desktop/OrbStack helpers, other Python services), double-check its output before trusting a "stopped" process was actually Archer.
- `restart-archer.py` is `stop` then `start`.
- `status-archer.py` reports whether a matching process is running and whether the port responds.

**Note**: If your checkout lives inside a OneDrive/Dropbox-synced folder, build the venv with `--copies` (`python3 -m venv --copies .venv`) rather than the default symlink-based venv — cloud-sync clients can flatten venv symlinks into plain text files, breaking `.venv/bin/python3`.

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
  archer:
    entrypoint: ["python", "scripts/deployment/docker_entrypoint.py"]
    command: ["uvicorn", "archer.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Note**: First run may take 15-20 minutes to download OSINT repositories. The Azure Sentinel clone in particular needs a long timeout — if a run is killed mid-clone, delete the partial `data/osint_repos/azure_sentinel/` directory before retrying rather than leaving a corrupted `.git` dir in place.

---

### start_clean.py
Start Archer with a clean database (removes all existing data).

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
Email: admin@archer.app
Password: £missary_0f_the_G0rg0nite$
```

---

### kill-archer.py
Forcefully stop all Archer processes.

**Usage**:
```bash
python scripts/deployment/kill-archer.py
```

**What it does**:
- Finds all running Archer/Uvicorn processes
- Terminates them
- Useful when graceful shutdown fails

**Alternatives**:
```bash
# Docker
docker-compose down

# systemd
sudo systemctl stop archer

# Manual process kill
ps aux | grep uvicorn
kill <pid>
```

---

## Deployment Workflows

### Initial Deployment

**Docker (Recommended)**:
```bash
git clone https://github.com/cmdaltr/archer.git
cd archer
docker-compose up --build
```

**Local Python (bare-metal)**:
```bash
git clone https://github.com/cmdaltr/archer.git
cd archer
python3 -m venv .venv          # add --copies if this checkout is inside a synced (OneDrive/Dropbox) folder
source .venv/bin/activate
pip install -r requirements.txt
python scripts/validation/setup_mappings.py
python3 scripts/deployment/start-archer.py --background
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
python3 scripts/deployment/restart-archer.py --background
```

### Clean Restart

```bash
# Stop Archer
python scripts/deployment/kill-archer.py  # or docker-compose down

# Clean start
python scripts/deployment/start_clean.py

# Reconfigure
python scripts/validation/setup_mappings.py

# Start
docker-compose up --build  # or python3 scripts/deployment/start-archer.py --background
```

## Troubleshooting

**Reachable at `127.0.0.1:8000` but not via a reverse proxy / hostname (e.g. FlightDeck's `archer.lab`)**: `start-archer.py` binds to `0.0.0.0` by default so this shouldn't happen on current versions — but if you're running uvicorn manually, make sure you pass `--host 0.0.0.0`, not `--host 127.0.0.1`. Reverse proxies running in Docker (Caddy via `host.docker.internal`, etc.) connect via a gateway interface, not literal loopback, so a loopback-only bind rejects the connection even though direct `127.0.0.1` access works fine.

**`pip install -r requirements.txt` fails with a `torch` dependency conflict on macOS**: you're likely on an Intel Mac with a Python version newer than 3.12. Install Python 3.11 or 3.12 (`brew install python@3.11`) and rebuild the venv with that interpreter — `torch==2.2.2` (the last Intel-mac-compatible release, pinned in `requirements.txt`) doesn't have wheels for Python 3.13+.

**`.venv/bin/python3` exists but `start-archer.py` fails with `Exec format error`**: the venv's interpreter binary/symlink got corrupted, typically by a cloud-sync client (OneDrive, Dropbox) rewriting it. Rebuild with `python3 -m venv --copies .venv` to avoid symlinks entirely.

## Related Documentation

- [Docker Deployment](../../docs/features/DOCKER.md)
- [Getting Started](../../GETTING_STARTED.md)
- [Architecture](../../docs/architecture/ARCHITECTURE.md)
