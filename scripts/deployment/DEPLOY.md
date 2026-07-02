# Deployment Scripts

Scripts for deploying, managing, and maintaining Archer instances.

## Scripts

### docker_entrypoint.py
Docker container entry point that initializes OSINT repositories and starts the web server.

**Usage**: Automatically called by Docker Compose (not meant for manual execution)

**What it does**:
1. Checks if OSINT repositories are initialized
2. Downloads and sets up detection rule repositories if needed:
   - Sigma rules
   - Elastic Detection Rules
   - Splunk Security Content
3. Starts the FastAPI application with Uvicorn

**Docker Compose**:
```yaml
services:
  archer:
    entrypoint: ["python", "scripts/deployment/docker_entrypoint.py"]
    command: ["uvicorn", "archer.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Note**: First run may take 15-20 minutes to download OSINT repositories.

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

**Local Python**:
```bash
git clone https://github.com/cmdaltr/archer.git
cd archer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python scripts/validation/setup_mappings.py
uvicorn archer.app:app --reload
```

### Updates

```bash
# Docker
git pull
docker-compose down
docker-compose up --build

# Local Python
git pull
source venv/bin/activate
pip install -r requirements.txt --upgrade
uvicorn archer.app:app --reload
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
docker-compose up --build  # or uvicorn archer.app:app --reload
```

## Related Documentation

- [Docker Deployment](../../docs/features/DOCKER.md)
- [Getting Started](../../GETTING_STARTED.md)
- [Architecture](../../docs/architecture/ARCHITECTURE.md)
