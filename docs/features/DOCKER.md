# Docker Deployment Guide

This guide explains how to run Archer using Docker and Docker Compose.

## Quick Start

```bash
# Build and start the containers
docker-compose up --build

# Or run in detached mode
docker-compose up -d --build

# View logs
docker-compose logs -f archer

# Stop containers
docker-compose down
```

## First Run Behavior

### OSINT Repository Initialization

On **first run**, Archer will clone 4 OSINT detection repositories (~425MB total):

- Elastic Security (106MB)
- Splunk Security Content (58MB)
- Azure Sentinel (256MB) ⚠️ **Takes 10-15 minutes**

**Total time:** 15-20 minutes

### What Happens:

1. Container starts
2. `scripts/docker_entrypoint.py` (cross-platform Python script) checks if repos exist
3. If not found → clones all repos
4. App starts after repos are ready

**Note:** The entrypoint uses Python instead of shell scripts for Windows compatibility.

### Progress Indication:

```bash
# Watch the initialization process
docker-compose logs -f archer

# You'll see:
🔍 OSINT repositories not found. Initializing...
This will take 15-20 minutes on first run.

📦 Elastic Security Detection Rules
📥 Cloning repository...
✓ Cloned in 11.4 seconds

# ... etc ...

✅ OSINT repositories initialized successfully!
🚀 Starting Archer application...
```

## Subsequent Runs

After first run, repos are **persisted** in the Docker volume:

```bash
docker-compose up

# Output:
✅ OSINT repositories already present, skipping clone.
🚀 Starting Archer application...
# App starts in seconds!
```

## Data Persistence

### Volume Mounts

```yaml
volumes:
  - ./data:/app/data  # Persists OSINT repos, database, drafts
```

### What's Persisted:

- ✅ OSINT repositories (`data/osint_repos/`)
- ✅ User database (`data/archer.db`)
- ✅ Draft detections (`data/drafts/`)
- ✅ Generated YAML files (`data/build/`)
- ✅ OSINT cache (`data/osint_cache/`)

### Important:

**Do NOT delete** `data/osint_repos/` unless you want to re-clone (15-20 minutes)

## Accessing the Application

Once started, Archer is available at:

- **Web UI:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs

### Web Interface Loading

The web interface will show a loading screen while OSINT repos are initializing:

```
Initializing Archer
Cloning detection repositories (this may take 15-20 minutes on first run)...

This may take 15-20 minutes on first run while detection
repositories are cloned. Subsequent starts will be much faster.
```

Once ready, the loading screen disappears automatically.

## Rebuilding the Container

### After Code Changes:

```bash
# Rebuild the image
docker-compose build

# Restart with new image
docker-compose up
```

### Clean Rebuild:

```bash
# Stop and remove containers
docker-compose down

# Remove old images
docker-compose build --no-cache

# Start fresh
docker-compose up
```

## Troubleshooting

### Container Exits Immediately

**Check logs:**
```bash
docker-compose logs archer
```

**Common issues:**
- Port 8000 already in use
- Missing dependencies in requirements.txt
- Python syntax errors

### OSINT Repos Keep Re-cloning

**Problem:** Repos clone every time container starts

**Solution:** Ensure `./data` volume is mounted correctly:
```yaml
volumes:
  - ./data:/app/data  # Check this is present in docker-compose.yml
```

### Slow First Start

**This is normal!** Cloning 455MB of repos takes 15-20 minutes.

**Speed it up:**
- Use fast internet connection
- Pre-clone repos on host: `python scripts/update_osint_repos.py`
- Repos in `./data/osint_repos/` will be used by container

### Out of Disk Space

**OSINT repos require:**
- Repositories: ~455MB
- Docker image: ~500MB
- Total: ~1GB minimum

**Check disk space:**
```bash
df -h
docker system df
```

**Clean up Docker:**
```bash
docker system prune -a
```

## Pre-Loading OSINT Repos (Optional)

To avoid 15-20 minute wait on first Docker run:

```bash
# On your host machine, clone repos first
python scripts/update_osint_repos.py

# Now when you start Docker, repos are already there!
docker-compose up
# ✅ OSINT repositories already present, skipping clone.
```

## Advanced: Build-Time Cloning

To clone repos during Docker **build** (not runtime):

```dockerfile
# Add to Dockerfile after COPY commands:
RUN python scripts/update_osint_repos.py --force
```

**Pros:** Image includes repos, no wait on container start
**Cons:** Image is 455MB larger, rebuilds take longer

## Environment Variables

Set in `docker-compose.yml`:

```yaml
environment:
  - PYTHONUNBUFFERED=1           # Real-time logging
  - DRAFT_MAX_AGE_DAYS=30        # Auto-clean old drafts
  # Add custom variables here
```

## Production Deployment

### Recommendations:

1. **Use persistent volumes**
   ```yaml
   volumes:
     - archer-data:/app/data  # Named volume instead of bind mount
   ```

2. **Remove --reload flag**
   ```dockerfile
   CMD ["uvicorn", "archer.app:app", "--host", "0.0.0.0", "--port", "8000"]
   ```

3. **Add health check**
   ```yaml
   healthcheck:
     test: ["CMD", "curl", "-f", "http://localhost:8000/api/status/osint"]
     interval: 30s
     timeout: 10s
     retries: 3
   ```

4. **Use reverse proxy (nginx)**
   ```yaml
   services:
     nginx:
       image: nginx
       ports:
         - "80:80"
         - "443:443"
       volumes:
         - ./nginx.conf:/etc/nginx/nginx.conf
   ```

## Multi-Platform Support

The Docker image works on:
- ✅ Linux (amd64, arm64)
- ✅ macOS (Intel, Apple Silicon)
- ✅ Windows (with WSL2)

## Updating Archer

```bash
# Pull latest code
git pull

# Rebuild and restart
docker-compose up --build

# OSINT repos will auto-update if >1 hour old
```

## Support

For issues:
- Check logs: `docker-compose logs -f archer`
- Verify mounts: `docker-compose config`
- Test locally: `python -m uvicorn archer.app:app`

## Summary

| Aspect | Details |
|--------|---------|
| **First run** | 15-20 minutes (clones OSINT repos) |
| **Subsequent runs** | Seconds (repos already present) |
| **Disk space** | ~1GB total |
| **Ports** | 8000 (Archer) |
| **Data persistence** | `./data` volume |
| **OSINT update** | Automatic (hourly check) |

Archer is ready when you see: `🚀 Starting Archer application...`

---

## Detection Validation Containers

The **Validate** tab uses additional Docker containers to test detection queries against sample events. These are ephemeral containers that start on-demand when you run validation.

### Available SIEM Containers

| SIEM | Image | Ports | RAM Required |
|------|-------|-------|--------------|
| **Splunk** | `splunk/splunk:latest` | 8000, 8089, 8088 | ~2GB |
| **Elasticsearch** | `docker.elastic.co/elasticsearch/elasticsearch:8.x` | 9200 | ~2GB |
| **Google SecOps Simulator** | Custom Python app | 8081 | ~256MB |
| **MDE Simulator** | Custom Python app | 8082 | ~256MB |

### Docker Compose for Validation

The validation containers are integrated into the main `docker-compose.yml` file. All SIEM services are optional and can be started individually or in combination.

### Usage

**Default startup** (Archer only):
```bash
docker-compose up -d
```

**Start specific SIEMs** (combine as needed):
```bash
# Single SIEM
docker-compose --profile secops up -d
docker-compose --profile mde up -d
docker-compose --profile splunk up -d
docker-compose --profile elastic up -d

# Multiple SIEMs
docker-compose --profile secops --profile mde up -d
docker-compose --profile splunk --profile elastic up -d

# All SIEMs
docker-compose --profile validation up -d
```

### Available Services

| Service | Profile | Ports | RAM |
|---------|---------|-------|-----|
| Archer | (always) | 8000 | - |
| Google SecOps | `secops` | 8081 | ~512MB |
| MDE | `mde` | 8082 | ~512MB |
| Splunk | `splunk` | 8001, 8088, 8089 | ~2GB |
| Elasticsearch | `elastic` | 9200 | ~1GB |

### Container Management

```bash
# View all running containers
docker-compose ps

# View validation container logs
docker-compose logs -f secops-simulator mde-simulator

# Stop all containers
docker-compose down
```

### Port Conflicts

If you're running Splunk or Elasticsearch locally, validation containers may conflict. Use port offsets:

```python
# In validation session
orchestrator.start_siem(session_id, port_offset=100)
# Splunk will use 8100, 8189, 8188 instead
```

### Resource Recommendations

For validation testing:
- **Minimum**: 4GB RAM (1 SIEM at a time)
- **Recommended**: 8GB RAM (multiple SIEMs)
- **Disk**: 2GB free space per SIEM

### Related Documentation

- [Runtime Validation Guide](RUNTIME_VALIDATION.md) - Complete validation feature documentation
