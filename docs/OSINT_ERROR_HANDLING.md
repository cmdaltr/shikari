# OSINT Error Handling

This document describes how Archer handles failures when cloning OSINT detection repositories.

## Overview

When Archer starts, it attempts to clone 5 OSINT detection repositories in the background:
- SigmaHQ/sigma
- elastic/detection-rules
- mitre-attack/car
- splunk/security_content
- Azure/Azure-Sentinel

Some repositories (particularly Azure Sentinel at 1.2GB) can timeout on slow connections or take 15-20 minutes on first run.

## User Experience

### 1. Initial Loading Screen

When you first visit Archer, you'll see a loading overlay that shows the real-time status of each OSINT repository:

```
Initializing OSINT Repositories
This may take 15-20 minutes on first run. Subsequent starts will be much faster.

┌─────────────────────────────────────────────────────────┐
│ 🔄 SigmaHQ Detection Rules                              │
│    Cloning...                                            │
├─────────────────────────────────────────────────────────┤
│ 🔄 Elastic Security Rules                               │
│    Cloning...                                            │
├─────────────────────────────────────────────────────────┤
│ ✅ MITRE CAR Analytics                                  │
│    Ready                                                 │
├─────────────────────────────────────────────────────────┤
│ ✅ Splunk Security Content                              │
│    Ready                                                 │
├─────────────────────────────────────────────────────────┤
│ 🔄 Azure Sentinel Detections                            │
│    Cloning...                                            │
└─────────────────────────────────────────────────────────┘
```

**Visual Indicators**:
- 🔄 **Spinner** (animated): Repository is currently being cloned
- ✅ **Checkmark** (green): Repository successfully cloned and ready
- ❌ **Cross** (red): Repository failed to clone

The app polls the `/api/status/osint` endpoint every 2 seconds to update the status in real-time.

### 2. Failure Prompt

If one or more repositories fail to clone (timeout, network error, etc.), the failed repositories show a red cross with the error message, and two action buttons appear:

```
┌─────────────────────────────────────────────────────────┐
│ ✅ SigmaHQ Detection Rules                              │
│    Ready                                                 │
├─────────────────────────────────────────────────────────┤
│ ✅ Elastic Security Rules                               │
│    Ready                                                 │
├─────────────────────────────────────────────────────────┤
│ ✅ MITRE CAR Analytics                                  │
│    Ready                                                 │
├─────────────────────────────────────────────────────────┤
│ ✅ Splunk Security Content                              │
│    Ready                                                 │
├─────────────────────────────────────────────────────────┤
│ ❌ Azure Sentinel Detections                            │
│    Timeout while cloning (repo too large or slow...)    │
└─────────────────────────────────────────────────────────┘

          [Retry]        [Continue]
```

### 3. User Options

**Retry**: Reloads the page to restart the initialization process. Use this if you think the failure was temporary (network issue, etc.).

**Continue**: Accepts the partial initialization and allows you to use Archer with the successfully cloned repositories. The app will function normally but won't include detection queries from the failed repositories.

## Technical Implementation

### Backend (app.py)

**State Tracking**:
```python
app.state.osint_ready = "partial"  # Can be True, False, or "partial"
app.state.osint_status = "⚠️ 4/5 repos ready. Failed: azure_sentinel"
app.state.osint_repos = {
    "sigma": {"status": "ready", "error": None},
    "azure_sentinel": {"status": "failed", "error": "Timeout while cloning..."}
}
app.state.osint_failed_repos = ["azure_sentinel"]
app.state.osint_user_accepted_failures = False
```

**API Endpoints**:

`GET /api/status/osint` - Returns current initialization status:
```json
{
  "ready": "partial",
  "status": "⚠️ 4/5 repos ready. Failed: azure_sentinel",
  "repos": {
    "sigma": {"status": "ready", "error": null},
    "azure_sentinel": {"status": "failed", "error": "Timeout while cloning..."}
  },
  "failed_repos": ["azure_sentinel"],
  "user_accepted_failures": false
}
```

`POST /api/status/osint/accept-failures` - User accepts partial initialization:
```json
{
  "accepted": true,
  "message": "Continuing without failed repositories"
}
```

### Frontend (index.html)

**Status Polling**:
```javascript
async function checkOSINTStatus() {
    const data = await fetch('/api/status/osint').then(r => r.json());

    if (data.ready === true) {
        // All repos ready, hide overlay
        hideLoadingOverlay();
    } else if (data.ready === "partial" && !data.user_accepted_failures) {
        // Some repos failed, show prompt
        showOSINTFailurePrompt(data);
    } else {
        // Still loading, check again in 2 seconds
        setTimeout(checkOSINTStatus, 2000);
    }
}
```

**Failure Prompt**:
- Displays warning icon
- Shows success count (e.g., "4 of 5 repositories")
- Lists all repos with ✅/❌ status and error messages
- Provides two action buttons

## Common Errors

### Timeout while cloning
**Cause**: Repository too large for connection speed, or git operation exceeded 5-minute timeout

**Solutions**:
1. Click "Continue Anyway" to use other repos
2. Click "Retry Later" when network improves
3. For air-gapped environments, manually copy repos from another machine

### Clone failed
**Cause**: Git error, network issue, or insufficient disk space

**Solutions**:
1. Check internet connectivity
2. Ensure sufficient disk space (Azure Sentinel alone is 1.2GB)
3. Check git is installed and accessible

## Air-Gapped Deployments

For environments without internet access:

1. Clone repos on an internet-connected machine:
   ```bash
   python scripts/update_osint_repos.py --force
   ```

2. Copy the entire `data/osint_repos/` directory (approximately 455MB)

3. Transfer to air-gapped environment

4. Place in the same location relative to Archer installation

5. The app will detect existing repos and skip cloning

## Testing

To test the failure prompt:

1. Temporarily reduce timeout in `archer/build/osint_repos.py` (line 126, 143):
   ```python
   timeout=5  # Change from 300 to 5 seconds
   ```

2. Start Archer and visit the web interface

3. The azure_sentinel repo should timeout, triggering the prompt

4. Test both "Continue Anyway" and "Retry Later" buttons

5. Restore original timeout value

## Monitoring

Check initialization status via API:
```bash
curl http://127.0.0.1:8000/api/status/osint | python3 -m json.tool
```

Monitor initialization progress in console logs:
```
🔍 Initializing OSINT detection repositories...
📥 Cloning sigma repository (this may take 10-30 seconds)...
✓ sigma repository ready
📥 Cloning elastic repository (this may take 10-30 seconds)...
✓ elastic repository ready
...
❌ Timeout while updating azure_sentinel
⚠️  OSINT initialization completed with failures: ['azure_sentinel']
```

## Related Files

- [app.py:665-749](../archer/app.py#L665-L749) - Async initialization and API endpoints
- [osint_repos.py:92-163](../archer/build/osint_repos.py#L92-L163) - Clone/update logic with timeout handling
- [index.html:185-281](../templates/index.html#L185-L281) - Loading screen and failure prompt UI
- [OSINT_ENRICHMENT.md](OSINT_ENRICHMENT.md) - OSINT enrichment documentation
- [DOCKER.md](DOCKER.md) - Docker deployment (includes repo initialization)
