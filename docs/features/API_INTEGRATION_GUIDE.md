# Archer API Integration Guide

**Version**: 2.1
**Last Updated**: 2025-03-04
**Base URL**: `http://localhost:8000` (default)

---

## Overview

The Archer API provides programmatic access to automated threat detection generation, MITRE ATT&CK intelligence processing, and security detection management.

### What You Can Build

- **SIEM Integrations**: Auto-generate detections for Splunk, Microsoft Defender, Elastic
- **Threat Intelligence Pipelines**: Process CVEs and threat reports into detections
- **Purple Team Automation**: Automated detection coverage for threat actor TTPs
- **Security Orchestration**: Custom workflows for detection management

### Key Features

✅ Generate production-ready detection queries from threat intelligence
✅ Upload and analyze threat reports (PDF, TXT, DOCX, etc.)
✅ Profile organizations and identify relevant threat actors
✅ Manage detection libraries with sharing and tagging
✅ Track generation progress in real-time
✅ Export detections in multiple formats (YAML, JSON, ZIP)

---

## Quick Start (5 Minutes)

### Prerequisites

- Archer instance running (default: `http://localhost:8000`)
- User account created
- Python 3.11 required (torch==2.2.2 in requirements.txt caps compatibility at 3.11) or Node.js 14+ (for examples)

### Your First API Call

```python
import requests

# 1. Create session
session = requests.Session()

# 2. Login
response = session.post(
    'http://localhost:8000/login',
    data={
        'email': 'your_email@example.com',
        'password': 'your_password'
    }
)

# 3. Generate detections for a threat group
generate_response = session.post(
    'http://localhost:8000/generate',
    data={'group_name': 'APT29'}
)

print(f"Started generation: {generate_response.json()['redirect']}")
```

That's it! Archer is now generating detections for APT29.

---

## Authentication & Security

### Session-Based Authentication

Archer uses session-based authentication with secure HTTP-only cookies.

#### Login Flow

```python
import requests

session = requests.Session()

# Login
login_response = session.post(
    'http://localhost:8000/login',
    data={
        'email': 'user@example.com',
        'password': 'your_password'
    }
)

# Session cookie is automatically stored
# All subsequent requests use this session
```

#### Logout

```python
logout_response = session.get('http://localhost:8000/logout')
```

### CSRF Protection

For form submissions, CSRF tokens are required:

```python
# Get CSRF token from cookie
csrf_token = session.cookies.get('archer_csrf_session')

# Include in form submissions
response = session.post(
    '/endpoint',
    data={'csrf_token': csrf_token, 'other_data': 'value'}
)
```

### Security Best Practices

✅ **Use HTTPS in production**
```python
BASE_URL = 'https://archer.yourcompany.com'  # Production
# BASE_URL = 'http://localhost:8000'  # Development only
```

✅ **Store credentials securely**
```python
import os
from dotenv import load_dotenv

load_dotenv()

email = os.getenv('ARCHER_EMAIL')
password = os.getenv('ARCHER_PASSWORD')
```

✅ **Enable MFA for production accounts**
```bash
curl -X POST "https://archer.example.com/api/mfa/setup" \
  -H "Cookie: archer_session=$SESSION"
```

✅ **Handle session expiration**
```python
def make_authenticated_request(url, **kwargs):
    response = session.get(url, **kwargs)

    if response.status_code == 401:
        # Re-authenticate
        session.post('/login', data={'email': email, 'password': password})
        response = session.get(url, **kwargs)

    return response
```

---

## Core Workflows

### Workflow 1: Generate Detections from Threat Group

**Use Case**: Generate detections for a known threat actor (e.g., APT29, Lazarus Group)

#### Step-by-Step

```python
import requests
import time

session = requests.Session()

# 1. Login
session.post(
    'http://localhost:8000/login',
    data={'email': 'user@example.com', 'password': 'your_password'}
)

# 2. Start generation
generate_response = session.post(
    'http://localhost:8000/generate',
    data={
        'group_name': 'APT29',
        'osint_enhancement': 'true',  # Merge OSINT patterns
        'run_correlation': 'true',     # Generate correlations
        'correlation_min_relevance': '0.75'
    }
)

redirect_url = generate_response.json()['redirect']
group_name = redirect_url.split('group_name=')[1]

# 3. Poll for progress
print("Generating detections...")
while True:
    progress = session.get(
        f'http://localhost:8000/progress_status?group_name={group_name}'
    ).json()

    status = progress['progress']['status']
    created = progress['progress'].get('created_yaml', 0)
    total = progress['progress'].get('total_yaml', 0)

    print(f"Status: {status} - {created}/{total} detections")

    if status == 'complete':
        print("✅ Generation complete!")
        break
    elif status == 'error':
        print("❌ Generation failed")
        break

    time.sleep(2)

# 4. Download results
zip_file = session.get(f'http://localhost:8000/api/download/all/{group_name}')
with open(f'{group_name}.zip', 'wb') as f:
    f.write(zip_file.content)

print(f"Downloaded {group_name}.zip")
```

**Output**: ZIP file containing:
- Detection YAML files
- Correlation JSON files
- Attack flow visualizations

---

### Workflow 2: Generate Detections from CVE

**Use Case**: Generate detections for specific vulnerabilities

```python
# Generate detections for Log4Shell
generate_response = session.post(
    'http://localhost:8000/generate/cve',
    data={
        'cve_id': 'CVE-2021-44228',  # Can be comma-separated: 'CVE-2021-44228,CVE-2022-22965'
        'run_correlation': 'true'
    }
)

# Poll and download (same as workflow 1)
```

**CVE Format Validation**:
```python
import re

def validate_cve_id(cve_id):
    """Validate CVE ID format: CVE-YYYY-NNNN"""
    pattern = r'^CVE-\d{4}-\d{4,}$'
    return bool(re.match(pattern, cve_id))

# Example
cve_id = "CVE-2021-44228"
if validate_cve_id(cve_id):
    # Generate detections
    pass
else:
    print("Invalid CVE format")
```

---

### Workflow 3: Upload and Analyze Threat Report

**Use Case**: Extract TTPs from a threat report and generate detections

```python
# 1. Upload threat report
with open('threat_report.pdf', 'rb') as f:
    upload_response = session.post(
        'http://localhost:8000/upload',
        files={'file': ('threat_report.pdf', f, 'application/pdf')},
        data={
            'use_openai': 'true',      # Use AI for extraction (requires API key)
            'auto_generate': 'false'   # Don't auto-generate (we'll select TTPs first)
        }
    )

result = upload_response.json()
synthetic_group = result['synthetic_group_name']

print(f"Extracted {result['ttps_count']} TTPs and {result['iocs_count']} IOCs")
print(f"TTPs: {[ttp['technique_id'] for ttp in result['ttps']]}")

# 2. Generate detections from extracted TTPs
generate_response = session.post(
    'http://localhost:8000/upload/generate',
    data={
        'synthetic_group_name': synthetic_group,
        'selected_ttps': '["T1059.001", "T1078", "T1003"]',  # Optional: filter TTPs
        'osint_enhancement': 'true'
    }
)

# 3. Poll and download (same as workflow 1)
```

**Supported File Types**:
- Documents: `.pdf`, `.txt`, `.md`, `.docx`, `.doc`
- Data: `.json`, `.csv`, `.xlsx`, `.xls`
- Rules: `.yar`, `.yara`
- **Max Size**: 50MB

---

### Workflow 4: Analyze Blog Post / Threat Report URL

**Use Case**: Extract TTPs from a public threat report URL

```python
analyze_response = session.post(
    'http://localhost:8000/analyze_blog',
    data={
        'url': 'https://www.mandiant.com/resources/threat-report-xyz',
        'use_openai': 'true',
        'auto_generate': 'false'
    }
)

result = analyze_response.json()
print(f"Extracted {result['ttps_count']} TTPs from blog post")
```

---

### Workflow 5: Company Threat Profiling

**Use Case**: Identify relevant threat actors for an organization

```python
# 1. Profile company
profile_response = session.post(
    'http://localhost:8000/profile',
    data={
        'domain': 'example.com',
        'include_industry': 'true',
        'include_geography': 'true',
        'include_tech_stack': 'true',
        'use_openai': 'false'
    }
)

profile = profile_response.json()

print(f"Company: {profile['company_name']}")
print(f"Industry: {profile['industry']}")
print(f"Relevant Threat Groups:")

for group in profile['threat_groups']:
    print(f"  - {group['name']}: {group['relevance_score']}%")
    print(f"    Reasons: {', '.join(group['reasons'])}")

# 2. Generate detections for selected threat groups
selected_groups = ['APT29', 'APT28']  # Based on profile results

generate_response = session.post(
    'http://localhost:8000/profile/generate-detections',
    data={
        'domain': 'example.com',
        'selected_groups': ','.join(selected_groups),
        'run_correlation': 'true'
    }
)
```

---

### Workflow 6: Detection Library Management

#### Search Library

```python
# Search for PowerShell detections
search_response = session.post(
    'http://localhost:8000/api/library/search',
    json={
        'query': 'powershell',
        'type_filter': 'yaml',           # 'all', 'yaml', 'json', 'correlation'
        'visibility_filter': 'all',      # 'all', 'private', 'shared'
        'creator_filter': 'all'          # 'all' or specific creator name
    }
)

detections = search_response.json()['detections']
print(f"Found {len(detections)} PowerShell detections")
```

#### Save Detection

```python
save_response = session.post(
    'http://localhost:8000/api/library/save',
    json={
        'title': 'Pass the Hash Detection',
        'detection_type': 'yaml',
        'visibility': 'private',         # 'private' or 'shared'
        'content': "name: PasstheHash\nid: ...",
        'platform': 'mde',               # 'splunk', 'mde', 'elastic'
        'tags': ['T1550.002', 'Lateral Movement', 'APT29'],
        'group': 'APT29'
    }
)

detection_id = save_response.json()['detection_id']
print(f"Saved detection ID: {detection_id}")
```

#### Export Detections

```python
# Get all detections
detections_response = session.get('http://localhost:8000/api/library/detections')
detections = detections_response.json()['detections']
detection_ids = [d['id'] for d in detections]

# Export to JSON
export_response = session.post(
    'http://localhost:8000/api/library/export',
    json={
        'ids': detection_ids,
        'format': 'json'  # 'json', 'csv', 'xml'
    }
)

with open('detections_export.json', 'w') as f:
    json.dump(export_response.json()['data'], f, indent=2)
```

#### Batch Operations

```python
# Update tags for multiple detections
session.post(
    'http://localhost:8000/api/library/tags',
    json={
        'ids': [123, 456, 789],
        'tags': ['Production', 'High Priority', 'Reviewed']
    }
)

# Update visibility
session.post(
    'http://localhost:8000/api/library/visibility',
    json={
        'ids': [123, 456],
        'visibility': 'shared'
    }
)

# Delete detections
session.post(
    'http://localhost:8000/api/library/delete',
    json={'ids': [123, 456]}
)
```

### Workflow 7: Detection Validation

Validate detection queries against containerized SIEMs with sample events.

> **Requirement:** Docker must be running on the Archer server.

```python
import requests
import time

session = requests.Session()
session.post('http://localhost:8000/login',
    data={'email': 'user@example.com', 'password': 'password'})

# 1. Check Docker availability
docker_status = session.get('http://localhost:8000/api/validation/docker-status').json()
if not docker_status['available']:
    print(f"Docker not available: {docker_status['message']}")
    exit(1)

# 2. Create validation session
session_response = session.post(
    'http://localhost:8000/api/validation/sessions',
    json={
        'technique_id': 'T1059.001',
        'technique_name': 'PowerShell',
        'query': 'index=windows_events process_name="powershell.exe" process_command_line="*-NoP*"',
        'vendor': 'splunk'
    }
).json()

session_id = session_response['session']['session_id']

# 3. Start SIEM container
siem_result = session.post(
    'http://localhost:8000/api/validation/start-siem',
    json={'session_id': session_id}
).json()

if not siem_result['success']:
    print(f"Failed to start SIEM: {siem_result['error']}")
    exit(1)

# 4. Generate sample events
events_result = session.post(
    'http://localhost:8000/api/validation/generate-events',
    json={
        'session_id': session_id,
        'indicators': {
            'cmd': ['powershell.exe -NoP -W Hidden'],
            'sw': ['mimikatz.exe']
        },
        'malicious_count': 10,
        'benign_count': 20
    }
).json()

# 5. Test detection
test_result = session.post(
    'http://localhost:8000/api/validation/test',
    json={'session_id': session_id}
).json()

result = test_result['result']
print(f"Detection {'PASSED' if result['passed'] else 'FAILED'}")
print(f"True Positives: {result['true_positives']}")
print(f"False Negatives: {result['false_negatives']}")
print(f"Precision: {result['precision']:.2%}")
print(f"Recall: {result['recall']:.2%}")
print(f"F1 Score: {result['f1_score']:.2%}")

# 6. Get suggestions if failed
if not result['passed']:
    suggestions = session.get(
        f'http://localhost:8000/api/validation/suggestions/{session_id}'
    ).json()

    for i, suggestion in enumerate(suggestions.get('suggestions', [])):
        print(f"\nSuggestion {i+1}: {suggestion['type']}")
        print(f"  Description: {suggestion['description']}")
        print(f"  Original: {suggestion['original']}")
        print(f"  Suggested: {suggestion['suggested']}")
        print(f"  Confidence: {suggestion['confidence']:.0%}")

# 7. Clean up
session.post(f'http://localhost:8000/api/validation/stop/{session_id}')
```

**Validation API Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/validation/docker-status` | GET | Check Docker availability |
| `/api/validation/sessions` | POST | Create validation session |
| `/api/validation/start-siem` | POST | Start SIEM container |
| `/api/validation/generate-events` | POST | Generate sample events |
| `/api/validation/test` | POST | Execute detection query |
| `/api/validation/suggestions/{session_id}` | GET | Get refinement suggestions |
| `/api/validation/refine` | POST | Apply a refinement |
| `/api/validation/stop/{session_id}` | POST | Stop session and cleanup |
| `/api/validation/quick-validate` | POST | All-in-one validation |

**📚 Detailed Guide:** [Runtime Validation Documentation](../features/RUNTIME_VALIDATION.md)

---

### Workflow 8: Threat Briefing

**Use Case**: Get a grounded, prioritised detection plan for a threat group, grounded in real MITRE ATT&CK technique data and your existing detection coverage.

Unlike the general `/api/ask` endpoint (which uses only the group name as context), `/api/threat-briefing` reads Archer's ATT&CK database and checks your detection library before calling the LLM — so prioritisation is based on actual facts.

#### Endpoint

```
POST /api/threat-briefing
Content-Type: application/json
```

#### Request Body

```json
{
  "group": "Scattered Spider",
  "top_n": 5
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `group` | string | ✅ | Group name (e.g. `"Scattered Spider"`) or ATT&CK ID (e.g. `"G1015"`) |
| `top_n` | integer | ❌ | Number of techniques to return (default: 5) |

#### Response

```json
{
  "group_name": "Scattered Spider",
  "group_id": "G1015",
  "total_techniques": 150,
  "covered_count": 12,
  "gap_count": 138,
  "top_techniques": [
    {
      "priority_rank": 1,
      "technique_id": "T1078.004",
      "technique_name": "Cloud Accounts",
      "tactic": "Initial Access",
      "attribution_type": "direct",  // present in briefing response; not in MITRESaw CSV
      "covered": false,
      "priority_reason": "Scattered Spider's primary initial access vector. No detection exists yet. Detecting this early stops the entire attack chain.",
      "detection_approach": "Monitor Azure AD SignInLogs for logins from new countries/ASNs, impossible travel, or MFA bypass patterns (phish-kit OTP relay)."
    }
  ],
  "attack_chain": ["Initial Access", "Persistence", "Defense Evasion", "Lateral Movement", "Exfiltration"],
  "briefing_summary": "Scattered Spider is a social-engineering-heavy group targeting cloud identities. Priority gaps are in Initial Access and Credential Access — detection here stops the kill chain before lateral movement begins.",
  "provider": "Claude (Anthropic)"
}
```

#### Python Example

```python
import requests

session = requests.Session()
session.post('http://localhost:8000/login',
    data={'email': 'user@example.com', 'password': 'password'})

# Get threat briefing for Scattered Spider
briefing = session.post(
    'http://localhost:8000/api/threat-briefing',
    json={'group': 'Scattered Spider', 'top_n': 5}
).json()

print(f"Group: {briefing['group_name']} ({briefing['group_id']})")
print(f"Coverage: {briefing['covered_count']}/{briefing['total_techniques']} techniques covered")
print(f"Gaps: {briefing['gap_count']} techniques without detections")
print()
print(f"Attack chain: {' → '.join(briefing['attack_chain'])}")
print()
print(f"Summary: {briefing['briefing_summary']}")
print()

for tech in briefing['top_techniques']:
    status = '✓ Covered' if tech['covered'] else '✗ Gap'
    print(f"#{tech['priority_rank']} [{status}] {tech['technique_id']} {tech['technique_name']} [{tech['tactic']}]")
    print(f"   Why: {tech['priority_reason']}")
    print(f"   How: {tech['detection_approach']}")
    print()
```

#### cURL Example

```bash
curl -b cookies.txt -X POST http://localhost:8000/api/threat-briefing \
  -H "Content-Type: application/json" \
  -d '{"group": "Scattered Spider", "top_n": 5}'
```

#### JavaScript Example

```javascript
const briefing = await fetch('/api/threat-briefing', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ group: 'Scattered Spider', top_n: 5 })
}).then(r => r.json());

console.log(`${briefing.covered_count}/${briefing.total_techniques} techniques covered`);
briefing.top_techniques.forEach(t => {
  console.log(`#${t.priority_rank} ${t.technique_id} ${t.technique_name} — ${t.covered ? 'Covered' : 'GAP'}`);
});
```

#### Error Responses

| Code | Reason |
|------|--------|
| `401` | Not authenticated |
| `404` | Group not found in ATT&CK data |
| `503` | No LLM provider configured (add API key under Profile → API Keys) |

#### Notes

- The briefing reads from `data/mitre_procedures.csv` (all three ATT&CK attribution paths: direct, via software, via campaign)
- Coverage check scans your detection library (`data/groups/`) for YAML files matching each technique ID
- The LLM prompt is capped at 80 gap techniques to stay within token limits — groups with 150+ techniques will show the 80 highest-priority gaps
- Requires an LLM provider (Anthropic, OpenAI, or local Ollama) — same as Ask Archer

### Workflow 9: Batch Hunts

Hunt several groups and CVEs with one call. The server runs them one after another, as you, so your SIEM platforms, technology stack and AI settings apply to each; one that fails doesn't stop the rest. Up to 50 per batch.

```bash
curl -X POST http://127.0.0.1:8000/api/batch -H "Authorization: Bearer $ARCHER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"groups": ["APT29", "Scattered Spider"], "cves": ["CVE-2024-3400"], "correlate": true}'
# {"id": "118ad0ce5170", "items": 3, "status_url": "/api/batch/118ad0ce5170"}

curl http://127.0.0.1:8000/api/batch/118ad0ce5170 -H "Authorization: Bearer $ARCHER_TOKEN"
```

Each item reports its run name (the results page is `/results/<run>`), `status` and `created_yaml`; the batch's `status` ends as `complete`, `partial` or `failed`. From Python: `ArcherClient().batch(groups=[...], cves=[...])` and `batch_status(id)`. `GET /api/batch` lists your batches.

### Workflow 10: Streamed Progress

`GET /api/progress/<run>/stream` sends a run's progress as Server-Sent Events: a `progress` event each time it changes, a comment line every 15 seconds while it's quiet, and a `done` event when the run finishes. It replaces polling `/progress_status`.

```bash
curl -N http://127.0.0.1:8000/api/progress/APT29/stream -H "Authorization: Bearer $ARCHER_TOKEN"
```

```javascript
const events = new EventSource("/api/progress/APT29/stream");  // same-origin, with the session cookie
events.addEventListener("progress", e => console.log(JSON.parse(e.data)));
events.addEventListener("done", () => events.close());
```

### Workflow 11: Webhooks

An admin registers URLs that Archer POSTs to when something happens:

| Event | Sent when | `data` |
|---|---|---|
| `run.completed` | a hunt finishes | `run`, `phase`, `created_yaml`, `results_url` |
| `run.failed` | a hunt stops with an error | `run`, `status`, `error` |
| `watchlist.match` | a Threat Feed watchlist finds new posts | `user_id`, `matches` (`query`, `title`, `url`) |

```bash
curl -X POST http://127.0.0.1:8000/api/webhooks -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://hooks.example.com/archer", "events": ["run.completed", "run.failed"]}'
# returns the webhook with its secret: the only time the secret is shown
```

The body is `{"event", "sent_at", "data"}` with an `X-Archer-Event` header and `X-Archer-Signature: sha256=<hex>`, an HMAC-SHA256 of the raw body under the webhook's secret. Check it before trusting a delivery:

```python
import hashlib, hmac
expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
assert hmac.compare_digest(expected, request.headers["X-Archer-Signature"])
```

Deliveries are tried three times with backoff (a 4xx other than 429 isn't retried), and the last 20 per webhook show in `GET /api/webhooks`. `POST /api/webhooks/<id>/test` sends a test event and returns the result; `PATCH` changes `url`, `events`, `enabled` or `description`; `DELETE` removes it. Set `ARCHER_PUBLIC_URL` (e.g. `https://archer.example.com`) to make `results_url` absolute. Webhooks and their secrets are stored in `data/webhooks.json`, never in git.

---

## Code Examples

### Python Complete Example

```python
import requests
import time
import json
from pathlib import Path

class ArcherClient:
    """Simple Archer API client"""

    def __init__(self, base_url='http://localhost:8000'):
        self.base_url = base_url
        self.session = requests.Session()

    def login(self, email, password):
        """Authenticate with Archer"""
        response = self.session.post(
            f'{self.base_url}/login',
            data={'email': email, 'password': password}
        )
        return response.status_code == 200

    def generate_detections(self, group_name, osint=True, correlate=True):
        """Generate detections for a threat group"""
        response = self.session.post(
            f'{self.base_url}/generate',
            data={
                'group_name': group_name,
                'osint_enhancement': str(osint).lower(),
                'run_correlation': str(correlate).lower()
            }
        )
        redirect_url = response.json()['redirect']
        return redirect_url.split('group_name=')[1]

    def poll_progress(self, group_name, interval=2):
        """Poll generation progress until complete"""
        while True:
            response = self.session.get(
                f'{self.base_url}/progress_status',
                params={'group_name': group_name}
            )
            progress = response.json()['progress']

            yield progress

            if progress['status'] in ['complete', 'error']:
                break

            time.sleep(interval)

    def download_results(self, group_name, output_path):
        """Download generated detections as ZIP"""
        response = self.session.get(
            f'{self.base_url}/api/download/all/{group_name}'
        )

        Path(output_path).write_bytes(response.content)
        return output_path


# Usage
client = ArcherClient()
client.login('user@example.com', 'password')

# Generate detections
group_name = client.generate_detections('APT29')

# Monitor progress
for progress in client.poll_progress(group_name):
    print(f"{progress['status']}: {progress.get('created_yaml', 0)}/{progress.get('total_yaml', 0)}")

# Download
client.download_results(group_name, f'{group_name}.zip')
```

### JavaScript/Node.js Complete Example

```javascript
const axios = require('axios');
const fs = require('fs');

class ArcherClient {
    constructor(baseURL = 'http://localhost:8000') {
        this.client = axios.create({
            baseURL,
            withCredentials: true
        });
    }

    async login(email, password) {
        await this.client.post('/login', new URLSearchParams({
            email,
            password
        }));
    }

    async generateDetections(groupName, options = {}) {
        const response = await this.client.post('/generate', new URLSearchParams({
            group_name: groupName,
            osint_enhancement: options.osint !== false,
            run_correlation: options.correlate !== false
        }));

        const url = new URL(response.data.redirect, this.client.defaults.baseURL);
        return url.searchParams.get('group_name');
    }

    async *pollProgress(groupName, interval = 2000) {
        while (true) {
            const response = await this.client.get('/progress_status', {
                params: { group_name: groupName }
            });

            const progress = response.data.progress;
            yield progress;

            if (progress.status === 'complete' || progress.status === 'error') {
                break;
            }

            await new Promise(resolve => setTimeout(resolve, interval));
        }
    }

    async downloadResults(groupName, outputPath) {
        const response = await this.client.get(`/api/download/all/${groupName}`, {
            responseType: 'arraybuffer'
        });

        fs.writeFileSync(outputPath, response.data);
        return outputPath;
    }
}

// Usage
(async () => {
    const client = new ArcherClient();
    await client.login('user@example.com', 'password');

    // Generate detections
    const groupName = await client.generateDetections('APT29');

    // Monitor progress
    for await (const progress of client.pollProgress(groupName)) {
        console.log(`${progress.status}: ${progress.created_yaml || 0}/${progress.total_yaml || 0}`);
    }

    // Download
    await client.downloadResults(groupName, `${groupName}.zip`);
    console.log('Download complete!');
})();
```

### cURL Complete Workflow

```bash
#!/bin/bash

BASE_URL="http://localhost:8000"
COOKIES="cookies.txt"

# Login
curl -c $COOKIES -X POST "$BASE_URL/login" \
  -d "email=user@example.com&password=your_password"

# Generate detections
REDIRECT=$(curl -b $COOKIES -X POST "$BASE_URL/generate" \
  -d "group_name=APT29&osint_enhancement=true&run_correlation=true" \
  | jq -r '.redirect')

GROUP_NAME=$(echo $REDIRECT | grep -oP 'group_name=\K[^&]+')
echo "Generating detections for: $GROUP_NAME"

# Poll progress
while true; do
  STATUS=$(curl -s -b $COOKIES "$BASE_URL/progress_status?group_name=$GROUP_NAME" \
    | jq -r '.progress.status')

  echo "Status: $STATUS"

  if [ "$STATUS" = "complete" ]; then
    break
  fi

  sleep 2
done

# Download results
curl -b $COOKIES -o "${GROUP_NAME}.zip" \
  "$BASE_URL/api/download/all/${GROUP_NAME}"

echo "Downloaded: ${GROUP_NAME}.zip"
```

---

## Best Practices

### 1. Error Handling

✅ **Always check status codes**
```python
response = session.post('/generate', data={'group_name': 'APT29'})

if response.status_code == 200:
    print("Success!")
elif response.status_code == 400:
    print(f"Bad request: {response.json()['detail']}")
elif response.status_code == 401:
    print("Not authenticated. Please login.")
elif response.status_code == 429:
    print("Rate limited. Please wait.")
else:
    print(f"Error {response.status_code}: {response.text}")
```

✅ **Implement retries with exponential backoff**
```python
import time
from requests.exceptions import RequestException

def make_request_with_retry(url, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = session.get(url)
            response.raise_for_status()
            return response
        except RequestException as e:
            if attempt == max_retries - 1:
                raise
            wait_time = 2 ** attempt  # Exponential backoff
            print(f"Retry {attempt + 1}/{max_retries} after {wait_time}s")
            time.sleep(wait_time)
```

✅ **Handle timeouts**
```python
try:
    response = session.post('/generate', data={'group_name': 'APT29'}, timeout=30)
except requests.Timeout:
    print("Request timed out. Server may be busy.")
```

---

### 2. Performance Optimization

✅ **Use connection pooling**
```python
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retry = Retry(total=3, backoff_factor=0.3)
adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
session.mount('http://', adapter)
session.mount('https://', adapter)
```

✅ **Poll efficiently with backoff**
```python
def poll_with_backoff(group_name, max_wait=300):
    """Poll with increasing intervals"""
    elapsed = 0
    interval = 2  # Start with 2 seconds

    while elapsed < max_wait:
        response = session.get(f'/progress_status?group_name={group_name}')
        status = response.json()['progress']['status']

        if status == 'complete':
            return True
        elif status == 'error':
            return False

        time.sleep(interval)
        elapsed += interval
        interval = min(interval * 1.5, 10)  # Max 10 seconds

    return False  # Timeout
```

✅ **Batch operations**
```python
# Bad: Individual requests
for detection_id in detection_ids:
    session.post('/api/library/delete', json={'ids': [detection_id]})

# Good: Batch request
session.post('/api/library/delete', json={'ids': detection_ids})
```

---

### 3. Data Validation

✅ **Validate input before sending**
```python
import re

def validate_cve_format(cve_id):
    pattern = r'^CVE-\d{4}-\d{4,}$'
    return bool(re.match(pattern, cve_id))

def validate_threat_group(group_name):
    # Check if group name is not empty and reasonable length
    return bool(group_name and 3 <= len(group_name) <= 50)
```

✅ **Handle file size limits**
```python
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

def upload_file(file_path):
    import os

    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        raise ValueError("File exceeds 50MB limit")

    with open(file_path, 'rb') as f:
        response = session.post('/upload', files={'file': f})

    return response.json()
```

---

### 4. Resource Management

✅ **Close sessions properly**
```python
try:
    session = requests.Session()
    # ... make requests ...
finally:
    session.close()
```

✅ **Use context managers**
```python
with requests.Session() as session:
    response = session.post('/generate', data={'group_name': 'APT29'})
    # Session automatically closed
```

✅ **Stream large downloads**
```python
def download_large_file(url, filename):
    with session.get(url, stream=True) as response:
        response.raise_for_status()
        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

download_large_file('/api/download/all/APT29', 'APT29.zip')
```

---

### 5. Logging & Monitoring

✅ **Log API interactions**
```python
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_detections(group_name):
    logger.info(f"Generating detections for: {group_name}")

    try:
        response = session.post('/generate', data={'group_name': group_name})
        logger.info(f"Response: {response.status_code}")
        return response.json()
    except Exception as e:
        logger.error(f"Failed to generate: {e}")
        raise
```

✅ **Track API usage**
```python
import time
from functools import wraps

def track_api_call(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start
            logger.info(f"{func.__name__} completed in {duration:.2f}s")
            return result
        except Exception as e:
            logger.error(f"{func.__name__} failed: {e}")
            raise
    return wrapper

@track_api_call
def upload_report(file_path):
    # ... upload logic ...
    pass
```

---

## Advanced Topics

### Background Jobs & Polling

Archer processes long-running tasks asynchronously:
- Detection generation
- File upload processing
- Blog analysis

**Polling Pattern**:
```javascript
async function trackProgress(groupName) {
  const updateProgress = async () => {
    const response = await fetch(`/progress_status?group_name=${groupName}`);
    const data = await response.json();

    // Update UI
    const percent = (data.progress.created_yaml / data.progress.total_yaml) * 100;
    updateProgressBar(percent);

    if (data.progress.status === 'complete') {
      window.location.href = `/results?group_name=${groupName}`;
    } else if (data.progress.status === 'error') {
      showError('Generation failed');
    } else {
      setTimeout(updateProgress, 2000);
    }
  };

  updateProgress();
}
```

### Rate Limiting

Current rate limits:
- `/login`: 5 requests per 5 minutes per IP
- `/register`: 5 requests per 5 minutes per IP
- Account lockout: 15 minutes after 5 failed login attempts

**Handling Rate Limits**:
```python
import time

def handle_rate_limit(response):
    if response.status_code == 429:
        retry_after = int(response.headers.get('Retry-After', 60))
        print(f"Rate limited. Waiting {retry_after} seconds...")
        time.sleep(retry_after)
        return True
    return False
```

---

## Troubleshooting

### Common Errors

#### Authentication Failures

**Problem**: `401 Unauthorized`

**Solutions**:
```python
# 1. Verify credentials
response = session.post('/login', data={'email': email, 'password': password})
if response.status_code != 200:
    print("Invalid credentials")

# 2. Check session cookie
if 'archer_session' not in session.cookies:
    print("No session cookie. Re-authenticate.")

# 3. Handle session expiration
def ensure_authenticated(func):
    def wrapper(*args, **kwargs):
        response = func(*args, **kwargs)
        if response.status_code == 401:
            session.post('/login', data={'email': email, 'password': password})
            response = func(*args, **kwargs)
        return response
    return wrapper
```

#### Rate Limiting

**Problem**: `429 Too Many Requests`

**Solution**: Implement exponential backoff (see Best Practices)

#### File Upload Issues

**Problem**: File upload fails

**Checks**:
```python
# 1. Check file size
import os
if os.path.getsize(file_path) > 50 * 1024 * 1024:
    print("File too large (max 50MB)")

# 2. Check file type
allowed_types = ['.pdf', '.txt', '.docx', '.json', '.csv']
if not any(file_path.endswith(ext) for ext in allowed_types):
    print("Unsupported file type")

# 3. Check file exists
if not os.path.exists(file_path):
    print("File not found")
```

#### Progress Polling Timeouts

**Problem**: Generation takes too long

**Solution**:
```python
def poll_with_timeout(group_name, timeout=600):
    start_time = time.time()

    while time.time() - start_time < timeout:
        response = session.get(f'/progress_status?group_name={group_name}')
        status = response.json()['progress']['status']

        if status in ['complete', 'error']:
            return status

        time.sleep(2)

    raise TimeoutError(f"Generation exceeded {timeout}s timeout")
```

---

## FAQ

### Q: How long does detection generation take?

**A**: Depends on the threat group size:
- Small groups (10-20 techniques): 1-2 minutes
- Medium groups (50-100 techniques): 5-10 minutes
- Large groups (200+ techniques): 15-30 minutes

### Q: Can I generate detections for multiple threat groups at once?

**A**: Not directly via API, but you can call the API multiple times in parallel:
```python
import concurrent.futures

groups = ['APT29', 'APT28', 'Lazarus Group']

with concurrent.futures.ThreadPoolExecutor() as executor:
    futures = [executor.submit(generate_detections, group) for group in groups]
    results = [f.result() for f in concurrent.futures.as_completed(futures)]
```

### Q: How do I know which SIEM platform to use?

**A**: Specify the platform when saving detections:
- `splunk` - Splunk SPL queries
- `mde` - Microsoft Defender KQL queries
- `elastic` - Elastic EQL queries

### Q: Can I use Archer API without authentication?

**A**: No, all API endpoints (except `/docs` and `/openapi.json`) require authentication.

### Q: What's the difference between YAML and JSON detections?

**A**:
- **YAML**: Human-readable detection format with metadata
- **JSON**: Machine-readable correlation format for multi-stage attacks

### Q: How do I report API bugs or request features?

**A**: Open an issue on GitHub: https://github.com/cmdaltr/archer/issues

---

## API Reference

For complete endpoint documentation, see the auto-generated API reference:

- **Interactive Docs** (Swagger UI): `http://localhost:8000/docs`
- **Alternative Docs** (ReDoc): `http://localhost:8000/redoc`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`

The auto-generated documentation provides:
- Complete list of all endpoints
- Request/response schemas
- Interactive testing interface
- Parameter descriptions
- Authentication requirements

---

## Additional Resources

### Official Documentation
- [Archer GitHub Repository](https://github.com/cmdaltr/archer)
- [Scripts Documentation](../SCRIPTS.md)
- [Feature Documentation](../features/)
- [Architecture Documentation](../architecture/)

### Community
- [GitHub Issues](https://github.com/cmdaltr/archer/issues)
- [GitHub Discussions](https://github.com/cmdaltr/archer/discussions)

### Related Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

---

## Support

For API support and questions:
- **GitHub Issues**: [Report a bug](https://github.com/cmdaltr/archer/issues)
- **GitHub Discussions**: [Ask a question](https://github.com/cmdaltr/archer/discussions)
- **Email**: [GitHub @cmdaltr](https://github.com/cmdaltr)

---

**© 2024 Archer Detection Generator** | Built with ❤️ by @cmdaltr
