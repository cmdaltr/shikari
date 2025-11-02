# Archer API Documentation

> **Version:** 1.0
> **Last Updated:** 2025-10-30
> **Base URL:** `http://localhost:8000` (default)

---

# Introduction

The Archer API provides programmatic access to automated threat detection generation, MITRE ATT&CK intelligence processing, and security detection management.

## Key Features

- ✅ Generate production-ready detection queries from threat intelligence
- ✅ Upload and analyze threat reports (PDF, TXT, DOCX, etc.)
- ✅ Profile organizations and identify relevant threat actors
- ✅ Manage detection libraries with sharing and tagging
- ✅ Track generation progress in real-time
- ✅ Export detections in multiple formats (YAML, JSON, ZIP)

---

# Authentication

## Session-Based Authentication

Archer uses session-based authentication with secure HTTP-only cookies.

### Login Endpoint

```
POST /login
```

**Request:**

```bash
curl -X POST "http://localhost:8000/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=user@example.com&password=your_password&csrf_token=<token>"
```

**Response:**

```
HTTP/1.1 303 See Other
Set-Cookie: archer_session=<session_token>; HttpOnly; Secure
Location: /
```

### Logout Endpoint

```
GET /logout
```

**Request:**

```bash
curl -X GET "http://localhost:8000/logout" \
  -H "Cookie: archer_session=<session_token>"
```

---

# Rate Limiting

| Endpoint | Limit | Window |
| --- | --- | --- |
| `/login` | 5 requests | 5 minutes per IP |
| `/register` | 5 requests | 5 minutes per IP |

**429 Response:**

```json
{
  "detail": "Too many failed login attempts. Please try again later."
}
```

---

# Error Handling

## Standard Error Response

```json
{
  "success": false,
  "error": "Error message",
  "detail": "Additional context"
}
```

## HTTP Status Codes

| Code | Meaning | Common Causes |
| --- | --- | --- |
| 200 | OK | Request successful |
| 303 | See Other | Redirect after POST |
| 400 | Bad Request | Invalid parameters |
| 401 | Unauthorized | Not authenticated |
| 403 | Forbidden | CSRF fail, account locked |
| 404 | Not Found | Resource doesn't exist |
| 413 | Payload Too Large | File exceeds 50MB |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server-side error |

---

# Detection Generation

## Generate Detections for Threat Group

Create detection queries for a known threat actor group.

```
POST /generate
```

### Request Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `group_name` | string | ✅ | Threat actor name (e.g., "APT29") |
| `osint_enhancement` | boolean | ❌ | Merge OSINT patterns (default: false) |
| `osint_comparison` | boolean | ❌ | Add OSINT metadata (default: false) |
| `run_correlation` | boolean | ❌ | Generate correlations (default: false) |
| `correlation_min_relevance` | float | ❌ | Threshold 0.5-1.0 (default: 0.75) |
| `ai_generators` | boolean | ❌ | Use AI (requires OpenAI key) |

### Example Request

```bash
curl -X POST "http://localhost:8000/generate" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "group_name=APT29&osint_enhancement=true&run_correlation=true"
```

### Response

```json
{
  "redirect": "/progress?group_name=APT29"
}
```

### Status Codes

- `200 OK` - Request accepted
- `400 Bad Request` - Unknown threat actor

---

## Generate Detections for CVE(s)

Create detections for specific CVE vulnerabilities.

```
POST /generate/cve
```

### Request Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `cve_id` | string | ✅ | Comma-separated CVE IDs |
| `run_correlation` | boolean | ❌ | Generate correlations |

### Example Request

```bash
curl -X POST "http://localhost:8000/generate/cve" \
  -H "Cookie: archer_session=abc123" \
  -d "cve_id=CVE-2021-44228,CVE-2022-22965&run_correlation=true"
```

### Response

```json
{
  "redirect": "/progress?group_name=CVE-2021-44228"
}
```

---

# File Upload & Analysis

## Upload Threat Intelligence File

Upload and extract TTPs/IOCs from threat reports.

```
POST /upload
```

### Supported File Types

- **Documents:** `.pdf`, `.txt`, `.md`, `.docx`, `.doc`
- **Data:** `.json`, `.csv`, `.xlsx`, `.xls`
- **Rules:** `.yar`, `.yara`

### File Size Limit

50MB maximum

### Request Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `file` | file | ✅ | Threat report file |
| `use_openai` | boolean | ❌ | Use AI extraction (default: false) |
| `auto_generate` | boolean | ❌ | Auto-generate detections |

### Example Request (Python)

```python
import requests

with open('threat_report.pdf', 'rb') as f:
    files = {'file': ('threat_report.pdf', f, 'application/pdf')}
    data = {'use_openai': 'true'}

    response = requests.post(
        'http://localhost:8000/upload',
        files=files,
        data=data,
        cookies={'archer_session': 'your_session_token'}
    )

print(response.json())
```

### Response

```json
{
  "success": true,
  "filename": "threat_report.pdf",
  "synthetic_group_name": "UploadedFile_2025103012345",
  "ttps": [
    {
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "tactics": ["Execution"],
      "description": "Uses PowerShell for execution"
    }
  ],
  "iocs": {
    "ip": ["192.168.1.100"],
    "domain": ["malicious.com"],
    "hash": ["d41d8cd98f00b204e9800998ecf8427e"]
  },
  "ttps_count": 12,
  "iocs_count": 45
}
```

---

## Generate from Uploaded File

Generate detections from extracted TTPs.

```
POST /upload/generate
```

### Request Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `synthetic_group_name` | string | ✅ | Group name from upload |
| `selected_ttps` | JSON string | ❌ | Array of technique IDs |
| `osint_enhancement` | boolean | ❌ | Enable OSINT enhancement |

### Example Request

```bash
curl -X POST "http://localhost:8000/upload/generate" \
  -H "Cookie: archer_session=abc123" \
  -d "synthetic_group_name=UploadedFile_2025103012345&osint_enhancement=true"
```

---

## Analyze Blog Post URL

Extract TTPs from a public threat report URL.

```
POST /analyze_blog
```

### Request Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `url` | string | ✅ | URL to threat report |
| `use_openai` | boolean | ❌ | Use AI for analysis |
| `auto_generate` | boolean | ❌ | Auto-generate detections |

### Example Request

```bash
curl -X POST "http://localhost:8000/analyze_blog" \
  -d "url=https://example.com/threat-report&use_openai=true"
```

---

# Progress Tracking

## Get Progress Status

Poll generation progress in real-time.

```
GET /progress_status?group_name=<group_name>
```

### Query Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `group_name` | string | ✅ | Threat group or CVE name |

### Response

```json
{
  "ok": true,
  "progress": {
    "status": "in_progress",
    "stage": "detections",
    "created_yaml": 45,
    "total_yaml": 120,
    "current_file": "PasstheHash_DeviceProcessEvents.yaml"
  }
}
```

### Status Values

- `started` - Processing initiated
- `in_progress` - Generating detections
- `correlating` - Building correlations
- `complete` - Finished successfully
- `error` - Failed

### Polling Example (JavaScript)

```javascript
async function pollProgress(groupName) {
  const interval = setInterval(async () => {
    const response = await fetch(`/progress_status?group_name=${groupName}`);
    const data = await response.json();

    if (data.progress.status === 'complete') {
      clearInterval(interval);
      window.location.href = `/results?group_name=${groupName}`;
    }
  }, 2000); // Poll every 2 seconds
}
```

---

# Detection Library

## Get All Detections

Retrieve all saved detections.

```
GET /api/library/detections
```

### Response

```json
{
  "success": true,
  "detections": [
    {
      "id": 123,
      "title": "PowerShell Execution via Rundll32",
      "detection_type": "yaml",
      "visibility": "private",
      "platform": "mde",
      "tags": "[\"T1059.001\",\"Execution\",\"APT29\"]",
      "created_at": "2025-10-30T10:00:00Z",
      "is_owner": true
    }
  ]
}
```

---

## Search Library Detections

Filter detections with advanced search.

```
POST /api/library/search
```

### Request Body

```json
{
  "query": "powershell",
  "type_filter": "yaml",
  "visibility_filter": "private",
  "creator_filter": "all"
}
```

### Filters

| Field | Options |
| --- | --- |
| `type_filter` | "all", "yaml", "json", "correlation" |
| `visibility_filter` | "all", "private", "shared" |

---

## Save Detection

Save a new detection to library.

```
POST /api/library/save
```

### Request Body

```json
{
  "title": "Pass the Hash Detection",
  "detection_type": "yaml",
  "visibility": "private",
  "content": "name: PasstheHash\nid: ...",
  "platform": "mde",
  "tags": ["T1550.002", "Lateral Movement"],
  "group": "APT29"
}
```

### Response

```json
{
  "success": true,
  "detection_id": 456,
  "tags_saved": ["T1550.002", "Lateral Movement", "APT29"]
}
```

---

## Update Detection Tags

Batch update tags for multiple detections.

```
POST /api/library/tags
```

### Request Body

```json
{
  "ids": [123, 456, 789],
  "tags": ["Production", "High Priority", "Reviewed"]
}
```

---

## Export Detections

Export detections in various formats.

```
POST /api/library/export
```

### Request Body

```json
{
  "ids": [123, 456, 789],
  "format": "json"
}
```

### Format Options

- `json` - JSON format
- `csv` - CSV format
- `xml` - XML format

---

## Delete Detections

Batch delete detections.

```
POST /api/library/delete
```

### Request Body

```json
{
  "ids": [123, 456]
}
```

---

# Download Endpoints

## Download Single Detection

```
GET /api/download/detection/<filename>
```

### Example

```bash
curl -O "http://localhost:8000/api/download/detection/PasstheHash_DeviceProcessEvents.yaml"
```

---

## Download All Detections (ZIP)

Download complete detection package.

```
GET /api/download/all/<group_name>
```

### ZIP Contents

```
detections/
  PasstheHash_DeviceProcessEvents.yaml
  PowerShell_windows_events.yaml
correlations/
  APT29.json
attack_flows/
  APT29.json
  APT29.html
```

### Example

```bash
curl -o APT29.zip "http://localhost:8000/api/download/all/APT29"
```

---

## Download Attack Flow

```
GET /api/download/flow/<filename>
```

### Example

```bash
curl -O "http://localhost:8000/api/download/flow/APT29.json"
```

---

# Company Profiling

## Profile Organization

Analyze an organization's threat landscape.

```
POST /profile
```

### Request Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `domain` | string | ✅ | Company domain |
| `include_industry` | boolean | ❌ | Industry-based analysis |
| `include_geography` | boolean | ❌ | Geographic analysis |
| `include_tech_stack` | boolean | ❌ | Tech stack analysis |
| `use_openai` | boolean | ❌ | Use AI for profiling |

### Example Request

```bash
curl -X POST "http://localhost:8000/profile" \
  -d "domain=example.com&include_industry=true&include_tech_stack=true"
```

### Response

```json
{
  "success": true,
  "domain": "example.com",
  "company_name": "Example Corp",
  "industry": "Technology",
  "threat_groups": [
    {
      "name": "APT29",
      "relevance_score": 85,
      "reasons": [
        "Targets technology sector",
        "Known to target US companies"
      ],
      "techniques_count": 45
    }
  ]
}
```

---

## Generate Detections for Profile

```
POST /profile/generate-detections
```

### Request Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `domain` | string | ✅ | Company domain |
| `selected_groups` | string | ✅ | Comma-separated group names |
| `run_correlation` | boolean | ❌ | Run correlations |

---

# User Management

## Registration

Create new user account.

```
POST /register
```

### Request Parameters

| Parameter | Type | Required | Validation |
| --- | --- | --- | --- |
| `email` | string | ✅ | Valid email format |
| `full_name` | string | ✅ | 2-64 characters |
| `password` | string | ✅ | 16-40 characters |
| `password_confirm` | string | ✅ | Must match password |

---

## Password Management

### Request Password Reset

```
POST /api/auth/request-reset
```

**Request Body:**

```json
{
  "email": "user@example.com"
}
```

### Reset Password

```
POST /api/auth/reset-password
```

**Request Body:**

```json
{
  "token": "abc123xyz",
  "new_password": "NewStrongPass456!@#"
}
```

### Change Password

```
POST /api/change-password
```

**Request Body:**

```json
{
  "current_password": "OldPassword123!",
  "new_password": "NewPassword456!@#"
}
```

---

## Profile Management

### Update Profile

```
POST /api/profile
```

**Request Body:**

```json
{
  "full_name": "John Smith"
}
```

### Upload Profile Picture

```
POST /api/profile/picture
```

**Form Data:**

- `profile_picture` - Image file

### Get Activity Timeline

```
GET /api/activities
```

**Response:**

```json
{
  "success": true,
  "activities": [
    {
      "id": 456,
      "type": "detection_generated",
      "title": "Generated Detections for APT29",
      "created_at": "2025-10-30T14:30:00Z"
    }
  ]
}
```

---

## API Keys Management

### Get API Keys (Decrypted)

```
GET /api/profile/apikeys
```

**Response:**

```json
{
  "openai": "sk-proj-...",
  "splunk": "splunk-api-key",
  "mde": "mde-api-key"
}
```

### Save API Keys (Encrypted)

```
POST /api/profile/apikeys
```

**Request Body:**

```json
{
  "openai": "sk-proj-your-key",
  "splunk": "splunk-api-key",
  "mde": "mde-api-key",
  "elastic": "elastic-api-key"
}
```

> **Security:** Keys are encrypted using Fernet symmetric encryption

---

## Multi-Factor Authentication

### Get MFA Status

```
GET /api/mfa/status
```

### Setup MFA

```
POST /api/mfa/setup
```

**Response:**

```json
{
  "success": true,
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,..."
}
```

### Verify and Enable MFA

```
POST /api/mfa/verify
```

**Request Body:**

```json
{
  "code": "123456"
}
```

### Disable MFA

```
POST /api/mfa/disable
```

### Generate Backup Codes

```
POST /api/backup-codes/generate
```

**Response:**

```json
{
  "success": true,
  "codes": [
    "ABC123-DEF456",
    "GHI789-JKL012",
    "MNO345-PQR678"
  ]
}
```

---

# Admin Endpoints

## Get All Users

```
GET /api/admin/users
```

**Admin Only** ⚠️

### Response

```json
{
  "success": true,
  "users": [
    {
      "id": 1,
      "email": "admin@example.com",
      "full_name": "Admin User",
      "role": "admin",
      "is_active": true
    }
  ]
}
```

---

## Create User

```
POST /api/admin/users
```

**Admin Only** ⚠️

**Request Body:**

```json
{
  "email": "newuser@example.com",
  "full_name": "New User",
  "password": "TempPassword123!@#",
  "role": "standard"
}
```

---

## Update User

```
PUT /api/admin/users/<user_id>
```

**Admin Only** ⚠️

**Request Body:**

```json
{
  "email": "updated@example.com",
  "full_name": "Updated Name",
  "role": "admin",
  "is_active": true
}
```

---

## Deactivate User

```
DELETE /api/admin/users/<user_id>
```

**Admin Only** ⚠️

---

# Code Examples

## Python - Generate Detections

```python
import requests
import time

# Login
session = requests.Session()
session.post('http://localhost:8000/login', data={
    'email': 'user@example.com',
    'password': 'your_password'
})

# Generate detections
response = session.post('http://localhost:8000/generate', data={
    'group_name': 'APT29',
    'osint_enhancement': 'true',
    'run_correlation': 'true'
})

group_name = response.json()['redirect'].split('group_name=')[1]

# Poll progress
while True:
    progress = session.get(
        f'http://localhost:8000/progress_status?group_name={group_name}'
    ).json()

    if progress['progress']['status'] == 'complete':
        break

    time.sleep(2)

# Download results
zip_file = session.get(f'http://localhost:8000/api/download/all/{group_name}')
with open(f'{group_name}.zip', 'wb') as f:
    f.write(zip_file.content)
```

---

## Python - Upload File

```python
import requests

session = requests.Session()
# ... login code ...

# Upload file
with open('threat_report.pdf', 'rb') as f:
    response = session.post(
        'http://localhost:8000/upload',
        files={'file': ('threat_report.pdf', f, 'application/pdf')},
        data={'use_openai': 'true'}
    )

result = response.json()
print(f"Extracted {result['ttps_count']} TTPs")

# Generate detections
session.post('http://localhost:8000/upload/generate', data={
    'synthetic_group_name': result['synthetic_group_name'],
    'osint_enhancement': 'true'
})
```

---

## JavaScript - Poll Progress

```javascript
async function pollProgress(groupName) {
  const interval = setInterval(async () => {
    const response = await fetch(
      `/progress_status?group_name=${groupName}`
    );
    const data = await response.json();

    console.log(`Status: ${data.progress.status}`);

    if (data.progress.status === 'complete') {
      clearInterval(interval);
      window.location.href = `/results?group_name=${groupName}`;
    }
  }, 2000);
}
```

---

## cURL - Complete Workflow

```bash
#!/bin/bash

# Login
curl -c cookies.txt -X POST "http://localhost:8000/login" \
  -d "email=user@example.com&password=your_password"

# Generate detections
curl -b cookies.txt -X POST "http://localhost:8000/generate" \
  -d "group_name=APT29&osint_enhancement=true" \
  | jq -r '.redirect'

# Download results
curl -b cookies.txt -o "APT29.zip" \
  "http://localhost:8000/api/download/all/APT29"
```

---

# Best Practices

## 1. Authentication & Security

✅ **Use HTTPS in production**

```python
base_url = 'https://archer.example.com'  # Production
```

✅ **Store credentials securely**

```python
import os
from dotenv import load_dotenv

load_dotenv()
email = os.getenv('ARCHER_EMAIL')
password = os.getenv('ARCHER_PASSWORD')
```

✅ **Enable MFA for sensitive accounts**

---

## 2. Error Handling

✅ **Check status codes**

```python
response = session.post('/generate', data={'group_name': 'APT29'})

if response.status_code == 200:
    print("Success!")
elif response.status_code == 400:
    print(f"Bad request: {response.json()['detail']}")
elif response.status_code == 401:
    print("Not authenticated")
```

✅ **Implement retries with backoff**

```python
import time

for attempt in range(3):
    try:
        response = session.get(url)
        response.raise_for_status()
        break
    except RequestException:
        if attempt == 2:
            raise
        time.sleep(2 ** attempt)
```

---

## 3. Performance

✅ **Use connection pooling**

```python
from requests.adapters import HTTPAdapter

session = requests.Session()
adapter = HTTPAdapter(max_retries=3)
session.mount('http://', adapter)
```

✅ **Poll efficiently**

```python
# Start with 2 seconds, increase to max 10 seconds
interval = 2
while status != 'complete':
    time.sleep(interval)
    interval = min(interval * 1.5, 10)
```

✅ **Batch operations**

```python
# Good: Batch request
session.post('/api/library/delete', json={'ids': [1, 2, 3]})

# Bad: Individual requests
for id in [1, 2, 3]:
    session.post('/api/library/delete', json={'ids': [id]})
```

---

## 4. Resource Management

✅ **Close sessions properly**

```python
with requests.Session() as session:
    response = session.post('/generate', data={'group_name': 'APT29'})
    # Session automatically closed
```

✅ **Stream large downloads**

```python
def download_large_file(url, filename):
    with session.get(url, stream=True) as response:
        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
```

---

# Support & Resources

## Official Documentation

- [Archer GitHub Repository](https://github.com/cmdshiftd/archer)
- [How Archer Works](http://localhost:8000/how-it-works)
- [Mapping Files Guide](docs/guides/MAPPING_FILES_GUIDE.md)

## Community

- [GitHub Issues](https://github.com/cmdshiftd/archer/issues)
- [GitHub Discussions](https://github.com/cmdshiftd/archer/discussions)

## Related Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

---

# Changelog

## Version 1.0 (2025-10-30)

- ✨ Initial API documentation release
- 📚 Documented 60+ HTTP endpoints
- 💻 Added code examples in Python, JavaScript, cURL
- 📖 Included best practices and patterns

---

**© 2025 Archer Detection Generator** | Built with ❤️ by @cmdshiftd
