# Archer API Documentation

**Version**: 1.0
**Last Updated**: 2025-10-30
**Base URL**: `http://localhost:8000` (default)

---

## Table of Contents

1. [Introduction](#introduction)
2. [Authentication](#authentication)
3. [Rate Limiting](#rate-limiting)
4. [Error Handling](#error-handling)
5. [Core API Endpoints](#core-api-endpoints)
   - [Detection Generation](#detection-generation)
   - [File Upload & Analysis](#file-upload--analysis)
   - [Progress Tracking](#progress-tracking)
   - [Detection Library](#detection-library)
   - [Company Profiling](#company-profiling)
6. [User Management](#user-management)
7. [Code Examples](#code-examples)
8. [Webhooks & Background Jobs](#webhooks--background-jobs)
9. [Best Practices](#best-practices)

---

## Introduction

The Archer API provides programmatic access to automated threat detection generation, MITRE ATT&CK intelligence processing, and security detection management. This REST API enables integration with:

- **SIEM platforms** (Splunk, Microsoft Defender, Elastic)
- **Threat intelligence feeds**
- **Purple team automation workflows**
- **Custom security orchestration tools**

### Key Features

✅ Generate production-ready detection queries from threat intelligence
✅ Upload and analyze threat reports (PDF, TXT, DOCX, etc.)
✅ Profile organizations and identify relevant threat actors
✅ Manage detection libraries with sharing and tagging
✅ Track generation progress in real-time
✅ Export detections in multiple formats (YAML, JSON, ZIP)

---

## Authentication

### Session-Based Authentication

Archer uses session-based authentication with secure HTTP-only cookies.

#### Login

```http
POST /login
Content-Type: application/x-www-form-urlencoded
Cookie: archer_csrf_session=<csrf_token>

email=user@example.com&password=your_password&csrf_token=<token>&remember_me=true
```

**Response:**
```http
HTTP/1.1 303 See Other
Set-Cookie: archer_session=<session_token>; HttpOnly; Secure; SameSite=Lax
Location: /
```

#### Logout

```http
GET /logout
Cookie: archer_session=<session_token>
```

**Response:**
```http
HTTP/1.1 303 See Other
Set-Cookie: archer_session=; Max-Age=0
Location: /login
```

### Protected Endpoints

All `/api/*` endpoints (except public ones) require authentication:

```http
GET /api/library/detections
Cookie: archer_session=<session_token>
```

**401 Unauthorized Response:**
```json
{
  "detail": "Not authenticated"
}
```

### CSRF Protection

Sensitive operations require CSRF tokens:

```http
POST /login
Cookie: archer_csrf_session=<csrf_token>
Content-Type: application/x-www-form-urlencoded

csrf_token=<token>&email=user@example.com&password=pass
```

---

## Rate Limiting

### Current Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/login` | 5 requests | 5 minutes per IP |
| `/register` | 5 requests | 5 minutes per IP |

**429 Too Many Requests Response:**
```json
{
  "detail": "Too many failed login attempts. Please try again later."
}
```

### Account Lockout

After 5 failed login attempts:
- Account locked for 15 minutes
- Status: `403 Forbidden`

---

## Error Handling

### Standard Error Response Format

```json
{
  "success": false,
  "error": "Error message",
  "detail": "Additional context"
}
```

### HTTP Status Codes

| Code | Meaning | Common Causes |
|------|---------|---------------|
| `200` | OK | Request successful |
| `303` | See Other | Redirect after POST |
| `400` | Bad Request | Invalid parameters, validation error |
| `401` | Unauthorized | Not authenticated |
| `403` | Forbidden | CSRF fail, account locked, insufficient permissions |
| `404` | Not Found | Resource doesn't exist |
| `413` | Payload Too Large | File upload exceeds 50MB |
| `429` | Too Many Requests | Rate limit exceeded |
| `500` | Internal Server Error | Server-side error |

### Error Examples

**Validation Error:**
```json
{
  "detail": "Missing required field: group_name"
}
```

**Authentication Error:**
```json
{
  "detail": "Not authenticated"
}
```

**Authorization Error:**
```json
{
  "detail": "User ID mismatch in header"
}
```

---

## Core API Endpoints

### Detection Generation

#### Generate Detections for Threat Group

Create detection queries for a known threat actor group.

```http
POST /generate
Content-Type: application/x-www-form-urlencoded

group_name=APT29&osint_enhancement=true&run_correlation=true&correlation_min_relevance=0.75
```

**Request Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `group_name` | string | ✅ | Threat actor name (e.g., "APT29", "Scattered Spider") |
| `osint_enhancement` | boolean | ❌ | Merge OSINT detection patterns (default: false) |
| `osint_comparison` | boolean | ❌ | Add OSINT comparison metadata (default: false) |
| `run_correlation` | boolean | ❌ | Generate multi-stage correlations (default: false) |
| `correlation_min_relevance` | float | ❌ | Correlation threshold 0.5-1.0 (default: 0.75) |
| `ai_generators` | boolean | ❌ | Use AI for advanced correlation (requires OpenAI key) |
| `semantic` | boolean | ❌ | Enable semantic analysis (default: false) |
| `advanced_parsing` | boolean | ❌ | Use advanced query parsing (default: false) |

**Response:**
```json
{
  "redirect": "/progress?group_name=APT29"
}
```

**Status Codes:**
- `200 OK` - Request accepted, processing started
- `400 Bad Request` - Unknown threat actor

**Example cURL:**
```bash
curl -X POST "http://localhost:8000/generate" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "group_name=APT29&osint_enhancement=true&run_correlation=true"
```

---

#### Generate Detections for CVE(s)

Create detections for specific CVE vulnerabilities.

```http
POST /generate/cve
Cookie: archer_session=<session_token>
Content-Type: application/x-www-form-urlencoded

cve_id=CVE-2021-44228,CVE-2022-22965&run_correlation=true
```

**Request Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `cve_id` | string | ✅ | Comma-separated CVE IDs (format: CVE-20XX-NNNN) |
| `run_correlation` | boolean | ❌ | Generate correlations (default: false) |
| `ai_generators` | boolean | ❌ | Use AI enhancement (default: false) |

**Response:**
```json
{
  "redirect": "/progress?group_name=CVE-2021-44228"
}
```

**Validation:**
- CVE format: `CVE-YYYY-NNNN` (4-digit year, 4+ digit ID)
- Multiple CVEs: comma-separated without spaces

**Example cURL:**
```bash
curl -X POST "http://localhost:8000/generate/cve" \
  -H "Cookie: archer_session=abc123" \
  -d "cve_id=CVE-2021-44228&run_correlation=true"
```

---

### File Upload & Analysis

#### Upload Threat Intelligence File

Upload and extract TTPs/IOCs from threat reports.

```http
POST /upload
Cookie: archer_session=<session_token>
Content-Type: multipart/form-data

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="threat_report.pdf"
Content-Type: application/pdf

<binary file data>
------WebKitFormBoundary
Content-Disposition: form-data; name="use_openai"

true
------WebKitFormBoundary--
```

**Request Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file` | file | ✅ | Threat report file |
| `use_openai` | boolean | ❌ | Use AI for extraction (default: false) |
| `auto_generate` | boolean | ❌ | Auto-generate detections (default: false) |
| `run_correlation` | boolean | ❌ | Run correlations (default: false) |

**Supported File Types:**
- Documents: `.pdf`, `.txt`, `.md`, `.docx`, `.doc`
- Data: `.json`, `.csv`, `.xlsx`, `.xls`
- Rules: `.yar`, `.yara`

**File Size Limit:** 50MB

**Response:**
```json
{
  "success": true,
  "show_extraction": true,
  "filename": "threat_report.pdf",
  "synthetic_group_name": "UploadedFile_2025103012345",
  "ttps": [
    {
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "tactics": ["Execution"],
      "description": "Uses PowerShell for execution",
      "source": "pdf:page:5"
    }
  ],
  "iocs": {
    "ip": ["192.168.1.100", "10.0.0.5"],
    "domain": ["malicious.com"],
    "hash": ["d41d8cd98f00b204e9800998ecf8427e"]
  },
  "ttps_count": 12,
  "iocs_count": 45,
  "auto_generate_requested": false
}
```

**Example Python:**
```python
import requests

with open('threat_report.pdf', 'rb') as f:
    files = {'file': ('threat_report.pdf', f, 'application/pdf')}
    data = {'use_openai': 'true', 'auto_generate': 'false'}

    response = requests.post(
        'http://localhost:8000/upload',
        files=files,
        data=data,
        cookies={'archer_session': 'your_session_token'}
    )

print(response.json())
```

---

#### Generate Detections from Uploaded File

After uploading, generate detections from extracted TTPs.

```http
POST /upload/generate
Cookie: archer_session=<session_token>
Content-Type: application/x-www-form-urlencoded

synthetic_group_name=UploadedFile_2025103012345&selected_ttps=["T1059.001","T1078"]&osint_enhancement=true
```

**Request Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `synthetic_group_name` | string | ✅ | Generated group name from upload |
| `selected_ttps` | JSON string | ❌ | Array of technique IDs to use |
| `selected_iocs` | JSON string | ❌ | Object of IOC types and values |
| `osint_enhancement` | boolean | ❌ | Enable OSINT enhancement |

**Response:**
```json
{
  "redirect": "/progress?group_name=UploadedFile_2025103012345"
}
```

---

#### Analyze Blog Post / Threat Report URL

Extract TTPs from a public threat report URL.

```http
POST /analyze_blog
Cookie: archer_session=<session_token>
Content-Type: application/x-www-form-urlencoded

url=https://example.com/threat-report&use_openai=true&auto_generate=false
```

**Request Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | ✅ | URL to threat report |
| `use_openai` | boolean | ❌ | Use AI for analysis |
| `auto_generate` | boolean | ❌ | Auto-generate detections |
| `run_correlation` | boolean | ❌ | Run correlations |

**Response:**
```json
{
  "success": true,
  "synthetic_group_name": "BlogAnalysis_2025103012345",
  "ttps": [...],
  "iocs": {...},
  "ttps_count": 8,
  "iocs_count": 23
}
```

---

### Progress Tracking

#### Get Progress Status

Poll generation progress in real-time.

```http
GET /progress_status?group_name=APT29
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `group_name` | string | ✅ | Threat group or CVE name |

**Response:**
```json
{
  "ok": true,
  "progress": {
    "status": "in_progress",
    "stage": "detections",
    "created_yaml": 45,
    "total_yaml": 120,
    "created_correlations": 12,
    "total_correlations": 50,
    "current_file": "PasstheHash_DeviceProcessEvents.yaml"
  }
}
```

**Status Values:**
- `started` - Processing initiated
- `in_progress` - Generating detections
- `correlating` - Building correlations
- `complete` - Finished successfully
- `error` - Failed

**Polling Strategy:**
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

### Detection Library

#### Get All Library Detections

Retrieve all saved detections for authenticated user.

```http
GET /api/library/detections
Cookie: archer_session=<session_token>
```

**Response:**
```json
{
  "success": true,
  "detections": [
    {
      "id": 123,
      "title": "PowerShell Execution via Rundll32",
      "detection_type": "yaml",
      "visibility": "private",
      "creator": "John Doe",
      "creator_email": "john@example.com",
      "platform": "mde",
      "tags": "[\"T1059.001\",\"Execution\",\"APT29\"]",
      "created_at": "2025-10-30T10:00:00Z",
      "is_owner": true,
      "osint_sources": ["Sigma", "Elastic"],
      "osint_compared": true,
      "osint_enhanced": true
    }
  ]
}
```

---

#### Search Library Detections

Filter detections with advanced search.

```http
POST /api/library/search
Cookie: archer_session=<session_token>
Content-Type: application/json

{
  "query": "powershell",
  "type_filter": "yaml",
  "visibility_filter": "private",
  "creator_filter": "all"
}
```

**Request Body:**

| Field | Type | Description |
|-------|------|-------------|
| `query` | string | Search in title/content |
| `type_filter` | string | "all", "yaml", "json", "correlation" |
| `visibility_filter` | string | "all", "private", "shared" |
| `creator_filter` | string | "all" or creator name |

**Response:**
```json
{
  "success": true,
  "detections": [...]
}
```

---

#### Save Detection to Library

Save a new detection to your library.

```http
POST /api/library/save
Cookie: archer_session=<session_token>
Content-Type: application/json

{
  "title": "Pass the Hash Detection",
  "detection_type": "yaml",
  "visibility": "private",
  "content": "name: PasstheHash\nid: ...",
  "platform": "mde",
  "tags": ["T1550.002", "Lateral Movement", "APT29"],
  "group": "APT29",
  "cve": null
}
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `title` | string | ✅ | Detection title |
| `detection_type` | string | ✅ | "yaml", "json", "correlation" |
| `visibility` | string | ✅ | "private" or "shared" |
| `content` | string/object | ✅ | Detection content |
| `platform` | string | ✅ | "splunk", "mde", "elastic" |
| `tags` | array | ❌ | Array of tag strings |
| `group` | string | ❌ | Associated threat group |
| `cve` | string | ❌ | Associated CVE ID |

**Response:**
```json
{
  "success": true,
  "detection_id": 456,
  "tags_saved": ["T1550.002", "Lateral Movement", "APT29"]
}
```

---

#### Update Detection Tags

Batch update tags for multiple detections.

```http
POST /api/library/tags
Cookie: archer_session=<session_token>
Content-Type: application/json

{
  "ids": [123, 456, 789],
  "tags": ["Production", "High Priority", "Reviewed"]
}
```

**Response:**
```json
{
  "success": true,
  "updated": 3
}
```

---

#### Update Detection Visibility

Change visibility for multiple detections.

```http
POST /api/library/visibility
Cookie: archer_session=<session_token>
Content-Type: application/json

{
  "ids": [123, 456],
  "visibility": "shared"
}
```

**Response:**
```json
{
  "success": true,
  "updated": 2
}
```

---

#### Export Detections

Export detections in various formats.

```http
POST /api/library/export
Cookie: archer_session=<session_token>
Content-Type: application/json

{
  "ids": [123, 456, 789],
  "format": "json"
}
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ids` | array | ✅ | Detection IDs to export |
| `format` | string | ✅ | "json", "csv", "xml" |

**Response (JSON format):**
```json
{
  "success": true,
  "data": [
    {
      "id": 123,
      "title": "...",
      "content": "...",
      ...
    }
  ],
  "count": 3
}
```

**Response (CSV/XML format):**
```
Content-Type: text/csv
Content-Disposition: attachment; filename="detections.csv"

<CSV or XML content>
```

---

#### Delete Detections

Batch delete detections from library.

```http
POST /api/library/delete
Cookie: archer_session=<session_token>
Content-Type: application/json

{
  "ids": [123, 456]
}
```

**Response:**
```json
{
  "success": true,
  "deleted": 2
}
```

**Note:** Only detection owners can delete their detections.

---

### Company Profiling

#### Profile Organization

Analyze an organization's threat landscape.

```http
POST /profile
Content-Type: application/x-www-form-urlencoded

domain=example.com&include_industry=true&include_geography=true&include_tech_stack=true&use_openai=false
```

**Request Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | string | ✅ | Company domain (e.g., "microsoft.com") |
| `include_industry` | boolean | ❌ | Industry-based threat analysis |
| `include_geography` | boolean | ❌ | Geographic threat analysis |
| `include_tech_stack` | boolean | ❌ | Technology stack analysis |
| `include_supply_chain` | boolean | ❌ | Supply chain dependency analysis |
| `use_openai` | boolean | ❌ | Use AI for enhanced profiling |
| `generate_detections` | boolean | ❌ | Auto-generate detections |

**Response:**
```json
{
  "success": true,
  "domain": "example.com",
  "company_name": "Example Corp",
  "industry": "Technology",
  "headquarters": "United States",
  "tech_stack": {
    "cloud_providers": ["AWS", "Azure"],
    "technologies": ["Windows", "Linux", "Office 365"]
  },
  "threat_groups": [
    {
      "name": "APT29",
      "relevance_score": 85,
      "reasons": [
        "Targets technology sector",
        "Known to target US companies",
        "Exploits cloud infrastructure"
      ],
      "techniques_count": 45
    }
  ],
  "supply_chain": {
    "dependencies": ["Vendor1", "Vendor2"],
    "risk_score": 72
  }
}
```

---

#### Generate Detections for Profiled Organization

Generate detections for selected threat groups from profile.

```http
POST /profile/generate-detections
Content-Type: application/x-www-form-urlencoded

domain=example.com&selected_groups=APT29,APT28&run_correlation=true
```

**Request Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | string | ✅ | Company domain |
| `selected_groups` | string | ✅ | Comma-separated threat group names |
| `run_correlation` | boolean | ❌ | Run correlations |

**Response:**
```json
{
  "redirect": "/progress?group_name=example.com_Profile"
}
```

---

### Download Endpoints

#### Download Single Detection

Download individual detection YAML file.

```http
GET /api/download/detection/PasstheHash_DeviceProcessEvents.yaml
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/x-yaml
Content-Disposition: attachment; filename="PasstheHash_DeviceProcessEvents.yaml"

name: Pass the Hash
id: 12345678-1234-1234-1234-123456789abc
technique: T1550.002
...
```

---

#### Download All Detections (ZIP)

Download complete detection package.

```http
GET /api/download/all/APT29
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/zip
Content-Disposition: attachment; filename="APT29.zip"

<ZIP file containing:>
  detections/
    PasstheHash_DeviceProcessEvents.yaml
    PowerShell_windows_events.yaml
    ...
  correlations/
    APT29.json
  attack_flows/
    APT29.json
    APT29.html
```

---

#### Get Detection Content

View detection YAML content in browser.

```http
GET /api/detection/PasstheHash_DeviceProcessEvents.yaml
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8

name: Pass the Hash
id: 12345678-1234-1234-1234-123456789abc
...
```

---

#### Download Attack Flow

Download MITRE ATT&CK Flow JSON.

```http
GET /api/download/flow/APT29.json
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Disposition: attachment; filename="APT29.json"

{
  "type": "bundle",
  "id": "bundle--...",
  "objects": [...]
}
```

---

#### View Attack Flow HTML

View interactive attack flow visualization.

```http
GET /api/attack-flow/APT29.html
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
  <head>
    <title>APT29 Attack Flow</title>
    ...
```

---

## User Management

### Registration

#### Create New User Account

```http
POST /register
Content-Type: application/x-www-form-urlencoded
Cookie: archer_csrf_session=<csrf_token>

email=newuser@example.com&full_name=John Doe&password=StrongPass123!@#&password_confirm=StrongPass123!@#&csrf_token=<token>
```

**Validation Requirements:**
- **Email**: Valid email format
- **Full Name**: 2-64 characters
- **Password**: 16-40 characters, strong complexity
- **Password Confirm**: Must match password

**Response:**
```http
HTTP/1.1 303 See Other
Location: /login?registered=true
```

---

### Password Management

#### Request Password Reset

```http
POST /api/auth/request-reset
Content-Type: application/json

{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "message": "If an account exists with this email, a reset link has been sent.",
  "reset_url": "http://localhost:8000/reset-password?token=abc123",
  "token": "abc123",
  "dev_mode": true
}
```

**Note:** In production, `reset_url`, `token`, and `dev_mode` are not included in response.

---

#### Reset Password with Token

```http
POST /api/auth/reset-password
Content-Type: application/json

{
  "token": "abc123xyz",
  "new_password": "NewStrongPass456!@#"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Password reset successful"
}
```

---

#### Change Password (Authenticated)

```http
POST /api/change-password
Cookie: archer_session=<session_token>
Content-Type: application/json

{
  "current_password": "OldPassword123!",
  "new_password": "NewPassword456!@#"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Password changed successfully"
}
```

---

### Profile Management

#### Update User Profile

```http
POST /api/profile
Cookie: archer_session=<session_token>
Content-Type: application/json

{
  "full_name": "John Smith"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Profile updated successfully"
}
```

---

#### Upload Profile Picture

```http
POST /api/profile/picture
Cookie: archer_session=<session_token>
Content-Type: multipart/form-data

------WebKitFormBoundary
Content-Disposition: form-data; name="profile_picture"; filename="avatar.jpg"
Content-Type: image/jpeg

<binary image data>
------WebKitFormBoundary--
```

**Response:**
```json
{
  "success": true,
  "url": "/static/profile_pictures/user123_avatar.jpg"
}
```

---

#### Get Activity Timeline

```http
GET /api/activities
Cookie: archer_session=<session_token>
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
      "description": "Created 120 detection queries",
      "metadata": {
        "group_name": "APT29",
        "detection_count": 120,
        "correlation_count": 45
      },
      "created_at": "2025-10-30T14:30:00Z"
    }
  ]
}
```

---

### API Keys Management

#### Get Stored API Keys (Decrypted)

```http
GET /api/profile/apikeys
Cookie: archer_session=<session_token>
```

**Response:**
```json
{
  "openai": "sk-proj-...",
  "splunk": "splunk-api-key",
  "mde": "mde-api-key",
  "elastic": "elastic-api-key",
  "anthropic": null
}
```

**Note:** Only returns keys that are set. Null values indicate no key stored.

---

#### Save API Keys (Encrypted)

```http
POST /api/profile/apikeys
Cookie: archer_session=<session_token>
Content-Type: application/json

{
  "openai": "sk-proj-your-openai-key",
  "splunk": "splunk-api-key",
  "mde": "mde-api-key",
  "elastic": "elastic-api-key",
  "anthropic": "anthropic-api-key"
}
```

**Response:**
```json
{
  "success": true,
  "message": "API keys saved successfully"
}
```

**Security:**
- Keys are encrypted using Fernet symmetric encryption
- Stored securely in user profile database
- Only accessible to authenticated user
- Decryption occurs on-demand

---

### Multi-Factor Authentication (MFA)

#### Get MFA Status

```http
GET /api/mfa/status
Cookie: archer_session=<session_token>
```

**Response:**
```json
{
  "success": true,
  "enabled": false
}
```

---

#### Setup MFA

Generate TOTP secret and QR code.

```http
POST /api/mfa/setup
Cookie: archer_session=<session_token>
```

**Response:**
```json
{
  "success": true,
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANS..."
}
```

**Usage:**
1. Scan QR code with authenticator app (Google Authenticator, Authy, etc.)
2. Enter 6-digit TOTP code to verify and enable MFA

---

#### Verify and Enable MFA

```http
POST /api/mfa/verify
Cookie: archer_session=<session_token>
Content-Type: application/json

{
  "code": "123456"
}
```

**Response:**
```json
{
  "success": true,
  "message": "MFA enabled successfully"
}
```

---

#### Disable MFA

```http
POST /api/mfa/disable
Cookie: archer_session=<session_token>
```

**Response:**
```json
{
  "success": true,
  "message": "MFA disabled successfully"
}
```

---

#### Generate Backup Codes

Generate one-time backup recovery codes.

```http
POST /api/backup-codes/generate
Cookie: archer_session=<session_token>
```

**Response:**
```json
{
  "success": true,
  "codes": [
    "ABC123-DEF456",
    "GHI789-JKL012",
    "MNO345-PQR678",
    "STU901-VWX234",
    "YZA567-BCD890"
  ]
}
```

**Important:** Store backup codes securely. They can be used once to login if MFA device is unavailable.

---

### Admin Endpoints

#### Get All Users (Admin Only)

```http
GET /api/admin/users
Cookie: archer_session=<admin_session_token>
```

**Response:**
```json
{
  "success": true,
  "users": [
    {
      "id": 1,
      "email": "admin@example.com",
      "full_name": "Admin User",
      "role": "admin",
      "is_active": true,
      "created_at": "2025-01-01T00:00:00Z",
      "is_current_user": true
    },
    {
      "id": 2,
      "email": "user@example.com",
      "full_name": "Standard User",
      "role": "standard",
      "is_active": true,
      "created_at": "2025-10-15T10:00:00Z",
      "is_current_user": false
    }
  ]
}
```

---

#### Create User (Admin Only)

```http
POST /api/admin/users
Cookie: archer_session=<admin_session_token>
Content-Type: application/json

{
  "email": "newuser@example.com",
  "full_name": "New User",
  "password": "TempPassword123!@#",
  "role": "standard"
}
```

**Response:**
```json
{
  "success": true,
  "user": {
    "id": 3,
    "email": "newuser@example.com",
    "full_name": "New User",
    "role": "standard",
    "is_active": true
  }
}
```

---

#### Update User (Admin Only)

```http
PUT /api/admin/users/2
Cookie: archer_session=<admin_session_token>
Content-Type: application/json

{
  "email": "updated@example.com",
  "full_name": "Updated Name",
  "role": "admin",
  "is_active": true
}
```

**Response:**
```json
{
  "success": true,
  "user": {
    "id": 2,
    "email": "updated@example.com",
    "full_name": "Updated Name",
    "role": "admin",
    "is_active": true
  }
}
```

---

#### Deactivate User (Admin Only)

```http
DELETE /api/admin/users/2
Cookie: archer_session=<admin_session_token>
```

**Response:**
```json
{
  "success": true,
  "message": "User deactivated successfully"
}
```

**Note:** Users cannot deactivate themselves.

---

#### Admin Password Reset

```http
POST /api/admin/reset-password
Cookie: archer_session=<admin_session_token>
Content-Type: application/json

{
  "user_id": 2,
  "new_password": "NewTempPassword456!@#"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Password reset successfully"
}
```

---

## Code Examples

### Python

#### Generate Detections for Threat Group

```python
import requests
import time

# Login
session = requests.Session()
login_response = session.post(
    'http://localhost:8000/login',
    data={
        'email': 'user@example.com',
        'password': 'your_password',
        'csrf_token': session.cookies.get('archer_csrf_session')
    }
)

# Generate detections
generate_response = session.post(
    'http://localhost:8000/generate',
    data={
        'group_name': 'APT29',
        'osint_enhancement': 'true',
        'run_correlation': 'true',
        'correlation_min_relevance': '0.75'
    }
)

redirect_url = generate_response.json()['redirect']
group_name = redirect_url.split('group_name=')[1]

# Poll progress
while True:
    progress = session.get(
        f'http://localhost:8000/progress_status?group_name={group_name}'
    ).json()

    status = progress['progress']['status']
    print(f"Status: {status}")

    if status == 'complete':
        break

    time.sleep(2)

# Download results
zip_file = session.get(f'http://localhost:8000/api/download/all/{group_name}')
with open(f'{group_name}.zip', 'wb') as f:
    f.write(zip_file.content)

print(f"Downloaded {group_name}.zip")
```

---

#### Upload and Process Threat Report

```python
import requests

session = requests.Session()
# ... login code ...

# Upload file
with open('threat_report.pdf', 'rb') as f:
    upload_response = session.post(
        'http://localhost:8000/upload',
        files={'file': ('threat_report.pdf', f, 'application/pdf')},
        data={'use_openai': 'true'}
    )

result = upload_response.json()
synthetic_group = result['synthetic_group_name']

print(f"Extracted {result['ttps_count']} TTPs and {result['iocs_count']} IOCs")

# Generate detections from extracted data
generate_response = session.post(
    'http://localhost:8000/upload/generate',
    data={
        'synthetic_group_name': synthetic_group,
        'osint_enhancement': 'true'
    }
)

print(f"Generating detections: {generate_response.json()['redirect']}")
```

---

#### Search and Export Library Detections

```python
import requests
import json

session = requests.Session()
# ... login code ...

# Search for PowerShell detections
search_response = session.post(
    'http://localhost:8000/api/library/search',
    json={
        'query': 'powershell',
        'type_filter': 'yaml',
        'visibility_filter': 'all'
    }
)

detections = search_response.json()['detections']
detection_ids = [d['id'] for d in detections]

print(f"Found {len(detection_ids)} PowerShell detections")

# Export to JSON
export_response = session.post(
    'http://localhost:8000/api/library/export',
    json={
        'ids': detection_ids,
        'format': 'json'
    }
)

with open('powershell_detections.json', 'w') as f:
    json.dump(export_response.json()['data'], f, indent=2)

print("Exported to powershell_detections.json")
```

---

### JavaScript (Node.js)

#### Generate Detections with Axios

```javascript
const axios = require('axios');
const fs = require('fs');

const client = axios.create({
  baseURL: 'http://localhost:8000',
  withCredentials: true
});

async function generateDetections() {
  // Login
  await client.post('/login', new URLSearchParams({
    email: 'user@example.com',
    password: 'your_password',
    csrf_token: client.defaults.headers.Cookie
  }));

  // Generate detections
  const generateResponse = await client.post('/generate', new URLSearchParams({
    group_name: 'APT29',
    osint_enhancement: 'true',
    run_correlation: 'true'
  }));

  const groupName = new URL(generateResponse.data.redirect, 'http://localhost:8000')
    .searchParams.get('group_name');

  // Poll progress
  while (true) {
    const progressResponse = await client.get(`/progress_status?group_name=${groupName}`);
    const status = progressResponse.data.progress.status;

    console.log(`Status: ${status}`);

    if (status === 'complete') break;

    await new Promise(resolve => setTimeout(resolve, 2000));
  }

  // Download ZIP
  const zipResponse = await client.get(`/api/download/all/${groupName}`, {
    responseType: 'arraybuffer'
  });

  fs.writeFileSync(`${groupName}.zip`, zipResponse.data);
  console.log(`Downloaded ${groupName}.zip`);
}

generateDetections().catch(console.error);
```

---

### cURL

#### Complete Workflow with cURL

```bash
#!/bin/bash

# Login and save cookies
curl -c cookies.txt -X POST "http://localhost:8000/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=user@example.com&password=your_password&csrf_token=$(curl -c cookies.txt -s http://localhost:8000/login | grep csrf_token | grep -oP 'value="\K[^"]*')"

# Generate detections
REDIRECT=$(curl -b cookies.txt -X POST "http://localhost:8000/generate" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "group_name=APT29&osint_enhancement=true&run_correlation=true" \
  | jq -r '.redirect')

GROUP_NAME=$(echo $REDIRECT | grep -oP 'group_name=\K[^&]+')

echo "Generating detections for: $GROUP_NAME"

# Poll progress
while true; do
  STATUS=$(curl -s -b cookies.txt "http://localhost:8000/progress_status?group_name=$GROUP_NAME" \
    | jq -r '.progress.status')

  echo "Status: $STATUS"

  if [ "$STATUS" = "complete" ]; then
    break
  fi

  sleep 2
done

# Download results
curl -b cookies.txt -o "${GROUP_NAME}.zip" \
  "http://localhost:8000/api/download/all/${GROUP_NAME}"

echo "Downloaded: ${GROUP_NAME}.zip"
```

---

## Webhooks & Background Jobs

### Background Processing

Archer processes long-running tasks asynchronously:

1. **Detection Generation** - Runs in background thread
2. **File Upload Processing** - Async extraction
3. **Blog Analysis** - Async scraping and parsing

### Progress Tracking Pattern

```javascript
// Client-side polling pattern
async function trackProgress(groupName) {
  const updateProgress = async () => {
    const response = await fetch(`/progress_status?group_name=${groupName}`);
    const data = await response.json();

    // Update UI
    document.getElementById('progress-bar').style.width =
      `${(data.progress.created_yaml / data.progress.total_yaml) * 100}%`;

    document.getElementById('status-text').textContent =
      `${data.progress.created_yaml} / ${data.progress.total_yaml} detections`;

    // Check completion
    if (data.progress.status === 'complete') {
      window.location.href = `/results?group_name=${groupName}`;
    } else if (data.progress.status === 'error') {
      alert('Generation failed. Please try again.');
    } else {
      // Continue polling
      setTimeout(updateProgress, 2000);
    }
  };

  updateProgress();
}
```

---

## Best Practices

### 1. Authentication & Security

✅ **Always use HTTPS in production**
```python
base_url = 'https://archer.example.com'  # Production
# base_url = 'http://localhost:8000'    # Development
```

✅ **Store credentials securely**
```python
import os
from dotenv import load_dotenv

load_dotenv()

session.post('/login', data={
    'email': os.getenv('ARCHER_EMAIL'),
    'password': os.getenv('ARCHER_PASSWORD')
})
```

✅ **Handle CSRF tokens correctly**
```python
# Get CSRF token from cookie or response
csrf_token = session.cookies.get('archer_csrf_session')
```

✅ **Enable MFA for sensitive accounts**
```bash
curl -X POST "https://archer.example.com/api/mfa/setup" \
  -H "Cookie: archer_session=$SESSION"
```

---

### 2. Error Handling

✅ **Check status codes**
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

✅ **Implement retries with backoff**
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

---

### 3. Performance Optimization

✅ **Use connection pooling**
```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retry = Retry(total=3, backoff_factor=0.3)
adapter = HTTPAdapter(max_retries=retry)
session.mount('http://', adapter)
session.mount('https://', adapter)
```

✅ **Poll efficiently**
```python
import time

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

### 4. Data Validation

✅ **Validate input before sending**
```python
import re

def validate_cve_format(cve_id):
    """Validate CVE ID format"""
    pattern = r'^CVE-\d{4}-\d{4,}$'
    return bool(re.match(pattern, cve_id))

cve_id = "CVE-2021-44228"
if validate_cve_format(cve_id):
    response = session.post('/generate/cve', data={'cve_id': cve_id})
else:
    print("Invalid CVE format")
```

✅ **Handle file size limits**
```python
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

def upload_file(file_path):
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        raise ValueError("File exceeds 50MB limit")

    with open(file_path, 'rb') as f:
        response = session.post('/upload', files={'file': f})

    return response.json()
```

---

### 5. Resource Management

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

### 6. Logging & Monitoring

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

### 7. Testing

✅ **Write integration tests**
```python
import unittest

class TestArcherAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.session = requests.Session()
        cls.session.post('/login', data={
            'email': 'test@example.com',
            'password': 'test_password'
        })

    def test_generate_detections(self):
        response = self.session.post('/generate', data={
            'group_name': 'APT29'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('redirect', response.json())

    def test_invalid_group_name(self):
        response = self.session.post('/generate', data={
            'group_name': 'NonexistentGroup123'
        })
        self.assertEqual(response.status_code, 400)

    @classmethod
    def tearDownClass(cls):
        cls.session.close()

if __name__ == '__main__':
    unittest.main()
```

---

## Additional Resources

### Official Documentation
- [Archer GitHub Repository](https://github.com/cmdaltr/archer)
- [How Archer Works](http://localhost:8000/how-it-works)
- [Mapping Files Configuration Guide](docs/guides/MAPPING_FILES_GUIDE.md)

### Community
- [GitHub Issues](https://github.com/cmdaltr/archer/issues)
- [GitHub Discussions](https://github.com/cmdaltr/archer/discussions)

### Related Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

---

## Changelog

### Version 1.0 (2025-10-30)
- Initial API documentation release
- Documented 60+ HTTP endpoints
- Added code examples in Python, JavaScript, cURL
- Included best practices and error handling patterns

---

## Support

For API support and questions:
- **Email**: [GitHub @cmdaltr](https://github.com/cmdaltr)
- **Issues**: [Report a bug](https://github.com/cmdaltr/archer/issues)
- **Discussions**: [Ask a question](https://github.com/cmdaltr/archer/discussions)

---

**© 2025 Archer Detection Generator** | Built with ❤️ by @cmdaltr
