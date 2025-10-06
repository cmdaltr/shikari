## VECTR Integration

This optional module integrates with VECTR for threat hunt tracking, documentation, and purple team collaboration.

## Overview

VECTR (https://vectr.io) is a purple team assessment and reporting tool. The Archer integration allows you to:
- Create hunt campaigns in VECTR for tracking
- Export Archer detections as VECTR test cases
- Map detections to MITRE ATT&CK techniques
- Track detection validation results
- Import test results back to enrich YAML files
- Generate coverage reports
- Manage environments and assessment groups

## Configuration

### Enable VECTR Module

```bash
export ENABLE_VECTR=true
```

### VECTR Server Setup

1. Install VECTR (see https://docs.vectr.io for installation)

2. Obtain API token from VECTR web interface:
   - Login to VECTR
   - Navigate to Settings → API Tokens
   - Create new token

3. Configure environment variables:
```bash
export VECTR_URL=https://your-vectr-server:8081
export VECTR_API_TOKEN=your-api-token-here
export VECTR_DEFAULT_CAMPAIGN="Archer-ThreatHunt"
export VECTR_DEFAULT_ENVIRONMENT="Production"
```

## Usage

### CLI Commands

#### 1. Export Detections to VECTR

Create a hunt campaign with all detections for a threat group:

```bash
# Export APT29 detections to VECTR
python3 archer.py vectr export --threat-group "APT29"
```

**Output:**
```
======================================================================
VECTR Integration - EXPORT
======================================================================

Creating campaign for APT29...
✅ Created campaign: APT29 Hunt - 2025-01-05 (ID: camp_123abc)

Creating test cases from data/generate...
✅ Created test case: Validate: PowerShell Encoded Command Execution (ID: tc_001)
✅ Created test case: Validate: Azure AD Tor Sign-In Detection (ID: tc_002)
...

✅ Created 15 test cases (2 skipped)

======================================================================
EXPORT SUMMARY
======================================================================
Campaign ID: camp_123abc
Test Cases Created: 15
Files Skipped: 2

✅ Export complete!
Campaign ID: camp_123abc
Use this ID to sync or import results later
```

**Custom Campaign Name:**
```bash
python3 archer.py vectr export \
  --threat-group "APT29" \
  --campaign-name "Q1-2025 APT29 Hunt"
```

#### 2. List Campaigns

```bash
# List all campaigns
python3 archer.py vectr list

# Filter by threat group
python3 archer.py vectr list --threat-group "APT29"
```

**Output:**
```
Found 3 campaign(s):

ID: camp_123abc
Name: APT29 Hunt - 2025-01-05
Group: APT29
Status: active
Created: 2025-01-05T10:30:00Z
----------------------------------------------------------------------
...
```

#### 3. Import Test Results

After running tests in VECTR, import results back to update detection confidence:

```bash
python3 archer.py vectr import \
  --campaign-id camp_123abc \
  --update-yamls
```

This will:
- Fetch test results from VECTR
- Update YAML files with `vectr_validation` section
- Add detection confidence scores
- Track false positive rates

**Updated YAML Example:**
```yaml
name: PowerShell Encoded Command Execution
description: Detects execution of encoded PowerShell commands
query: |
  DeviceProcessEvents
  | where ProcessCommandLine has "-encodedcommand"

# Added by VECTR import
vectr_validation:
  campaign_id: camp_123abc
  test_case_id: tc_001
  status: completed
  result: pass
  detected: true
  confidence: high
  tested_date: 2025-01-05T14:30:00Z
  false_positives: 0
```

#### 4. Bidirectional Sync

Keep Archer and VECTR synchronized:

```bash
# Export new detections AND import test results
python3 archer.py vectr sync \
  --campaign-id camp_123abc \
  --threat-group "APT29"
```

#### 5. Coverage Report

Generate detection coverage report:

```bash
python3 archer.py vectr coverage --campaign-id camp_123abc
```

**Output:**
```
# VECTR Coverage Report: APT29 Hunt - 2025-01-05

Generated: 2025-01-05T16:00:00Z

## Summary
- Total Test Cases: 15
- Pending: 3
- Completed: 12

## Test Results
- Passed: 10
- Failed: 2
- Partial: 0
- Skipped: 0

## Coverage by Technique
- T1003.001: 2 test case(s)
- T1059.001: 3 test case(s)
- T1071.001: 2 test case(s)
...

## Coverage by Tactic
- Credential Access: 4 test case(s)
- Execution: 5 test case(s)
- Command and Control: 2 test case(s)
...

## Coverage by Platform
- windows: 12 test case(s)
- azure: 3 test case(s)
```

### Programmatic Usage

```python
from archer.vectr import VECTRClient, CampaignManager, TestCaseManager, export_to_vectr

# Initialize client
client = VECTRClient()

# Test connection
if client.test_connection():
    print("Connected to VECTR!")

# Create campaign
campaign_mgr = CampaignManager(client)
campaign = campaign_mgr.create_hunt_campaign(
    name="APT29 Hunt Q1 2025",
    threat_group="APT29",
    description="Comprehensive hunt for APT29 TTPs",
    environment="Production"
)

# Create test cases from detections
testcase_mgr = TestCaseManager(client)
summary = testcase_mgr.bulk_create_from_directory(
    campaign_id=campaign['id'],
    yaml_dir="data/generate",
    filter_group="APT29"
)

print(f"Created {summary['created']} test cases")

# Update test result
testcase_mgr.update_test_result(
    campaign_id=campaign['id'],
    testcase_id="tc_001",
    result="pass",
    detected=True,
    notes="Detection triggered successfully with no false positives"
)

# Get coverage
coverage = testcase_mgr.get_detection_coverage(campaign['id'])
print(f"Techniques covered: {len(coverage['by_technique'])}")
```

## Workflow Integration

### Complete Hunt Workflow

```bash
# Step 1: Generate detections for threat group
python3 archer.py generate "APT29"

# Step 2: Run emulation tests
python3 archer.py emulate T1059.001 --enrich
python3 archer.py emulate T1071.001 --enrich

# Step 3: Build correlations
python3 archer.py correlate --verbose

# Step 4: Export to VECTR for tracking
python3 archer.py vectr export --threat-group "APT29"

# (Conduct hunt operations, test detections in VECTR)

# Step 5: Import results and update confidence
python3 archer.py vectr import \
  --campaign-id camp_123abc \
  --update-yamls

# Step 6: Generate coverage report
python3 archer.py vectr coverage --campaign-id camp_123abc > report.md
```

## VECTR Test Case Structure

When Archer exports detections to VECTR, each test case includes:

### Basic Information
- **Name**: `Validate: {Detection Name}`
- **Description**: Detection description from YAML
- **Technique IDs**: MITRE ATT&CK technique mappings
- **Tactics**: Associated tactics
- **Platforms**: Target platforms (windows, linux, azure, etc.)

### Test Details
- **Test Type**: `detection_validation`
- **Detection Query**: Full KQL/Splunk query
- **Detection Platform**: Query platform (mde, splunk, sentinel)
- **Detection File**: Source YAML file path

### Operator Guidance

If emulation evidence is available, test cases include guidance:
```
**Sample Commands:**
- `powershell.exe -nop -w hidden -encodedcommand ...`
- `powershell.exe -EncodedCommand ...`

**Expected Processes:**
- powershell.exe
- powershell.exe (encoded)
```

### Red Team Tools

Recommended tools for testing:
- Atomic Red Team (if emulation evidence exists)
- Custom tools based on detection context

## Benefits

### 1. Hunt Tracking
- Organize detections into campaigns
- Track testing status and results
- Document hunt operations

### 2. Team Collaboration
- Share detections with red/purple teams
- Provide operator guidance for testing
- Track false positive rates

### 3. Coverage Analysis
- Identify gaps in detection coverage
- Map coverage to MITRE ATT&CK
- Track progress across environments

### 4. Continuous Improvement
- Import test results to update confidence
- Identify detections needing refinement
- Build evidence-based detection library

## Data Flow

### Export Flow
```
Archer Detections (YAML)
  ↓
VECTR Campaign Created
  ↓
Test Cases Generated
  ↓
Purple Team Testing
  ↓
Results Recorded in VECTR
```

### Import Flow
```
VECTR Test Results
  ↓
Archer Import
  ↓
YAML Files Updated
  ↓
vectr_validation Section Added
  ↓
Detection Confidence Scored
```

### Sync Flow (Bidirectional)
```
New Archer Detections → VECTR (Export)
VECTR Test Results → Archer (Import)
```

## Output Files

### Campaign Exports
```
data/vectr/campaigns/
├── APT29_Hunt_2025-01-05.json
├── ScatteredSpider_Hunt_2025-01-06.json
└── .gitkeep
```

### Export Structure
```json
{
  "campaign": {
    "id": "camp_123abc",
    "name": "APT29 Hunt - 2025-01-05",
    "threat_group": "APT29",
    "status": "active",
    "created_date": "2025-01-05T10:30:00Z"
  },
  "test_cases": [
    {
      "id": "tc_001",
      "name": "Validate: PowerShell Encoded Command Execution",
      "technique_ids": ["T1059.001", "T1027"],
      "tactics": ["Execution", "Defense Evasion"],
      "status": "completed",
      "result": "pass",
      "detected": true
    }
  ],
  "export_date": "2025-01-05T16:00:00Z",
  "exported_by": "archer"
}
```

## Troubleshooting

### Module Not Enabled

```
ERROR: VECTR module is not enabled.
```

**Solution:**
```bash
export ENABLE_VECTR=true
```

### Not Configured

```
ERROR: VECTR is not configured.
```

**Solution:**
```bash
export VECTR_URL=https://your-vectr-server:8081
export VECTR_API_TOKEN=your-api-token
```

### Connection Failed

```
VECTR API request failed: Connection refused
```

**Solutions:**
1. Verify VECTR server is running
2. Check URL is correct (including port)
3. Verify SSL certificate if using HTTPS
4. Check firewall rules

### Authentication Failed

```
VECTR API request failed: 401 Unauthorized
```

**Solutions:**
1. Verify API token is correct
2. Check token hasn't expired
3. Ensure user has proper permissions

### Campaign Not Found

```
ERROR: --campaign-id required for import
```

**Solution:**
1. Use `vectr list` to find campaign IDs
2. Or export creates new campaign and returns ID

## API Endpoints Used

Archer uses the following VECTR API endpoints:

- `GET /api/v1/campaigns` - List campaigns
- `POST /api/v1/campaigns` - Create campaign
- `GET /api/v1/campaigns/{id}` - Get campaign details
- `GET /api/v1/campaigns/{id}/testcases` - List test cases
- `POST /api/v1/campaigns/{id}/testcases` - Create test case
- `PUT /api/v1/campaigns/{id}/testcases/{tc_id}` - Update test case
- `GET /api/v1/environments` - List environments
- `GET /api/v1/assessmentgroups` - List assessment groups

## Future Enhancements

- [ ] Web UI for VECTR integration
- [ ] Automated test scheduling in VECTR
- [ ] Real-time sync webhooks
- [ ] Multi-environment deployment tracking
- [ ] VECTR template customization
- [ ] Advanced coverage analytics
- [ ] Integration with VECTR reporting
- [ ] Purple team playbook generation
