# OSINT Detection Enhancement System

**Last Updated:** 2025-11-14
**Status:** ✅ Fully Operational
**Version:** 2.0

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Detection Generation](#detection-generation)
4. [Correlation Integration](#correlation-integration)
5. [OSINT Sources](#osint-sources)
6. [Repository Management](#repository-management)
7. [Query Snippet Extraction](#query-snippet-extraction)
8. [Badge System](#badge-system)
9. [Reports and Metadata](#reports-and-metadata)
10. [Error Handling](#error-handling)
11. [Usage and Configuration](#usage-and-configuration)
12. [Troubleshooting](#troubleshooting)
13. [Examples and Best Practices](#examples-and-best-practices)

---

## Overview

The OSINT (Open Source Intelligence) Enhancement system automatically searches external threat intelligence sources to improve detection quality. It operates throughout the entire detection lifecycle - from initial rule generation through correlation and reporting.

### Operational Modes

1. **FIND Mode**: When NO indicators are found in MITRE ATT&CK, search OSINT to discover indicators
2. **ENRICH Mode**: When indicators ARE found in MITRE, enhance them with additional OSINT patterns
3. **CORRELATE Mode**: Aggregate OSINT metadata across multiple detections in correlation rules
4. **REPORT Mode**: Display OSINT enrichment information in generated reports

This comprehensive approach ensures all detections benefit from the latest community threat intelligence beyond MITRE ATT&CK.

### Key Features

- ✅ **Automatic Enhancement** - Runs during detection generation
- ✅ **5 OSINT Sources** - Sigma, Elastic, MITRE CAR, Splunk, Azure Sentinel
- ✅ **Local Repositories** - No API rate limits, fast searches (<1s)
- ✅ **Platform-Aware** - Extracts Azure operations and AWS API calls
- ✅ **Query Snippets** - Provides actionable detection patterns for cloud platforms
- ✅ **Badge System** - Visual indicators for OSINT-only detections
- ✅ **Generic Term Filtering** - Prevents low-quality detections
- ✅ **Correlation Integration** - OSINT metadata flows through to correlation rules
- ✅ **Report Generation** - OSINT information included in Word/PDF/HTML reports
- ✅ **Graceful Degradation** - Works with partial repository availability

---

## Architecture

### Detection Generation Flow

```
┌─────────────────────────────────────┐
│  Parse MITRE ATT&CK Technique Data  │
└──────────────┬──────────────────────┘
               │
               ▼
      ┌────────────────┐
      │ Extract IOCs   │
      └────────┬───────┘
               │
               ▼
   ┌───────────────────────┐
   │ Filter Generic Terms  │
   │ Remove: condition,    │
   │ value, data, file,    │
   │ process, command, etc │
   └───────────┬───────────┘
               │
   ┌───────────┴────────────────┐
   │                            │
Has Real IOCs            No Real IOCs
   │                            │
   ▼                            ▼
┏━━━━━━━━━━━━━━━━━━┓    ┏━━━━━━━━━━━━━━━━━━┓
┃ PATH 1: ENRICH   ┃    ┃ PATH 2: FIND     ┃
┃ Add OSINT for    ┃    ┃ Search OSINT to  ┃
┃ higher fidelity  ┃    ┃ find indicators  ┃
┗━━━━━━━┬━━━━━━━━━━┛    ┗━━━━━━━┬━━━━━━━━━━┛
        │                        │
        ▼                        ▼
┌──────────────────┐    ┌──────────────────┐
│ Search Sources:  │    │ Search Sources:  │
│ • Sigma Rules    │    │ • Sigma Rules    │
│ • MITRE CAR      │    │ • MITRE CAR      │
│ • Elastic Rules  │    │ • Elastic Rules  │
│ • Splunk Content │    │ • Splunk Content │
│ • Azure Sentinel │    │ • Azure Sentinel │
└─────────┬────────┘    └─────────┬────────┘
          │                        │
          ▼                        ▼
┌──────────────────┐    ┌──────────────────┐
│ Merge MITRE +    │    │ Use OSINT as     │
│ OSINT IOCs       │    │ Primary IOCs     │
│ (dedupe)         │    │ (Orange Badge)   │
└─────────┬────────┘    └─────────┬────────┘
          │                        │
          └────────────┬───────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ Create Detection │
              │ with OSINT Meta  │
              └─────────┬────────┘
                        │
                        ▼
                 ┌──────────────┐
                 │  YAML File   │
                 └──────┬───────┘
                        │
                        ▼
             ┌────────────────────┐
             │ Correlation Engine │
             │ (Aggregate OSINT)  │
             └──────────┬─────────┘
                        │
                        ▼
                ┌───────────────┐
                │ Report Export │
                │ (Show OSINT)  │
                └───────────────┘
```

### Generic Term Filtering

To prevent low-quality detections, 33 generic terms are filtered:

```python
generic_terms = {
    'condition', 'conditions', 'value', 'values', 'data', 'file', 'files',
    'process', 'processes', 'command', 'commands', 'user', 'users',
    'system', 'event', 'events', 'log', 'logs', 'entry', 'entries',
    'action', 'actions', 'type', 'types', 'name', 'names', 'path',
    'paths', 'string', 'strings', 'text', 'info', 'information'
}
```

**Filtering Logic:**
- Applied during detection generation AND results display
- If all indicators are generic → treat as "no indicators" → trigger OSINT search
- If some indicators are real → create detection normally with OSINT enrichment

---

## Detection Generation

### New Features Added for Cloud Operations

#### 1. API Indicator Type

**Added to:** `indicatorMapping.json`, `schemaSplunk.json`

Unified indicator type for all cloud operations (Azure + AWS):

```json
{
  "api": {
    "Splunk": {
      "azure_signin": ["operation_name", "activity_display_name"],
      "azure_activity": ["operationName", "operation"],
      "aws_cloudtrail": ["event_name", "eventName"],
      "aws_guardduty": ["api_call", "finding_type"]
    }
  }
}
```

**Impact:**
- Cloud techniques now generate AWS detections (previously missing)
- Azure operations and AWS API calls use same `api` indicator type
- Techniques like AdditionalCloudRoles now create both Azure and AWS detections

#### 2. OSINT Snippet Extraction

**Function:** `extract_operations_from_osint_snippets()` in `osint_comparison.py`

Parses OSINT query snippets to extract structured indicators:

```python
def extract_operations_from_osint_snippets(osint_indicators: Dict) -> Dict[str, List[str]]:
    """
    Extract structured API calls from OSINT query snippets.

    Parses snippets like:
    - [Elastic] operation_name:"Add member to role"
    - [Splunk] eventName IN ("CreatePolicyVersion","AttachUserPolicy")

    Returns:
        {
          "api": ["Add member to role", "CreatePolicyVersion", ...],
          "cmd": [...]
        }
    """
```

#### 3. Pipeline Integration

**Files Updated:**
1. `collate.py` - Extracts and passes OSINT indicators
2. `yaml.py` - Passes OSINT indicators and writes metadata
3. `queries.py` - Merges OSINT indicators into query search clause

**Flow:**
```
OSINT Metadata → extract_operations_from_osint_snippets() →
Structured Indicators → collate_data() → compile_splunk_queries() →
Query with OSINT operations
```

### OSINT Metadata in Detection YAML Files

Individual detection YAML files include comprehensive OSINT metadata:

```yaml
# OSINT Comparison Metadata
osint_compared: true
osint_enhanced: true
comparison_date: 2024-11-13
osint_sources:
  - Elastic
  - Splunk
  - Sigma
osint_indicators:
  cmd:
    - mimikatz.exe
    - sekurlsa::logonpasswords
  sw:
    - powershell.exe
    - rundll32.exe
  api:
    - Add member to role
osint_query_snippets:
  - source: Elastic
    query: 'operation_name:"Add member to role"'
    url: https://github.com/elastic/detection-rules/...
  - source: Splunk
    query: 'Operation IN ("CreatePolicyVersion","AttachUserPolicy")'
    url: https://github.com/splunk/security_content/...
enrichment_notes: |
  Successfully enriched query with 15 OSINT indicators from 3 sources
```

---

## Correlation Integration

### OSINT Tracking in Correlation JSON

Correlation files automatically include aggregated OSINT metadata from all constituent detection queries:

```json
{
  "correlation_id": "CORR-0001",
  "name": "Correlation: Credential Access + Lateral Movement",
  "platform": "mde",
  "query_count": 3,
  "osint_enriched": true,
  "osint_sources": [
    "Elastic",
    "Sigma",
    "Splunk"
  ],
  "osint_indicators": {
    "cmd": ["mimikatz.exe", "procdump.exe", "lsass.exe"],
    "sw": ["powershell.exe", "psexec.exe"],
    "api": ["Add member to role", "CreatePolicyVersion"]
  },
  "osint_enrichment_count": 2,
  "osint_enriched_queries": [
    {
      "name": "OS Credential Dumping: LSASS Memory",
      "osint_enhanced": true,
      "osint_sources": ["Elastic", "Splunk"],
      "osint_indicators": {
        "cmd": ["mimikatz.exe", "sekurlsa::logonpasswords"],
        "sw": ["procdump.exe"]
      }
    },
    {
      "name": "Use Alternate Authentication Material: Pass the Hash",
      "osint_enhanced": true,
      "osint_sources": ["Sigma"],
      "osint_indicators": {
        "cmd": ["sekurlsa::pth"]
      }
    }
  ]
}
```

### Data Flow for Correlations

```
Detection Generation:
MITRE ATT&CK → Extract Indicators → OSINT Search → Merge Indicators →
Generate Enhanced Query → Write YAML with OSINT Metadata

Correlation Generation:
Read Detection YAMLs → Extract Queries + OSINT Metadata →
Score Relevance → Generate JOIN Query → Create Correlation JSON with OSINT Data

Report Generation:
Read Detections/Correlations → Parse OSINT Metadata →
Generate Report with OSINT Sections → Export to Word/PDF/HTML
```

### Benefits for Correlation Analysis

**For Security Analysts:**
1. **Source Attribution**: Know which indicators came from OSINT vs. MITRE
2. **Validation Confidence**: Use OSINT source URLs to verify indicator accuracy
3. **Investigation Context**: Understand which community detections informed the rule
4. **Quality Assessment**: Identify correlations with strong OSINT backing

**For Detection Engineers:**
1. **Transparency**: Clear visibility into OSINT contributions to detections
2. **Maintenance**: Track when OSINT enrichment occurred for update planning
3. **Coverage**: Identify detections that could benefit from additional OSINT
4. **Collaboration**: Reference community detection sources for improvement ideas

---

## OSINT Sources

### Local Repository Method

All OSINT sources are cloned locally for fast, offline-capable searches:

| Repository | Size | Rules | Clone Time | Search Time | Update Frequency |
|-----------|------|-------|------------|-------------|------------------|
| **SigmaHQ/sigma** | 30MB | 3,065 | ~3s | <1s | Hourly |
| **elastic/detection-rules** | 106MB | 1,504 | ~10s | <1s | Hourly |
| **mitre-attack/car** | 5MB | 200+ | ~1s | <1s | Hourly |
| **splunk/security_content** | 58MB | 1,800+ | ~5s | ~1s | Hourly |
| **Azure/Azure-Sentinel** | 256MB | 1,000+ | ~60s | ~2s | Hourly |
| **Total** | **~455MB** | **7,569+** | **~80s** | **<5s** | **Hourly** |

### Benefits Over API Method

- ✅ **No Rate Limits** - GitHub API limits (60/hour unauthenticated, 5000/hour authenticated) eliminated
- ✅ **Fast Searches** - Local grep <1 second vs 5-10 seconds per API call
- ✅ **Offline Capable** - Works without internet after initial clone
- ✅ **More Results** - Process all matching files vs API's limited results
- ✅ **Reliable** - No network errors or timeouts during searches

### What Each Source Provides

#### 1. Sigma Rules (SigmaHQ/sigma)
- **Focus:** Generic detection rules in vendor-neutral YAML format
- **Extracts:** CommandLine patterns, Image/Process names, Registry keys, Network indicators
- **Best For:** Endpoint detections (Windows, Linux, macOS)

#### 2. Elastic Detection Rules
- **Focus:** Elasticsearch/Kibana detection rules
- **Extracts:** EQL queries, KQL queries, field names, specific values
- **Best For:** Cloud detections (Azure, AWS, GCP), SIEM queries

#### 3. MITRE CAR (Cyber Analytics Repository)
- **Focus:** Behavioral analytics and pseudocode implementations
- **Extracts:** Analytics descriptions, data requirements, implementations
- **Best For:** Detection analytics, correlation rules

#### 4. Splunk Security Content
- **Focus:** Splunk SPL detection searches
- **Extracts:** SPL queries, field names, lookup tables, detection logic
- **Best For:** Splunk-specific detections, SPL query patterns

#### 5. Azure Sentinel
- **Focus:** Azure Sentinel KQL detection rules
- **Extracts:** KQL queries, Azure-specific field names, hunting queries
- **Best For:** Azure AD, Office 365, Azure Security Center detections

---

## Repository Management

### Storage Location

```
data/osint_repos/
├── sigma/           # 30MB, 3,065 rules
├── elastic/         # 106MB, 1,504 rules
├── mitre_car/       # 5MB, 200+ analytics
├── splunk/          # 58MB, 1,800+ detections
└── azure_sentinel/  # 256MB, 1,000+ rules
Total: ~455MB
```

### Automatic Updates

**Trigger:** Web app startup + every OSINT search
**Frequency:** Repos updated if >1 hour old
**Method:** `git pull --depth 1` for existing repos, `git clone --depth 1` for new
**Fallback:** If update fails, uses existing local copy

### Initialization

Repositories are automatically cloned/updated when:
1. **App Startup** - FastAPI `@app.on_event("startup")` hook
2. **Docker Start** - Dockerfile includes initialization
3. **First OSINT Search** - Fallback if startup failed

### Manual Update

```bash
# Update all OSINT repositories
python scripts/update_osint_repos.py

# Force update even if recently updated
python scripts/update_osint_repos.py --force
```

### Air-Gapped Deployment

**On internet-connected machine:**
```bash
# 1. Update all repositories
python scripts/update_osint_repos.py --force

# 2. Create archive
cd /path/to/archer
tar -czf osint_repos.tar.gz data/osint_repos/

# 3. Transfer osint_repos.tar.gz to air-gapped machine
```

**On air-gapped machine:**
```bash
# 4. Extract
cd /path/to/archer
tar -xzf osint_repos.tar.gz

# 5. Verify
ls -lh data/osint_repos/
```

The app will detect existing repos and skip cloning.

---

## Query Snippet Extraction

### What Are Query Snippets?

Query snippets are detection query patterns extracted from OSINT sources. They provide:

- **Exact field names** specific to log sources
- **Specific values** like API operation names, event types, status codes
- **Known identifiers** such as role GUIDs, resource IDs, error codes
- **Detection patterns** showing how vendors structure their queries

### Why Query Snippets Matter for Cloud

For cloud techniques, query snippets ARE the indicators because cloud detections focus on:
- API operation names (not processes)
- Resource IDs (not file paths)
- Service events (not endpoint logs)
- Identity operations (not registry keys)

### Example: T1098.003 - Additional Cloud Roles

#### Without OSINT (Generic):
```splunk
index=azure_signin
| search operation_name="*role*"
```
❌ Too broad, catches benign role views, poor performance

#### With OSINT Query Snippets:
```splunk
index=azure_signin
| where operation_name IN (
    "Add member to role",
    "Update role setting in PIM",
    "Add eligible member to role",
    "Add scoped member to role"
  )
  AND result_type="0"  /* Success */
| eval role_id=mvindex('modified_property_new_value', 0)
| where role_id IN (
    "62e90394-69f5-4237-9190-012177145e10",  /* Global Administrator */
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  /* Security Administrator */
    "729827e3-9c14-49f7-bb1b-9608f156bbb8"   /* Helpdesk Administrator */
  )
```
✅ Specific operations, privileged role GUIDs, success filtering, field extraction

### Query Snippet Sources

**From Elastic:**
```
event.dataset:azure.auditlogs and
azure.auditlogs.operation_name:"Update role setting in PIM" and
event.outcome:(Success or success)
```

**From Splunk Security Content:**
```spl
`o365_management_activity`
Workload=AzureActiveDirectory
Operation="Add member to role"
| eval role_id=mvindex('ModifiedProperties{}.NewValue', 0)
| where role_id IN ("62e90394-69f5-4237-9190-012177145e10")
```

### How Analysts Use Query Snippets

**Step 1:** Review OSINT details in detection YAML

**Step 2:** Extract field names
- From snippet: `azure.auditlogs.operation_name`
- Verify in your environment (may be just `operation_name`)

**Step 3:** Copy specific values
- `"Add member to role"`, `"Update role setting in PIM"`

**Step 4:** Incorporate GUIDs/IDs
- Role GUID `62e90394-69f5-4237-9190-012177145e10` = Global Administrator
- Add to query for high-fidelity alerting

**Step 5:** Validate & tune
- Run in test environment
- Adjust field names for your log format
- Add exclusions for known-good activity

---

## Badge System

### No Badge (Normal Detection - OSINT Enriched)

- **Condition:** Detection has real indicators from MITRE ATT&CK (after filtering generic terms)
- **Display:** No badge shown
- **Checkbox:** Checked by default
- **Examples:** AADInternals, powershell.exe, Connect-AZAccount
- **OSINT Enrichment:** YES - All detections with indicators are automatically enriched
- **Metadata:** OSINT sources and enrichment date included in YAML (if OSINT found)

### Orange Badge ("Needs Review - enriched with additional OSINT")

- **Condition:** Detection created ONLY from OSINT research (no MITRE indicators or only generic terms)
- **Display:** Orange badge with sun/sparkle icon
- **Checkbox:** Unchecked by default (requires review)
- **OSINT Enrichment:** YES - OSINT was the primary source of indicators
- **Metadata:** OSINT sources and enrichment date included in YAML

### No Detection Created

- **Condition:** No real indicators AND no OSINT enrichment found
- **Examples:** Techniques with only generic terms like "condition", "value", "data"
- **Behavior:** Detection generation skipped entirely

---

## Reports and Metadata

### OSINT Information in Reports

Generated reports (Word, PDF, HTML) now display OSINT enrichment information:

#### Detection-Level OSINT Information
- **Enrichment Status**: Visual indicator showing if query was enhanced with OSINT
- **OSINT Sources**: List of OSINT repositories used (Elastic, Splunk, Sigma, etc.)
- **Color Coding**:
  - Green ✓ for queries enriched with OSINT indicators
  - Blue ℹ for queries compared but not enhanced

#### Correlation-Level OSINT Information
- **Enrichment Count**: Shows how many of the correlated queries were OSINT-enriched
- **Aggregated Sources**: Combined list of all OSINT sources across queries
- **Indicator Summary**: Count of aggregated OSINT indicators by type

### Report Sections

**Word Report Sections:**
- Detection Rules → OSINT Enrichment (per detection)
- Correlation Rules → OSINT Enrichment (aggregated)

**HTML Report Sections:**
- Color-coded OSINT status badges
- Expandable OSINT source lists
- Indicator type breakdowns

### Implementation Files

**Modified Files:**
1. **`archer/build/yaml.py`** (lines 349-371)
   - Added `osint_query_snippets` section to detection YAML files
   - Parses and formats OSINT query snippets with source attribution

2. **`archer/genai/engine.py`** (lines 2472-2494, 2713-2803)
   - Extracts OSINT metadata from detection YAMLs
   - Aggregates OSINT indicators across multiple detections in correlations
   - Includes OSINT enrichment data in correlation output JSON

3. **`archer/reports/generator.py`** (lines 229-245, 351-378, 702-710)
   - Displays OSINT enrichment status in Word reports
   - Shows OSINT sources and indicator counts in correlation sections
   - Includes color-coded OSINT indicators in HTML reports

---

## Error Handling

### User Experience

#### 1. Initial Loading Screen

When Archer starts, a loading overlay shows real-time status of each OSINT repository:

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

**Visual Indicators:**
- 🔄 **Spinner** (animated): Repository is currently being cloned
- ✅ **Checkmark** (green): Repository successfully cloned and ready
- ❌ **Cross** (red): Repository failed to clone

#### 2. Failure Prompt

If repositories fail to clone, failed repos show a red cross with error message and action buttons:

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

**User Options:**
- **Retry:** Reloads page to restart initialization (use if failure was temporary)
- **Continue:** Accepts partial initialization, uses available repositories

### Backend State Tracking

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

### API Endpoints

**GET /api/status/osint** - Returns current initialization status:
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

**POST /api/status/osint/accept-failures** - User accepts partial initialization:
```json
{
  "accepted": true,
  "message": "Continuing without failed repositories"
}
```

### Common Errors

#### Timeout while cloning
**Cause:** Repository too large for connection speed, or git operation exceeded 5-minute timeout
**Solutions:**
1. Click "Continue" to use other repos
2. Click "Retry" when network improves
3. For air-gapped environments, manually copy repos

#### Clone failed
**Cause:** Git error, network issue, or insufficient disk space
**Solutions:**
1. Check internet connectivity
2. Ensure sufficient disk space (Azure Sentinel alone is 256MB)
3. Check git is installed and accessible

---

## Usage and Configuration

### Automatic Integration

OSINT enrichment runs automatically during detection generation:

```python
# In archer/build/detections.py - compile_query()
if not identifiers or not has_real_indicators:
    # No real MITRE indicators - try OSINT
    osint_found, osint_data = search_osint_for_technique(
        technique_id=tid,
        technique_name=name,
        technique_description=technique_description,
        platforms=technique_platforms
    )

    if should_create_detection(has_mitre_indicators=False, osint_found=osint_found):
        # Create detection with OSINT metadata
        construct_yaml(..., osint_enrichment=osint_data)
```

### Viewing OSINT Data in Correlations

After generating correlations for a threat group:

```bash
python archer/parsers/correlations.py --threat-group APT29
```

The output JSON file will include OSINT metadata for analysis:

```python
import json

with open('data/correlate/APT29.json') as f:
    data = json.load(f)

for correlation in data['correlations']:
    if correlation.get('osint_enriched'):
        print(f"Correlation {correlation['correlation_id']}:")
        print(f"  - Enriched Queries: {correlation['osint_enrichment_count']}/{correlation['query_count']}")
        print(f"  - Sources: {', '.join(correlation['osint_sources'])}")
        print(f"  - Indicators: {sum(len(v) for v in correlation['osint_indicators'].values())} total")
```

### No Configuration Required

The local repository approach **does not require a GitHub token** or any environment variables. All OSINT searches are performed against local clones.

### Directories Created Automatically

```bash
# OSINT repository clones (updated hourly)
data/osint_repos/
  ├── sigma/           # 30MB, 3,065 rules
  ├── elastic/         # 106MB, 1,504 rules
  ├── mitre_car/       # 5MB, 200+ analytics
  ├── splunk/          # 58MB, 1,800+ detections
  └── azure_sentinel/  # 256MB, 1,000+ rules
  Total: ~455MB

# OSINT search result cache (24 hours)
data/osint_cache/
```

### Add to .gitignore

```
data/osint_repos/
data/osint_cache/
```

---

## Troubleshooting

### Script Hangs During Repository Clone

**Problem:** Azure Sentinel clone takes >30 minutes or appears to hang

**Solution:**
```bash
# Kill the process
pkill -f "update_osint_repos"

# Try again with better network connection
python scripts/update_osint_repos.py --force
```

**Note:** Azure Sentinel is ~256MB and can take 10-20 minutes on slower connections. This is normal.

### Permission Denied Errors

**Problem:** Cannot create `data/osint_repos/` directory

**Solution:**
```bash
# Check permissions
ls -ld data/

# Fix permissions if needed
chmod 755 data/
mkdir -p data/osint_repos
```

### Git Not Installed

**Problem:** `git: command not found`

**Solution:**
```bash
# macOS
xcode-select --install

# Linux (Ubuntu/Debian)
sudo apt-get install git

# Linux (RHEL/CentOS)
sudo yum install git
```

### Disk Space Issues

**Problem:** Not enough space for repositories (~455MB required)

**Solution:**
```bash
# Check available space
df -h .

# Clean up old cache if needed
python scripts/cleanup.py
rm -rf data/osint_cache/*

# Minimum required: 1GB free space
```

### OSINT Enrichment Not Working

**Problem:** Detections generated but no OSINT enrichment applied

**Checklist:**
1. Verify repositories are cloned: `ls -lh data/osint_repos/`
2. Check repository sizes are reasonable (not empty)
3. Test OSINT functionality: `python scripts/test_osint.py`
4. Check logs for errors during detection generation
5. Verify network connectivity (for initial clone)

**Force re-clone:**
```bash
# Remove existing repos
rm -rf data/osint_repos/

# Re-clone fresh
python scripts/update_osint_repos.py --force
```

### Missing AWS Detections for Cloud Techniques

**Problem:** AdditionalCloudRoles or CloudInfrastructureDiscovery only has Azure detections, no AWS

**Solution:** This was fixed by adding the `api` indicator type. If still missing:
1. Verify `api` type exists in `indicatorMapping.json`
2. Check OSINT enhancement is enabled in web UI
3. Regenerate detections for the technique

---

## Examples and Best Practices

### Query Snippets vs Traditional IOCs

| Aspect | Traditional IOCs | Query Snippets |
|--------|------------------|----------------|
| **Use Case** | Endpoint detections | Cloud/SaaS detections |
| **Examples** | `wmic.exe`, `powershell.exe` | `azure.auditlogs.operation_name` |
| **What They Provide** | File names, hashes, IPs | Field names, API operations, patterns |
| **Detection Type** | Signature-based | Behavior-based |
| **Platform** | Windows, Linux, macOS | Azure, AWS, GCP, O365 |

### Best Practices for Query Snippets

#### DO:
✅ Copy exact field names from snippets
✅ Use specific operation names (not wildcards)
✅ Include known identifiers (role GUIDs, error codes)
✅ Apply filters from OSINT examples (service account exclusions)
✅ Cross-reference multiple sources for validation

#### DON'T:
❌ Blindly copy entire queries without understanding them
❌ Assume field names are identical across all log sources
❌ Ignore exclusion patterns (false positive filters)
❌ Skip validation in your environment
❌ Forget to tune thresholds for your baseline

---

## Files Modified

### Core Implementation

| File | Purpose | Changes |
|------|---------|---------|
| `archer/build/osint_enrichment.py` | Main OSINT search logic | Created |
| `archer/build/osint_repos.py` | Repository cloning/updating | Created |
| `archer/build/osint_comparison.py` | Query snippet extraction | Added `extract_operations_from_osint_snippets()` |
| `archer/build/detections.py` | Detection generation | Added generic term filtering, OSINT integration |
| `archer/build/collate.py` | Data collation | Added `osint_indicators` parameter |
| `archer/build/yaml.py` | YAML generation | Added OSINT metadata handling, query snippets |
| `archer/build/queries.py` | Query compilation | Added OSINT indicator merging |
| `archer/genai/engine.py` | Correlation engine | Added OSINT metadata extraction and aggregation |
| `archer/reports/generator.py` | Report generation | Added OSINT display sections |

### Mapping Files

| File | Changes |
|------|---------|
| `archer/mappings/indicatorMapping.json` | Added `api` indicator type |
| `archer/mappings/schemaSplunk.json` | Added transformation pipelines for `api` type |

### Frontend

| File | Purpose |
|------|---------|
| `archer/app.py` | OSINT status API endpoints, indicator extraction |
| `templates/index.html` | Loading screen, failure prompt UI |
| `templates/results.html` | Badge display, technique formatting |

### Scripts

| File | Purpose |
|------|---------|
| `scripts/update_osint_repos.py` | Manual repository update script |
| `scripts/test_osint.py` | OSINT functionality testing |

---

## Summary

The OSINT Enhancement System transforms generic MITRE ATT&CK descriptions into actionable detections throughout the entire detection lifecycle by:

1. **Precision** - Exact field names and values to search
2. **Context** - How the security community detects each technique
3. **Validation** - Cross-vendor confirmation of detection patterns
4. **Tuning** - Known false positive filters and thresholds
5. **Correlation** - Aggregated OSINT metadata across multiple detections
6. **Reporting** - Comprehensive OSINT information in generated reports

It is especially critical for cloud detections where traditional endpoint IOCs don't exist, making query snippets the primary "indicators" for Azure, AWS, GCP, and SaaS platform detections.

**Key Metrics:**
- ✅ 7,569+ detection rules from 5 sources
- ✅ ~455MB total repository size
- ✅ <5 seconds total search time
- ✅ No API rate limits (local repositories)
- ✅ Offline capable after initial clone
- ✅ Automatic hourly updates
- ✅ Graceful degradation with partial availability
- ✅ Full integration with correlations and reports

**Last Updated:** 2025-11-14
