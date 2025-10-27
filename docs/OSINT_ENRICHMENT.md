# OSINT Enrichment Implementation

## Overview

The OSINT (Open Source Intelligence) Enrichment system automatically searches external threat intelligence sources to enhance detection quality:

1. **When NO indicators are found**: Search OSINT to find indicators for detection creation
2. **When indicators ARE found**: Enrich with OSINT to increase detection fidelity

This dual approach ensures all detections benefit from the latest threat intelligence beyond MITRE ATT&CK.

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
                   ┌───────────────┴────────────────┐
                   │                                │
            Has Real IOCs                    No Real IOCs
                   │                                │
                   │                                │
                   ▼                                ▼
    ┏━━━━━━━━━━━━━━━━━━━━━━━━┓     ┏━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃  PATH 1: ENRICHMENT    ┃     ┃  PATH 2: FIND           ┃
    ┃  Search OSINT to       ┃     ┃  Search OSINT to        ┃
    ┃  INCREASE fidelity     ┃     ┃  FIND indicators        ┃
    ┗━━━━━━━━━┬━━━━━━━━━━━━━━┛     ┗━━━━━━━━━┬━━━━━━━━━━━━━━━┛
              │                              │
              ▼                              ▼
    ┌──────────────────┐          ┌──────────────────┐
    │ Search Sources:  │          │ Search Sources:  │
    │ • Sigma Rules    │          │ • Sigma Rules    │
    │ • MITRE CAR      │          │ • MITRE CAR      │
    │ • Elastic Rules  │          │ • Elastic Rules  │
    └─────────┬────────┘          └─────────┬────────┘
              │                              │
              ▼                              ▼
    ┌──────────────────┐          ┌──────────────────┐
    │ OSINT Found?     │          │ OSINT Found?     │
    └───┬──────────┬───┘          └───┬──────────┬───┘
        │ YES  NO  │                  │ YES  NO  │
        │      │   │                  │      │   │
        ▼      │   │                  ▼      │   │
    ┌──────────────┐ │          ┌──────────────┐ │
    │ Merge MITRE  │ │          │ Use OSINT as │ │
    │ + OSINT IOCs │ │          │ Primary IOCs │ │
    │ (dedupe)     │ │          └──────┬───────┘ │
    └──────┬───────┘ │                 │         │
           │         │                 │         │
           └─────────┼─────────────────┘         │
                     │                           │
                     ▼                           ▼
            ┌──────────────────┐      ┌──────────────────┐
            │ Create Detection │      │ Skip Detection   │
            │ with IOCs        │      │ Creation         │
            └─────────┬────────┘      └──────────────────┘
                      │
                      ▼
               ┌──────────────┐
               │  YAML File   │
               └──────┬───────┘
                      │
          ┌───────────┴────────────┐
          │                        │
          ▼                        ▼
    ┌──────────┐            ┌──────────┐
    │ No Badge │            │  Orange  │
    │ (Normal) │            │  Badge   │
    └──────────┘            └──────────┘
    MITRE IOCs              OSINT-only
    + OSINT enrichment      (no MITRE IOCs)
    ✓ Checked               ✗ Unchecked

KEY CONCEPTS:
• Generic term filtering ensures quality before OSINT search
• OSINT ALWAYS runs (both paths) to maximize detection fidelity
• PATH 1: Has indicators → Enrich with OSINT for higher fidelity
• PATH 2: No indicators → Find indicators through OSINT
• Orange badge = OSINT-only detections (need review)
• No badge = MITRE-based detections (may include OSINT enrichment)
```

## Badge System

### No Badge (Normal Detection - OSINT Enriched)
- **Condition**: Detection has real indicators extracted from MITRE ATT&CK (after filtering generic terms)
- **Display**: No badge shown
- **Checkbox**: Checked by default
- **Examples**: AADInternals, powershell.exe, Connect-AZAccount
- **OSINT Enrichment**: YES - All detections with indicators are automatically enriched with OSINT to increase fidelity
- **Metadata**: OSINT sources and enrichment date included in YAML (if OSINT found)

### Orange Badge ("Needs Review - enriched with additional OSINT")
- **Condition**: Detection created ONLY from OSINT research (no MITRE indicators or only generic MITRE terms)
- **Display**: Orange badge with sun/sparkle icon
- **Checkbox**: Unchecked by default
- **OSINT Enrichment**: YES - OSINT was the primary source of indicators
- **Metadata**: OSINT sources and enrichment date included in YAML

### No Detection Created
- **Condition**: No real indicators AND no OSINT enrichment found
- **Examples**: Techniques with only generic terms like "condition", "value", "data"
- **Behavior**: Detection generation skipped entirely

## Generic Term Filtering

### Overview

To prevent low-quality detections, Archer filters out overly generic terms that provide minimal detection value. This filtering occurs during both:
1. **Detection generation** (prevents creation of poor-quality detections)
2. **Results display** (ensures accurate indicator counts)

### Filtered Generic Terms

The following terms are considered too generic to be useful indicators:

```python
generic_terms = {
    'condition', 'conditions', 'value', 'values', 'data', 'file', 'files',
    'process', 'processes', 'command', 'commands', 'user', 'users',
    'system', 'event', 'events', 'log', 'logs', 'entry', 'entries',
    'action', 'actions', 'type', 'types', 'name', 'names', 'path',
    'paths', 'string', 'strings', 'text', 'info', 'information'
}
```

### Filtering Logic

**During Detection Generation:**
```python
# In archer/build/detections.py - compile_query()
filtered_identifiers, has_real_indicators = filter_generic_indicators(identifiers)

if not has_real_indicators and identifiers:
    # All indicators are generic - treat as no indicators
    print(f" ⚠️  All indicators are generic terms")
    print(f" 🔍 Treating as no indicators - will attempt OSINT enrichment")
    identifiers = {}  # Clear to trigger OSINT path
```

**During Results Display:**
```python
# In archer/app.py - extract_indicators_from_query()
for item in indicators:
    if item.lower() in generic_terms:
        continue  # Skip generic term
    unique_indicators.append(item)
```

### Example Scenarios

**Scenario 1: Generic-only indicators**
- **Input**: `has_any("condition")` from MITRE
- **After Filtering**: 0 real indicators
- **Behavior**: Triggers OSINT enrichment
- **Result**: Detection created only if OSINT finds real indicators

**Scenario 2: Mixed indicators**
- **Input**: `has_any("AADInternals", "condition")` from MITRE
- **After Filtering**: 1 real indicator (`AADInternals`)
- **Behavior**: Creates detection normally
- **Result**: Detection with no badge

**Scenario 3: No indicators**
- **Input**: No indicators from MITRE
- **After Filtering**: 0 indicators
- **Behavior**: Triggers OSINT enrichment
- **Result**: Detection created with orange badge if OSINT succeeds

### Cloud Service Commands

In addition to filtering generic terms, Archer actively extracts cloud service commands:

```python
# Pattern matches PowerShell cmdlets and cloud CLI commands
cloud_cmd_pattern = r'["\*]+(Connect-[A-Z][A-Za-z]+|gcloud|aws\s+[a-z]+|az\s+[a-z]+)["\*]+'
```

**Extracted Commands:**
- PowerShell Azure cmdlets: `Connect-AZAccount`, `Connect-MgGraph`, `Set-AzContext`
- Cloud CLI tools: `gcloud`, `aws`, `az`

This ensures cloud-related detections properly show indicators even when they use command-line tools.

## OSINT Sources Searched

### 1. Sigma Rules (SigmaHQ/sigma) - LOCAL REPO
- **Method**: Local repository clone + grep search
- **Repository**: https://github.com/SigmaHQ/sigma
- **Size**: ~30MB, 3,065 detection rules
- **Clone Time**: ~3 seconds (one-time)
- **Update Frequency**: Every 1 hour (automatic)
- **Search Time**: <1 second per technique
- **Extraction**: CommandLine, Image, TargetFilename patterns from Sigma YAML
- **No API limits**: Completely offline after initial clone

### 2. Elastic Detection Rules - LOCAL REPO
- **Method**: Local repository clone + grep search
- **Repository**: https://github.com/elastic/detection-rules
- **Size**: ~106MB, 1,504 detection rules
- **Clone Time**: ~10 seconds (one-time)
- **Update Frequency**: Every 1 hour (automatic)
- **Search Time**: <1 second per technique
- **Extraction**: Queries and metadata from TOML files
- **No API limits**: Completely offline after initial clone

### 3. MITRE CAR (Cyber Analytics Repository) - LOCAL REPO
- **Method**: Local repository clone + grep search
- **Repository**: https://github.com/mitre-attack/car
- **Size**: ~5MB, 200+ analytics
- **Clone Time**: ~1 second (one-time)
- **Update Frequency**: Every 1 hour (automatic)
- **Search Time**: <1 second per technique
- **Extraction**: Analytics and pseudocode implementations
- **No API limits**: Completely offline after initial clone

### 4. Splunk Security Content - LOCAL REPO
- **Method**: Local repository clone + grep search
- **Repository**: https://github.com/splunk/security_content
- **Size**: ~58MB, 1,800+ detections
- **Clone Time**: ~5 seconds (one-time)
- **Update Frequency**: Every 1 hour (automatic)
- **Search Time**: ~1 second per technique
- **Extraction**: SPL search queries and detection metadata from YAML
- **No API limits**: Completely offline after initial clone

### 5. Azure Sentinel - LOCAL REPO
- **Method**: Local repository clone + grep search
- **Repository**: https://github.com/Azure/Azure-Sentinel
- **Size**: ~256MB, 1,000+ detection rules
- **Clone Time**: ~60 seconds (one-time)
- **Update Frequency**: Every 1 hour (automatic)
- **Search Time**: ~2 seconds per technique
- **Extraction**: KQL queries and rule metadata from YAML/JSON
- **No API limits**: Completely offline after initial clone

## Local Repository Management

### Repository Storage
`data/osint_repos/`
- **sigma/**: Sigma rules repository (30MB, 3,065 rules)
- **elastic/**: Elastic detection rules repository (106MB, 1,504 rules)
- **mitre_car/**: MITRE CAR analytics (5MB, 200+ analytics)
- **splunk/**: Splunk Security Content (58MB, 1,800+ detections)
- **azure_sentinel/**: Azure Sentinel rules (256MB, 1,000+ rules)
- **Total**: ~455MB for all 5 repositories

### Automatic Updates
- **Trigger**: Web app startup + every OSINT search
- **Frequency**: Repos updated if >1 hour old
- **Method**: `git pull --depth 1` for existing repos, `git clone --depth 1` for new
- **Fallback**: If update fails, uses existing local copy

### Initialization
Repos are automatically cloned/updated when:
1. **App Startup**: FastAPI `@app.on_event("startup")` hook
2. **Docker Start**: Dockerfile can include initialization
3. **First OSINT Search**: Fallback if startup failed

### Benefits Over API
- **No Rate Limits**: GitHub API limits (60/hour unauthenticated, 5000/hour authenticated) eliminated
- **Fast Searches**: Local grep is <1 second vs 5-10 seconds per API call
- **Offline Capable**: Works without internet after initial clone
- **More Results**: Can process all matching files vs API's limited results
- **Reliable**: No network errors or timeouts during searches

## Caching System

### Cache Location
`data/osint_cache/`

### Cache Structure
```json
{
  "technique_id": "T1078",
  "cached_at": "2024-10-24T12:00:00Z",
  "data": {
    "osint_enriched": true,
    "osint_sources": [
      "https://github.com/SigmaHQ/sigma/...",
      "https://car.mitre.org/analytics/CAR-2021-01-001"
    ],
    "osint_indicators": {
      "cmd": ["powershell.exe", "cmd.exe /c"],
      "file": ["C:\\Windows\\System32\\cmd.exe"]
    },
    "enrichment_date": "2024-10-24T12:00:00Z",
    "enrichment_notes": "Found 3 Sigma rule(s); Found 1 MITRE CAR analytic(s)"
  }
}
```

### Cache Expiration
- **Duration**: 24 hours
- **Purpose**: Reduce API calls, improve performance
- **Behavior**: Cached results (both positive and negative) reused within 24 hours

## YAML Metadata

### OSINT-Enriched Detection Example

```yaml
id: 3907b960-eaee-4833-96ca-2cee3769c8b6
name: ValidAccounts
description: |
  Detection for Valid Accounts technique
# ... standard fields ...

# OSINT Enrichment Metadata
osint_enriched: true
enrichment_date: 2024-10-24T12:00:00Z
osint_sources:
  - https://github.com/SigmaHQ/sigma/rules/windows/process_creation/proc_creation_win_susp_commands.yml
  - https://car.mitre.org/analytics/CAR-2021-01-001
enrichment_notes: |
  Found 3 Sigma rule(s); Found 1 MITRE CAR analytic(s)
```

## API Rate Limiting

### GitHub API Limits
- **Unauthenticated**: 60 requests/hour
- **Authenticated**: 5000 requests/hour
- **Recommendation**: Set `GITHUB_TOKEN` environment variable

### Rate Limiting Strategy
- 500ms delay between requests
- Early termination if rate limit reached (403 response)
- Cache results to minimize repeat requests

## Configuration

### No Environment Variables Required!
The new local repository approach **does not require a GitHub token** or any environment variables. All OSINT searches are performed against local clones of the repositories.

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

### Add to `.gitignore`

```
data/osint_repos/
data/osint_cache/
```

## Air-Gapped Deployment

### Using the Update Script

For air-gapped environments, use the standalone update script:

**On an internet-connected machine:**
```bash
# Update all OSINT repositories
python scripts/update_osint_repos.py

# Force update even if recently updated
python scripts/update_osint_repos.py --force
```

**Transfer to air-gapped environment:**
```bash
# 1. On internet-connected machine, create archive
cd /path/to/archer
tar -czf osint_repos.tar.gz data/osint_repos/

# 2. Transfer osint_repos.tar.gz to air-gapped machine

# 3. On air-gapped machine, extract
cd /path/to/archer
tar -xzf osint_repos.tar.gz
```

The script will:
- Clone all 5 OSINT repositories (~455MB total)
- Update existing repositories if needed
- Show progress and statistics
- Respect the 1-hour update interval (unless --force is used)

### Update Frequency

On internet-connected systems, repositories are automatically updated:
- **Hourly check**: Repos update if >1 hour old
- **Startup check**: Verified on application startup
- **Manual update**: Run `python scripts/update_osint_repos.py --force`

For air-gapped systems, update as needed:
- Weekly updates recommended for latest detections
- Monthly updates minimum for active threats

## Usage

### Automatic Integration

OSINT enrichment runs automatically during detection generation when no MITRE indicators are found:

```python
# In archer/build/detections.py - compile_query()
if not identifiers:
    # No MITRE indicators - try OSINT
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

### Manual Testing

```python
from archer.build.osint_enrichment import search_osint_for_technique

# Search for OSINT data
found, data = search_osint_for_technique(
    technique_id="T1078",
    technique_name="Valid Accounts",
    technique_description="...",
    platforms=["Windows", "Linux"]
)

if found:
    print(f"Sources: {data['osint_sources']}")
    print(f"Indicators: {data['osint_indicators']}")
```

## Files Modified

### Core Implementation
- **archer/build/osint_enrichment.py** - Main OSINT search logic
- **archer/build/detections.py** - Integration with detection generation and generic term filtering
  - Added `filter_generic_indicators()` function (lines 13-58)
  - Applied filtering before detection creation (lines 242-250)
- **archer/build/yaml.py** - YAML metadata handling

### Display Logic
- **archer/app.py** - Detection loading, OSINT flag detection, and indicator extraction
  - Added generic term filtering to `extract_indicators_from_query()` (lines 370-400)
  - Added cloud service command extraction (lines 314-318)
  - Added technique name formatting with spaces (lines 2710-2711)
- **templates/results.html** - Badge display and CSS
  - Removed correlation description redundancy (line 1073)

### Removed Files
- **latest.yaml** - No longer used (removed references from app.py and progress.js)

## UI/UX Improvements

### Technique Name Formatting

Technique names are now automatically formatted with spaces for better readability:

**Before:**
- `ConditionalAccessPolicies`
- `MultiFactorAuthentication`
- `TrustModification`

**After:**
- `Conditional Access Policies`
- `Multi Factor Authentication`
- `Trust Modification`

**Implementation:**
```python
# In archer/app.py - format_technique_name()
if not technique_upper.startswith("T"):
    # Format CamelCase technique names with spaces
    technique_display = format_technique_name(technique)
```

### Correlation Display Cleanup

Removed redundant vendor/data source labels from correlation descriptions:

**Before:**
```
Correlation: Multi-Factor Authentication (MDE) → Trust Modification (MDE)
```

**After:**
```
Multi-Factor Authentication → Trust Modification
```

The vendor (MDE/Splunk) is shown separately in the blue vendor badge, eliminating redundancy.

### Debug Logging Cleanup

Removed excessive debug messages while keeping important warnings:

**Removed:**
- Progress bar state logging every 1.5 seconds
- Correlation calculation debug messages
- Redirect check verbose logging

**Kept:**
- Error messages (`console.error`)
- Unexpected status warnings (`console.warn`)
- Backend completion confirmations
- Progress anomaly warnings

## Error Handling

### Network Errors
- Gracefully handle timeouts (10s timeout per request)
- Log errors but continue with other sources
- Cache negative results to avoid repeated failures

### Rate Limit Errors
- Detect 403 responses from GitHub API
- Skip remaining requests for that source
- Log warning message

### Parsing Errors
- Handle malformed JSON responses
- Handle missing fields in source data
- Continue processing other sources

## Performance Considerations

### API Call Optimization
- **Parallel Searches**: Currently sequential (can be parallelized)
- **Early Termination**: Stop after finding sufficient indicators
- **Cache First**: Always check cache before making API calls

### Indicator Extraction
- Limit extracted indicators (3 per type per source)
- Limit total sources cached (10 max)
- Filter duplicates

## Future Enhancements

### Additional OSINT Sources
1. **Splunk Security Content** - GitHub repo search
2. **Atomic Red Team** - Test procedures → detection opportunities
3. **LOLBAs/GTFOBins** - Living-off-the-land techniques
4. **Threat Intelligence Blogs** - Vendor research posts

### Advanced Features
1. **Confidence Scoring** - Rank OSINT sources by reliability
2. ~~**Indicator Quality** - Filter low-quality/generic indicators~~ ✅ **IMPLEMENTED**
3. **Platform-Specific Search** - Target searches by platform
4. **Parallel API Calls** - Use async/await for faster searches
5. **User Feedback Loop** - Learn from manual reviews

## Troubleshooting

### No OSINT Results Found
- Check internet connectivity
- Verify GitHub API is accessible
- Check cache directory permissions
- Enable debug logging

### Rate Limit Errors
- Set `GITHUB_TOKEN` environment variable
- Reduce search frequency
- Clear cache to force refresh

### Orange Badge Not Showing
- Verify `osint_enriched: true` in YAML file
- Check app.py logs for parsing errors
- Verify template CSS loaded correctly

## Testing

### Unit Tests
```bash
# Test OSINT search functions
python -m pytest tests/test_osint_enrichment.py
```

### Integration Tests
```bash
# Generate detections with OSINT enrichment
python -m archer.build.orchestrator process_group "Test Group"
```

### Manual Verification
1. Generate detections for a technique with no MITRE indicators
2. Check console output for OSINT search messages
3. Verify YAML file contains `osint_enriched: true`
4. Check results page shows orange badge

---

## Summary of Recent Changes

### 2024-10-24: Universal OSINT Enrichment ✅
- **Enhancement**: ALL detections with indicators are now enriched with OSINT
- **Previous Behavior**: OSINT only searched when NO indicators found
- **New Behavior**:
  1. **No indicators** → Search OSINT to FIND indicators
  2. **Has indicators** → Enrich with OSINT to INCREASE fidelity
- **Impact**: Higher detection quality across ALL detections, not just OSINT-only ones
- **Implementation**: OSINT indicators merged with MITRE indicators, duplicates removed

### 2024-10-24: Generic Term Filtering ✅
- **Problem**: Low-quality detections created with generic indicators like "condition", "value", "data"
- **Solution**: Filter out 33 generic terms during detection generation and results display
- **Impact**: Higher quality detections, fewer false positives, automatic OSINT fallback

### 2024-10-24: OSINT Enrichment Integration ✅
- **Trigger**: ALWAYS - for both finding and enriching indicators
- **Sources**: Sigma Rules, MITRE CAR, Elastic Detection Rules
- **Caching**: 24-hour cache to optimize performance
- **Badge**: Orange badge ONLY for OSINT-only detections (no MITRE indicators)

### Detection Quality Improvements ✅
1. **Generic-only indicators** → OSINT enrichment attempted to find real indicators
2. **No indicators + No OSINT** → Detection NOT created
3. **Real indicators** → OSINT enrichment adds additional indicators for fidelity
4. **Cloud commands extracted** → Connect-AZAccount, gcloud, aws, az

### UI/UX Enhancements ✅
1. **Technique names formatted** → "Conditional Access Policies" vs "ConditionalAccessPolicies"
2. **Correlation descriptions cleaned** → Removed redundant vendor labels
3. **Debug logging reduced** → Cleaner console output, kept important warnings
4. **Progress bar fixed** → Proper completion detection and auto-redirect

### Files Modified
- `archer/build/detections.py` - Generic term filtering function
- `archer/build/osint_enrichment.py` - OSINT search implementation
- `archer/app.py` - Indicator extraction, technique formatting, cloud commands
- `templates/results.html` - UI improvements
- `static/js/progress.js` - Progress bar fixes, logging cleanup

### Testing Recommendations
1. **Regenerate detections** for existing threat groups to apply filtering
2. **Verify** techniques with generic terms (e.g., "Conditional Access Policies") are either:
   - Not created (if no OSINT found), or
   - Created with orange badge (if OSINT found)
3. **Check** cloud service detections show indicators (Connect-AZAccount, gcloud, etc.)
4. **Confirm** technique names display with spaces in results page

## Troubleshooting

### Script Hangs During Repository Clone

**Problem**: Azure Sentinel clone takes >30 minutes or appears to hang

**Solution**:
```bash
# Kill the process
pkill -f "update_osint_repos"

# Try again with better network connection
python scripts/update_osint_repos.py --force
```

**Note**: Azure Sentinel is ~256MB and can take 10-20 minutes on slower connections. This is normal.

### Permission Denied Errors

**Problem**: Cannot create `data/osint_repos/` directory

**Solution**:
```bash
# Check permissions
ls -ld data/

# Fix permissions if needed
chmod 755 data/
mkdir -p data/osint_repos
```

### Git Not Installed

**Problem**: `git: command not found`

**Solution**:
```bash
# macOS
xcode-select --install

# Linux (Ubuntu/Debian)
sudo apt-get install git

# Linux (RHEL/CentOS)
sudo yum install git
```

### Disk Space Issues

**Problem**: Not enough space for repositories (~455MB required)

**Solution**:
```bash
# Check available space
df -h .

# Clean up old cache if needed
python scripts/cleanup.py
rm -rf data/osint_cache/*

# Minimum required: 1GB free space
```

### OSINT Enrichment Not Working

**Problem**: Detections generated but no OSINT enrichment applied

**Checklist**:
1. Verify repositories are cloned: `ls -lh data/osint_repos/`
2. Check repository sizes are reasonable (not empty)
3. Test OSINT functionality: `python scripts/test_osint.py`
4. Check logs for errors during detection generation
5. Verify network connectivity (for initial clone)

**Force re-clone**:
```bash
# Remove existing repos
rm -rf data/osint_repos/

# Re-clone fresh
python scripts/update_osint_repos.py --force
```

### Rate Limit Errors (Legacy API Method)

**Problem**: GitHub API rate limit exceeded

**Solution**: This should not occur with the local repository method. If you see rate limit errors:
1. Verify you're using the latest version of Archer
2. Check that `archer/build/osint_enrichment.py` uses local repo searches, not API calls
3. Update to the latest code if using old API-based method

---

## Query Snippets: Detailed Examples

### What Are Query Snippets?

**Query snippets** are detection query patterns extracted from OSINT sources (Elastic, Splunk, Azure Sentinel). They provide the most valuable enrichment for cloud-based detections where traditional endpoint IOCs don't apply.

Query snippets show:
- **Exact field names**: Field names specific to the log source
- **Specific values**: API operation names, event types, status codes
- **Known identifiers**: Role GUIDs, resource IDs, error codes
- **Detection patterns**: How vendors structure their queries

---

### Example 1: T1098.003 - Additional Cloud Roles (Azure)

#### MITRE ATT&CK Baseline

**What MITRE Provides:**
- Technique ID: T1098.003
- Description: "Adversaries may add additional cloud roles to maintain persistent access"
- Platforms: Azure AD, Office 365, IaaS

**Generic Detection (MITRE-only):**
```spl
index=azure_signin
| search operation_name="*role*"
| table _time, user, operation_name, result
```

❌ **Issues**: 
- Wildcard search (performance impact)
- Too broad (catches benign role views)
- Missing specific privileged role operations

---

#### OSINT Query Snippets

**From Elastic Detection Rules:**
```
event.dataset:azure.auditlogs and
azure.auditlogs.operation_name:"Update role setting in PIM" and
event.outcome:(Success or success)
```

**What This Reveals:**
- Field name: `azure.auditlogs.operation_name` (not just `operation_name`)
- Specific operation: `"Update role setting in PIM"` (Privileged Identity Management)
- Success filter: `event.outcome:(Success or success)`

---

**From Splunk Security Content:**
```spl
`o365_management_activity`
Workload=AzureActiveDirectory
Operation="Add member to role"
| eval role_id=mvindex('ModifiedProperties{}.NewValue', 0)
| where role_id IN (
    "62e90394-69f5-4237-9190-012177145e10",  /* Global Admin */
    "194ae4cb-b126-40b2-bd5b-6091b380977d"   /* Security Admin */
  )
```

**What This Reveals:**
- Specific operation: `"Add member to role"`
- Field extraction pattern: `mvindex('ModifiedProperties{}.NewValue', 0)`
- **Critical**: Known privileged role GUIDs to filter for high-value targets

---

#### Enhanced Detection (MITRE + OSINT)

```spl
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
    "729827e3-9c14-49f7-bb1b-9608f156bbb8",  /* Helpdesk Administrator */
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"   /* SharePoint Administrator */
  )
| stats count values(operation_name) as operations by
    _time, user_principal_name, target_user_principal_name, role_id
| sort - _time
```

**Improvements From OSINT:**
1. ✅ Specific operations (no wildcards)
2. ✅ Privileged role GUIDs from community intelligence
3. ✅ Success-only filtering (`result_type="0"`)
4. ✅ Field extraction patterns for nested JSON
5. ✅ Statistical aggregation approach

---

### Example 2: T1136.001 - Create Account (Endpoint)

#### MITRE ATT&CK Baseline

**What MITRE Provides:**
- Description: "Adversaries may create a local account"
- Detection: "Monitor for command-line parameters associated with account creation"

**Generic Detection:**
```spl
index=windows_events EventCode=4720
| table _time, device, user, new_account_name
```

❌ **Issues**:
- Windows Event ID only (misses command-line creation)
- No macOS/Linux coverage
- No service account filtering

---

#### OSINT Indicators & Snippets

**From Sigma Rules (Indicators):**

Commands:
- `create`
- `addUser`
- `net user /add`
- `/useradd`

Software/Processes:
- `net.exe`
- `wmic.exe`
- `/dscl`
- `/sysadminctl`

---

**From Elastic (Query Snippet):**
```
event.code:"4720" and
winlog.event_data.TargetUserName:* and
not user.name:("DWM-*" or "UMFD-*")
```

**What This Reveals:**
- Service account filter: Exclude `DWM-*`, `UMFD-*` (Desktop Window Manager, User Mode Driver Framework)
- Field name: `winlog.event_data.TargetUserName`

---

**From Sigma (macOS Detection):**
```yaml
detection:
  selection_dscl:
    Image|endswith: '/dscl'
    CommandLine|contains: 'create'
  selection_sysadminctl:
    Image|endswith: '/sysadminctl'
    CommandLine|contains: 'addUser'
```

**What This Reveals:**
- macOS account creation tools: `/dscl`, `/sysadminctl`
- Command patterns to match

---

#### Enhanced Detection (Multi-Platform)

```spl
index IN (windows_events, edr_events, linux_syslog)
(
  /* Windows Event ID 4720 */
  (EventCode=4720 AND sourcetype="WinEventLog:Security")
  OR
  /* Windows Command Line */
  (
    process_name IN ("net.exe", "wmic.exe") AND
    process_command_line IN ("*user*add*", "*user*/add*", "*localgroup*administrators*/add*")
  )
  OR
  /* macOS Commands */
  (
    process_name IN ("/dscl", "/sysadminctl", "/usr/bin/dscl") AND
    process_command_line IN ("*create*", "*addUser*")
  )
  OR
  /* Linux Commands */
  (
    process_name IN ("useradd", "/usr/sbin/useradd") AND
    process_command_line="*"
  )
)
/* Filter out service accounts from OSINT examples */
| where NOT match(new_account_name, "(?i)DWM-|UMFD-|NT AUTHORITY")
| stats count values(process_command_line) as commands by
    _time, device, user, process_name, new_account_name, parent_process_name
| where count < 5  /* Unusual to create many accounts */
```

**Improvements From OSINT:**
1. ✅ Multi-platform coverage (Windows, macOS, Linux)
2. ✅ Multiple detection methods (events + process monitoring)
3. ✅ Service account exclusions from Elastic
4. ✅ Specific tools and command patterns from Sigma
5. ✅ Statistical anomaly (count < 5)

---

### Example 3: T1078.004 - Valid Accounts: Cloud Accounts

#### MITRE ATT&CK Baseline

**What MITRE Provides:**
- Description: "Adversaries may obtain and abuse credentials of cloud accounts"
- Platforms: IaaS, SaaS, Office 365

**Generic Detection:**
```spl
index=azure_signin
| search signin*
| where result_type!=0
| table _time, user, src_ip, result_description
```

❌ **Issues**:
- Only detects failed logins (misses successful compromises)
- No geolocation anomaly detection
- No impossible travel detection

---

#### OSINT Query Snippets

**From Elastic (Azure Signin from Rare Location):**
```
event.dataset:azure.signinlogs and
azure.signinlogs.properties.status.errorCode:0 and
not azure.signinlogs.properties.user_principal_name:*#EXT#* and
event.outcome:success
```

**What This Reveals:**
- Field: `azure.signinlogs.properties.status.errorCode`
- Success code: `0` (not just `result_type`)
- External user filter: Exclude `*#EXT#*` (guest accounts)

---

**From Splunk (Impossible Travel):**
```spl
`azure_monitor_aad`
operationName="Sign-in activity"
| iplocation src_ip
| eval City=if(isnull(City),"Unknown",City)
| streamstats current=f last(City) as prevCity last(_time) as prevTime window=2 by user
| eval timeDelta=((_time - prevTime) / 3600)
| eval distanceKM=...  /* Haversine formula */
| eval speedKPH=(distanceKM / timeDelta)
| where speedKPH > 800  /* Impossible to travel this fast */
```

**What This Reveals:**
- Operation name: `"Sign-in activity"`
- **Advanced pattern**: Geolocation tracking with `iplocation`
- **Calculation**: Speed-based impossible travel detection (> 800 KPH)
- **Window function**: `streamstats` to compare sequential logins

---

#### Enhanced Detection (Anomaly-Based)

```spl
index=azure_signin operationName="Sign-in activity"
| where result_type="0"  /* Success */
| where NOT match(user_principal_name, "#EXT#")  /* Exclude guests */
| iplocation src_ip
| eval City=if(isnull(City), "Unknown", City)
| eval Country=if(isnull(Country), "Unknown", Country)
/* Track previous login */
| streamstats current=f
    last(City) as prevCity
    last(Country) as prevCountry
    last(latitude) as prevLat
    last(longitude) as prevLon
    last(_time) as prevTime
    window=2 by user_principal_name
/* Calculate travel metrics */
| eval timeDeltaHours=((_time - prevTime) / 3600)
| eval distance=6371*acos(
    cos(radians(latitude))*cos(radians(prevLat))*
    cos(radians(prevLon)-radians(longitude))+
    sin(radians(latitude))*sin(radians(prevLat))
  )  /* Haversine formula for km */
| eval speedKPH=round(distance / timeDeltaHours, 2)
/* Flag anomalies */
| where speedKPH > 800 OR
    (City != prevCity AND timeDeltaHours < 1) OR
    (Country != prevCountry AND Country != "Unknown" AND prevCountry != "Unknown")
| table _time, user_principal_name, src_ip, City, Country,
    prevCity, prevCountry, speedKPH, timeDeltaHours, app_display_name
| sort - speedKPH
```

**Improvements From OSINT:**
1. ✅ Impossible travel calculation from Splunk pattern
2. ✅ Guest account filtering from Elastic
3. ✅ Geographic tracking with `iplocation`
4. ✅ Multiple anomaly conditions (speed, city change, country change)
5. ✅ Haversine distance calculation for accuracy

---

### How Analysts Use Query Snippets

#### Step 1: Review OSINT Details

Click "Show Details" on enriched detection:

```
Sources Used:
  ├─ Elastic: privilege_escalation_azure_rbac_administrator_roles_assigned.toml
  └─ Splunk: azure_ad_privileged_role_assigned_to_service_principal.yml

Indicators Used:
  Query Patterns:
    ├─ [Elastic] azure.auditlogs.operation_name:"Add member to role"
    └─ [Splunk] role_id IN ("62e90394-69f5-4237-9190-012177145e10")
```

#### Step 2: Extract Field Names

From snippet: `azure.auditlogs.operation_name`

Verify in your environment:
```spl
index=azure_signin
| table *
| head 1
```

Check if field exists: `azure.auditlogs.operation_name` or `operation_name`

#### Step 3: Copy Specific Values

From snippet: `"Add member to role"`, `"Update role setting in PIM"`

Add to your query:
```spl
| where operation_name IN ("Add member to role", "Update role setting in PIM")
```

#### Step 4: Incorporate GUIDs/IDs

From Splunk snippet: Role GUID `62e90394-69f5-4237-9190-012177145e10`

Research what this is:
- Global Administrator role in Azure AD
- Highest privilege level
- Should be monitored closely

Add to query for high-fidelity alerting.

#### Step 5: Validate & Tune

1. Run query in test environment
2. Verify field names match your log format
3. Adjust for your specific data sources
4. Add exclusions for known-good activity
5. Set appropriate alert thresholds

---

### Query Snippets vs Traditional IOCs

| Aspect | Traditional IOCs | Query Snippets |
|--------|------------------|----------------|
| **Use Case** | Endpoint detections | Cloud/SaaS detections |
| **Examples** | `wmic.exe`, `powershell.exe` | `azure.auditlogs.operation_name` |
| **What They Provide** | File names, hashes, IPs | Field names, API operations, patterns |
| **Detection Type** | Signature-based | Behavior-based |
| **Platform** | Windows, Linux, macOS | Azure, AWS, GCP, O365 |

**Key Insight**: For cloud techniques, query snippets ARE the indicators because cloud detections focus on:
- API operation names (not processes)
- Resource IDs (not file paths)
- Service events (not endpoint logs)
- Identity operations (not registry keys)

---

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

### Troubleshooting Query Snippets

**Q: Field from snippet doesn't exist in my logs**

A: Different log sources may use different field names:
- Check your field schema: `index=* | fieldsummary`
- Common variations:
  - `operation_name` vs `azure.auditlogs.operation_name`
  - `result_type` vs `properties.status.errorCode`
  - `user` vs `user_principal_name`

**Q: Query snippet is for Elasticsearch but I use Splunk**

A: Translate the logic:
- Elastic `event.dataset:azure.auditlogs` → Splunk `sourcetype=azure:audit`
- Elastic `and` → Splunk `AND`
- Elastic field:value → Splunk field=value

**Q: No query snippets showing for my detection**

A: This is normal for:
- Endpoint techniques with clear IOCs (Sigma provides them)
- Techniques without OSINT coverage yet
- Very new techniques added to MITRE recently

Use the software/command indicators instead.

---

## Summary

Query snippets transform MITRE's generic descriptions into actionable detections by providing:

1. **Precision**: Exact field names and values to search
2. **Context**: How the security community detects this technique
3. **Validation**: Cross-vendor confirmation of detection patterns
4. **Tuning**: Known false positive filters and thresholds

They are especially critical for cloud detections where traditional endpoint IOCs don't exist, making them the primary "indicators" for Azure, AWS, GCP, and SaaS platform detections.

**Last Updated**: 2025-10-25
