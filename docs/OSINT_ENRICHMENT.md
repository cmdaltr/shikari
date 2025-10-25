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
