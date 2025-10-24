# OSINT Enrichment Implementation

## Overview

The OSINT (Open Source Intelligence) Enrichment system automatically searches external threat intelligence sources when MITRE ATT&CK data doesn't provide sufficient indicators for detection creation.

## Architecture

### Detection Generation Flow

```
┌─────────────────────────────────────┐
│  Parse MITRE ATT&CK Technique Data  │
└──────────────┬──────────────────────┘
               │
               ▼
      ┌────────────────┐
      │ Extract IOCs?  │
      └────┬───────┬───┘
           │ YES   │ NO
           │       │
           ▼       │
   ┌───────────────────────┐
   │ Filter Generic Terms  │ ← NEW: Remove "condition", "value", "data", etc.
   │ - condition, value    │
   │ - data, file, process │
   │ - command, user, etc. │
   └───┬───────────────┬───┘
       │ Real IOCs     │ Only Generic
       │               │
       │               ▼
       │          ┌─────────────────────┐
       │          │  Search OSINT       │
       │          │  - Sigma Rules      │
       │          │  - MITRE CAR        │
       │          │  - Elastic Rules    │
       │          └──────┬──────────────┘
       │                 │
       │                 ▼
       │            ┌────────────┐
       │            │ Found IOCs?│
       │            └─┬────────┬─┘
       │              │ YES    │ NO
       │        ┌---──┘        │
       ▼        ▼              ▼
    ┌────────────-──┐   ┌──────────────┐
    │ Create        │   │ Skip         │
    │ Detection     │   │ Detection    │
    │ (Normal)      │   │ Creation     │
    └────────────-──┘   └──────────────┘
           │
           ▼
    ┌──────────────┐
    │ YAML File    │
    │ with Badge   │
    │ - None       │ ← Has MITRE indicators (real IOCs)
    │ - Orange     │ ← OSINT-enriched (no MITRE, has OSINT)
    └──────────────┘

    Note: Yellow badge removed - detections with no indicators are not created
```

## Badge System

### No Badge (Normal Detection)
- **Condition**: Detection has real indicators extracted from MITRE ATT&CK (after filtering generic terms)
- **Display**: No badge shown
- **Checkbox**: Checked by default
- **Examples**: AADInternals, powershell.exe, Connect-AZAccount

### Orange Badge ("Needs Review - enriched with additional OSINT")
- **Condition**: Detection created from OSINT research (no MITRE indicators or only generic MITRE terms)
- **Display**: Orange badge with sun/sparkle icon
- **Checkbox**: Unchecked by default
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

### 1. Sigma Rules (SigmaHQ/sigma)
- **API**: GitHub Code Search
- **Query**: `{technique_id} in:file repo:SigmaHQ/sigma path:rules`
- **Extraction**: CommandLine, Image, TargetFilename patterns
- **Rate Limit**: 10 requests/minute (GitHub authenticated)

### 2. MITRE CAR (Cyber Analytics Repository)
- **API**: GitHub Raw Content
- **File**: `analytics.json`
- **Extraction**: Analytics with matching technique coverage
- **Rate Limit**: No limit (raw file fetch)

### 3. Elastic Detection Rules
- **API**: GitHub Code Search
- **Query**: `{technique_id} in:file repo:elastic/detection-rules path:rules`
- **Extraction**: Rule metadata
- **Rate Limit**: 10 requests/minute (GitHub authenticated)

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

### Environment Variables

```bash
# Optional: GitHub personal access token for higher rate limits
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
```

### Cache Directory

```bash
# Created automatically
data/osint_cache/
```

Add to `.gitignore`:
```
data/osint_cache/
```

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

## Summary of Recent Changes (2024-10-24)

### Generic Term Filtering ✅
- **Problem**: Low-quality detections created with generic indicators like "condition", "value", "data"
- **Solution**: Filter out 33 generic terms during detection generation and results display
- **Impact**: Higher quality detections, fewer false positives, automatic OSINT fallback

### OSINT Enrichment Integration ✅
- **Trigger**: When no real indicators exist (after filtering generic terms)
- **Sources**: Sigma Rules, MITRE CAR, Elastic Detection Rules
- **Caching**: 24-hour cache to optimize performance
- **Badge**: Orange badge for OSINT-enriched detections

### Detection Quality Improvements ✅
1. **Generic-only indicators** → OSINT enrichment attempted
2. **No indicators + No OSINT** → Detection NOT created
3. **Real indicators** → Normal detection created
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
