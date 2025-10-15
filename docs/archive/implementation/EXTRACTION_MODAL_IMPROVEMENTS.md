# Extraction Modal Improvements

## Overview
Enhanced the file upload and blog analysis extraction modal with improved TTP/IOC display, user selection capabilities, and better IOC extraction logic.

## Changes Made

### 1. Backend API Endpoint - Technique Names
**File**: `archer/app.py`
**Lines**: 1509-1555

Added new endpoint `/api/technique_names` that:
- Accepts a list of technique IDs (e.g., ["T1059.001", "T1078"])
- Loads MITRE ATT&CK enterprise-attack.json data
- Returns a mapping of technique IDs to human-readable names
- Example response: `{"T1059.001": "PowerShell", "T1078": "Valid Accounts"}`

### 2. Improved IOC Extraction
**File**: `archer/parsers/file_intelligence.py`
**Lines**: 396-540

#### IP Address Extraction (Lines 412-427)
- **Supports multiple defanging formats**: `[.]`, `[[.]]`
- **Preserves original defanging**: If already defanged (`100[[.]]37[[.]]109[[.]]58`), keeps as-is
- **Adds defanging to normal IPs**: `203.0.113.1` becomes `203[.]0[.]113[.]1`
- Validates IP address ranges (0-255 per octet)
- Excludes common false positives (localhost, private ranges)
- **Never double-defangs** indicators

#### Domain Extraction (Lines 429-520)
- **Intelligent property path detection** - Excludes programming constructs:
  - **PascalCase/camelCase detection**: `AppAccessContext[.]ClientAppName`, `accessedProcess[.]commandLine`
  - **Programming terms**: `Item[.]Subject`, `ParentFolder[.]Path`, `DestFolder[.]Path`
  - Detects schema/field names from logs and telemetry
- **Major improvements to reduce false positives:**
  - Excludes file extensions (.exe, .dll, .rar, .zip, .dit, etc.)
  - Excludes version numbers (e.g., 3.1.rar, 1.0.0.0)
  - Validates TLD (must be at least 2 chars, all letters)
  - Requires at least one letter in domain name (not just numbers)
  - Filters common legitimate domains (microsoft.com, google.com, etc.)
  - Checks files BEFORE property paths to catch `NTDS[.]dit` correctly
- **Preserves original defanging**: `evil[.]com` stays as `evil[.]com`, not `evil[[.]]com`
- Adds defanging to normal domains

#### File Extraction Enhancement
- Correctly identifies and extracts malicious file indicators:
  - `NTDS.dit` (Active Directory database)
  - `SAM.hive`, `SYSTEM.hive`, `SECURITY.hive`
- Skips common executables and archives that aren't indicators

#### Command Extraction (Lines 497-528)
New functionality to extract commands:
- FTP commands: `ftp.exe adver.sary.c2.server`
- SSH commands: `ssh -i adversary-key.pem user@vm-ip`
- AWS CLI: `aws s3 cp malware.exe s3://bucket/`
- Azure CLI: `az vm create ...`
- Docker: `docker run ...`, `docker exec ...`
- gcloud: `gcloud compute instances create ...`
- PowerShell: `powershell -EncodedCommand ...`, `Invoke-Expression ...`
- CMD: `cmd /c whoami`
- Common tools: `rundll32`, `regsvr32`, `mshta`, `certutil`, `bitsadmin`, `wmic`, etc.

### 3. Frontend Modal Enhancement
**File**: `static/js/index.js`
**Lines**: 541-778

#### TTP Display with Checkboxes and Hyperlinks
- Fetches technique names from `/api/technique_names` endpoint
- Displays as: **Technique Name (T1234.001)** with hyperlink to MITRE ATT&CK
- Each TTP has a checkbox for user selection
- "Select All" checkbox to toggle all TTPs at once
- While loading, shows "Loading technique names..." placeholder
- Falls back to showing just technique IDs if API call fails

Example display:
```
☑ PowerShell (T1059.001)  [links to https://attack.mitre.org/techniques/T1059/001]
☑ Valid Accounts (T1078)   [links to https://attack.mitre.org/techniques/T1078]
```

#### IOC Display Improvements
- Organized by type with clear labels:
  - IP Addresses
  - Domains
  - Commands
  - File Hashes
  - Registry Keys
  - Event IDs
  - Software
  - File Paths
- Each IOC has a checkbox for selection
- Shows first 20 items per type, with note for remaining count
- "Select All" checkbox to toggle all IOCs at once
- All items checked by default

#### User Selection Collection
When user clicks "Proceed with Selected Items":
1. Collects all checked TTP values
2. Collects all checked IOC values by type
3. Automatically includes remaining IOCs beyond first 20 displayed
4. Validates at least one item is selected
5. Sends selected items to generation endpoint

### 4. Backend Generation Endpoints Updated
**Files**: `archer/app.py`

#### Upload Generation Endpoint (Lines 954-1077)
- Added `selected_ttps` and `selected_iocs` form parameters
- Parses JSON strings from frontend
- Uses selected items if provided, otherwise uses all extracted data
- Maintains backward compatibility

#### Blog Generation Endpoint (Lines 1176-1301)
- Same enhancements as upload generation
- Added `selected_ttps` and `selected_iocs` form parameters
- Parses and applies user selections

## User Experience Flow

### Before
1. Upload file → Immediately starts processing all extracted data
2. No visibility into what was extracted
3. No control over what gets processed
4. Many false positive domains (3.1.rar, ADExplorer.exe, etc.)

### After
1. Upload file → Shows extraction results modal
2. User sees:
   - **TTPs**: "PowerShell (T1059.001)" with MITRE link and checkbox
   - **IOCs**: Organized by type (IP, Domain, Commands, etc.) with checkboxes
3. User can:
   - Click MITRE links to learn about techniques
   - Uncheck false positives or irrelevant items
   - Use "Select All" toggles for bulk selection
4. Click "Proceed with Selected Items" → Only selected items are processed
5. Much cleaner IOC extraction with fewer false positives

## Technical Benefits

1. **Better Data Quality**: Reduced false positives in domain extraction
2. **User Control**: Users can review and curate extracted data before processing
3. **Context**: MITRE ATT&CK links provide immediate context for techniques
4. **Command Extraction**: New capability to extract adversary commands from reports
5. **Defanged Indicators**: Proper handling of `[.]` notation for safe display/sharing
6. **Backward Compatible**: Works with or without user selections

## Testing

All Python files pass syntax validation:
```bash
python3 -m py_compile archer/app.py  # ✓ OK
python3 -m py_compile archer/parsers/file_intelligence.py  # ✓ OK
```

Regex patterns validated for:
- IP defanging: `192[.]168[.]1[.]100` ✓
- Domain defanging: `malicious[.]example[.]com` ✓
- Command extraction: Patterns tested against common adversary commands ✓

## Files Modified

1. `archer/app.py` - Added technique names API, updated generation endpoints
2. `archer/parsers/file_intelligence.py` - Improved IOC extraction logic
3. `static/js/index.js` - Enhanced modal with checkboxes, hyperlinks, and selection

## Migration Notes

No breaking changes. The system works with both:
- Old behavior: If no selections provided, processes all extracted data
- New behavior: If selections provided, processes only selected items

No database migrations or configuration changes required.
