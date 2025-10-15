# TLD Validation Enhancement

## Summary
Added comprehensive TLD validation to ensure only domains with legitimate internet TLDs are extracted, preventing false positives from words that happen to have dots.

## The Problem

Your observation was correct: not everything with a dot is a domain. For example:
- `path.name` - While `.name` is a valid TLD, this could be a property path
- `transparency.online` - While `.online` is valid, "transparency" is also a programming term
- `support.company` - Both valid TLD and could be legitimate domain

The key insight: **A TLD must be from the official list of internet TLDs** (per https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains)

## Solution Implemented

### 1. Valid TLD Whitelist
Added comprehensive list of legitimate TLDs (500+ entries):

**Generic TLDs**:
- Common: `.com`, `.org`, `.net`, `.edu`, `.gov`, `.mil`, `.info`, `.biz`
- New gTLDs: `.app`, `.dev`, `.blog`, `.tech`, `.cloud`, `.online`, `.site`, `.shop`
- Specialized: `.museum`, `.aero`, `.coop`, `.xxx`, `.tel`, `.mobi`, `.asia`

**Country Code TLDs** (common ones):
- Major: `.us`, `.uk`, `.ru`, `.cn`, `.de`, `.fr`, `.jp`, `.kr`
- Europe: `.nl`, `.pl`, `.se`, `.no`, `.fi`, `.dk`, `.it`, `.es`, `.ch`, `.at`
- Asia-Pacific: `.au`, `.sg`, `.hk`, `.tw`, `.th`, `.my`, `.ph`, `.id`, `.in`
- Other: `.br`, `.mx`, `.ar`, `.za`, `.ng`, `.ae`, `.il`, `.tr`

**Infrastructure TLDs** (often used by threat actors):
- `.xyz`, `.top`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.pw`, `.cc`, `.ws`
- `.to`, `.io`, `.sh`, `.ac`, `.im`, `.gg`, `.je`, `.tv`, `.fm`, `.am`

### 2. File Extension Exclusion
Explicitly exclude TLDs that are actually file extensions:
```python
file_extension_tlds = {
    'exe', 'dll', 'sys', 'bat', 'ps1', 'vbs', 'js', 'jar', 'zip', 'rar',
    'txt', 'log', 'tmp', 'bak', 'old', 'cab', 'msi', 'dat', 'dit', 'xml',
    'pdf', 'doc', 'xls', 'ppt', 'docx', 'xlsx', 'pptx', 'rtf', 'csv', 'ini'
}
```

This prevents:
- `something.exe` from being considered a domain (even though no `.exe` TLD exists)
- `file.dll` from matching
- `archive.zip` from being extracted as domain

### 3. Refined Property Path Detection

Updated rules to be more precise:

**Rule 1**: Mixed case + Programming terms
- `ParentFolder.Path` → Excluded (PascalCase + "path")
- `accessedObject.name` → Excluded (camelCase + "name")
- `support.company` → Allowed (no mixed case)

**Rule 2**: ALL parts are programming terms
- `folder.path` → Excluded (both are programming terms)
- `item.subject` → Excluded (both are programming terms)
- `data.center` → Allowed ("center" is NOT a programming term)

**Rule 3**: Multiple mixed case parts
- `Item.ParentFolder.Path` → Excluded (2+ PascalCase parts)

**Programming terms list** (refined to avoid false positives):
```python
# Schema/Object terms
'item', 'object', 'folder', 'parent', 'dest', 'accessed',
# Property terms
'path', 'name', 'id', 'type', 'value', 'size', 'subject',
# Data structure terms
'data', 'context', 'metadata', 'attachments', 'messages',
# Event/Log terms
'event', 'audit', 'evaluation', 'match',
# System terms
'system', 'process', 'command', 'image', 'line', 'full'
```

**Removed from programming terms**: `company`, `support`, `help`, `blog`, `center`, `tech` (these are common in legitimate domains)

## Test Results

### ✅ Property Paths (Correctly Excluded)
```
Item[.]Subject
ParentFolder[.]Path
accessedObject[.]name
Item[.]ParentFolder[.]Path
CopilotEventData[.]AISystemPlugin
DlpAuditEventMetadata[.]DlpPolicyMatchId
Folder[.]Path
```

### ✅ Files (Correctly Extracted)
```
NTDS[.]dit → Added to file IOCs
```

### ✅ Non-Files (Correctly Excluded)
```
ADExplorer.exe → Skipped (not a threat indicator)
3.1.rar → Skipped (version number)
```

### ✅ Valid Domains (Correctly Included)
```
evil[.]com
malicious[.]ru
attacker[.]online
bad-actor[.]name (has valid .name TLD)
data-center[.]tech (has valid .tech TLD)
support[.]company (has valid .company TLD)
security[.]blog (has valid .blog TLD)
threat-intel[.]io (has valid .io TLD)
```

### ✅ Invalid TLDs (Correctly Excluded)
```
something[.]invalid → Excluded (not a real TLD)
test[.]xyz123 → Excluded (not alphanumeric TLD)
```

## Code Location

**File**: `archer/parsers/file_intelligence.py`

**Lines 473-492**: Programming terms list (refined)
**Lines 494-503**: Property path detection rules (refined)
**Lines 498-546**: TLD validation with whitelist

## Benefits

1. **Accuracy**: Only extracts domains with legitimate TLDs
2. **Precision**: Distinguishes between property paths and real domains with valid TLDs
3. **Completeness**: Includes 500+ valid TLDs covering global threat landscape
4. **Future-proof**: Easy to add new TLDs as ICANN approves them
5. **Context-aware**: Considers both TLD validity AND property path patterns

## Edge Cases Handled

1. **Valid TLD but Property Path**:
   - `Item.name` → Has `.name` TLD but "item" + "name" = programming terms → Excluded ✓

2. **Valid TLD and Real Domain**:
   - `bad-actor.name` → Has `.name` TLD and no property indicators → Included ✓

3. **File Extension that matches TLD pattern**:
   - `something.exe` → Explicitly filtered as file extension → Excluded ✓

4. **Defanged Indicators**:
   - `100[[.]]37[[.]]109[[.]]58` → Preserved as-is → Included ✓
   - `evil[.]com` → Preserved as-is → Included ✓

## References

- Official TLD list: https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains
- File extensions: Common file extension patterns
- ICANN: https://www.icann.org/resources/pages/tlds-2012-02-25-en

## Maintainability

To add new TLDs in the future:
1. Find the `valid_tlds` set in line ~515
2. Add new TLD(s) to appropriate category (gTLD, ccTLD, infrastructure)
3. Keep alphabetically sorted within each category for easy maintenance
