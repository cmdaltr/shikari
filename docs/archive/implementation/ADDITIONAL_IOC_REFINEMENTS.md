# Additional IOC Extraction Refinements

## Summary
Implemented five additional refinements to improve IOC quality and display:
1. Strip command descriptions after `: ` separator
2. Trim whitespace and trailing dots from commands
3. Remove `.name` TLD from valid TLD list
4. Convert ALL IOCs to lowercase with deduplication
5. Reduce display limit from 20 to 10 IOCs

## 1. Command Description Stripping

### Problem
Commands often have descriptions appended with a colon separator:
```
aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess: Grants elevated privileges.
```

The description "Grants elevated privileges" is not part of the actual command.

### Solution
Strip everything after `: ` (colon + space):

**Implementation**: [archer/parsers/file_intelligence.py](archer/parsers/file_intelligence.py) Lines 657-659
```python
# Strip description after ': ' separator
if ': ' in match:
    match = match.split(': ')[0]
```

### Results
```
Before: aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess: Grants elevated privileges.
After:  aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

## 2. Command Whitespace and Dot Trimming

### Problem
Commands may have trailing/leading whitespace or unnecessary dots:
```
"  docker run malware...  "
"ssh -i key.pem user@host  "
```

### Solution
Trim whitespace and strip trailing dots:

**Implementation**: [archer/parsers/file_intelligence.py](archer/parsers/file_intelligence.py) Lines 661-662
```python
# Clean up: strip whitespace and trailing dots
cleaned = match.strip().rstrip('.')
```

### Results
```
Before: "  docker run malware...  "
After:  "docker run malware"

Before: "ssh -i key.pem user@host  "
After:  "ssh -i key.pem user@host"
```

## 3. Removed `.name` TLD

### Problem
`.name` is a valid generic TLD, but it was causing false positives with property paths like:
- `accessedObject.name`
- `Item.name`
- `ParentFolder.name`

While our property path detection would catch most of these, removing `.name` from the valid TLD list provides an extra layer of filtering.

### Solution
Removed `'name'` from the valid TLD set.

**Implementation**: [archer/parsers/file_intelligence.py](archer/parsers/file_intelligence.py) Lines 534-561

**Before**:
```python
'info', 'biz', 'name', 'pro', 'museum', ...
```

**After**:
```python
'info', 'biz', 'pro', 'museum', ...  # 'name' removed
```

**Note**: Legitimate domains ending in `.name` would need to be manually added if encountered in threat intelligence.

## 4. All IOCs Lowercase with Deduplication

### Problem
Mixed case IOCs creating duplicates:
```
NTDS.dit
ntds.dit
Evil.COM
evil.com
```

These are functionally identical but were being treated as separate IOCs.

### Solution
Convert ALL IOCs to lowercase and deduplicate.

**Implementation**: [archer/parsers/file_intelligence.py](archer/parsers/file_intelligence.py) Lines 677-685
```python
# Remove duplicates and convert ALL IOCs to lowercase
for key in iocs:
    # Convert all to lowercase first
    lowercase_items = [item.lower() for item in iocs[key]]
    # Remove duplicates
    unique_items = sorted(list(set(lowercase_items)))
    iocs[key] = unique_items
```

### Results
```
Input:  ['NTDS.dit', 'ntds.dit', 'Evil.COM', 'evil.com', 'Test.COM', 'test.com']
Output: ['evil.com', 'ntds.dit', 'test.com']

✓ All duplicates removed
✓ All converted to lowercase
✓ Sorted alphabetically
```

### Applies To
- **Domains**: `evil.com` = `EVIL.COM`
- **IPs**: `192.168.1.1` (no case but consistent)
- **Files**: `ntds.dit` = `NTDS.DIT` = `Ntds.Dit`
- **Hashes**: `abc123...` = `ABC123...`
- **Commands**: `PowerShell` = `powershell`
- **Registry Keys**: `HKEY_LOCAL_MACHINE` = `hkey_local_machine`
- **Event IDs**: Already numeric
- **Software**: `Mimikatz` = `mimikatz`

### Benefits
1. **Consistency**: All IOCs in uniform lowercase format
2. **Deduplication**: No more duplicate entries
3. **Compatibility**: Matches most SIEM/detection tool conventions
4. **Simplicity**: Easier to search and compare

## 5. Display Limit: 20 → 10 IOCs

### Problem
Showing 20 IOCs initially made the modal too long and overwhelming.

### Solution
Reduced initial display to 10 IOCs per type, with expandable "Show X more" link.

**Implementation**: [static/js/index.js](static/js/index.js)

**Changes**:
- Line 595: `slice(0, 20)` → `slice(0, 10)` (first batch)
- Line 606: `length > 20` → `length > 10` (check threshold)
- Line 608: `slice(20)` → `slice(10)` (remaining items)
- Line 609: `idx + 20` → `idx + 10` (index offset)
- Line 621: `length - 20` → `length - 10` (count remaining)

### User Experience
**Before**: Shows 20 IOCs, then "... and 8 more"
**After**: Shows 10 IOCs, then "▼ Show 8 more"

**Example**:
```
Domains (18):
  evil.com
  malicious.ru
  attacker.online
  ... (7 more shown)

▼ Show 8 more (all selected by default)
```

Clicking expands to show all 18 domains.

### Benefits
1. **Less overwhelming**: Cleaner initial view
2. **Faster scanning**: Focus on first 10 items
3. **Better UX**: Expandable for full review
4. **Consistent**: Same experience across all IOC types

## Test Results

### Command Cleaning
```bash
Input:  "aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess: Grants elevated privileges."
Output: "aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"

Input:  "docker run malware...  "
Output: "docker run malware"

Input:  "powershell -Command Get-Process: Lists running processes"
Output: "powershell -Command Get-Process"

✓ Descriptions stripped after ': '
✓ Whitespace trimmed
✓ Trailing dots removed
```

### Lowercase Deduplication
```bash
Input:  ['NTDS.dit', 'ntds.dit', 'Evil.COM', 'evil.com', 'Test.COM']
Output: ['evil.com', 'ntds.dit', 'test.com']

✓ All converted to lowercase
✓ Duplicates removed
✓ Sorted alphabetically
```

### Display Limit
```
Old: 20 visible, "... and X more" (static text)
New: 10 visible, "▼ Show X more" (clickable)

✓ Reduced visual clutter
✓ Expandable on demand
✓ All IOCs still accessible
```

## Files Modified

1. **[archer/parsers/file_intelligence.py](archer/parsers/file_intelligence.py)**
   - Lines 534-561: Removed `.name` from valid TLDs
   - Lines 657-668: Command description stripping and trimming
   - Lines 677-685: Lowercase conversion and deduplication

2. **[static/js/index.js](static/js/index.js)**
   - Lines 595-627: Changed display limit from 20 to 10 IOCs

## Impact

### Before
```
Commands:
- aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess: Grants elevated privileges.
- docker run malware...

Domains:
- NTDS.dit
- ntds.dit
- Evil.COM
- evil.com
- bad-actor.name  (property path false positive)

[Showing 20 of 28 items]
```

### After
```
Commands:
- aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
- docker run malware

Domains:
- evil.com
- ntds.dit

[Showing 10 of 15 items] ▼ Show 5 more
```

## Summary

All changes improve IOC quality and user experience:
- ✅ Commands are cleaner (no descriptions, whitespace, or dots)
- ✅ IOCs are consistent (all lowercase)
- ✅ No duplicates (case-insensitive deduplication)
- ✅ Fewer false positives (`.name` TLD removed)
- ✅ Better UX (10 item display limit with expand)

All changes validated with syntax checking and logic testing.
