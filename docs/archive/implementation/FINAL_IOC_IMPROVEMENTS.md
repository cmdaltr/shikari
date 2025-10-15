# Final IOC Extraction Improvements

## Summary
Implemented three additional enhancements based on user feedback:
1. Added exclusions for specific TLDs and security vendor domains
2. Implemented case-insensitive deduplication for IOCs
3. Made "... and X more" text clickable to expand/collapse additional IOCs

## 1. Additional Exclusions

### TLDs to Exclude
Added to the file extension exclusion list:
- `.email` - Generic TLD that shouldn't be in threat intel
- `.id` - Country code TLD for Indonesia, but also used in property names

### Domains to Exclude
Added security vendor and infrastructure domains:
- `crowdstrike.com` - Security vendor (including all subdomains)
- `splunkcloud.com` - Security platform (including all subdomains)
- `file.io` - Legitimate file sharing service

**Implementation**: [archer/parsers/file_intelligence.py](archer/parsers/file_intelligence.py)
```python
# Lines 522-529: TLD exclusions
file_extension_tlds = {
    'exe', 'dll', 'sys', 'bat', 'ps1', 'vbs', 'js', 'jar', 'zip', 'rar',
    'txt', 'log', 'tmp', 'bak', 'old', 'cab', 'msi', 'dat', 'dit', 'xml',
    'pdf', 'doc', 'xls', 'ppt', 'docx', 'xlsx', 'pptx', 'rtf', 'csv', 'ini',
    'email', 'id'  # Additional TLDs to exclude
}

# Lines 571-584: Domain exclusions
exclude_domains = [
    'microsoft.com', 'google.com', 'github.com', 'windows.com',
    'apple.com', 'adobe.com', 'mozilla.org', 'kernel.org',
    'example.com', 'test.com', 'localhost',
    'crowdstrike.com', 'splunkcloud.com', 'file.io'
]
# Checks both substring match AND subdomain match
```

## 2. Case-Insensitive Deduplication

### Problem
Duplicate IOCs with different casing:
```
NTDS.dit
ntds.dit
```
Both refer to the same file but were being listed separately.

### Solution
Implemented case-insensitive deduplication for relevant IOC types:

**IOC Types with Case-Insensitive Deduplication**:
- `domain` - Domains are case-insensitive (evil.com = EVIL.COM)
- `ip` - IPs are case-insensitive (192.168.1.1 = 192.168.1.1, but notation could vary)
- `file` - File names on Windows are case-insensitive
- `hash` - Hashes are case-insensitive (MD5/SHA1/SHA256)

**IOC Types with Case-Sensitive Deduplication**:
- `cmd` - Commands may be case-sensitive on Linux
- `reg` - Registry paths should preserve case
- `evt` - Event IDs are numeric, but kept separate
- `sw` - Software names should preserve case

**Implementation**: [archer/parsers/file_intelligence.py](archer/parsers/file_intelligence.py) Lines 669-685
```python
# Remove duplicates (case-insensitive for domains, IPs, files, hashes)
for key in iocs:
    if key in ['domain', 'ip', 'file', 'hash']:
        # Case-insensitive deduplication - preserve first occurrence's case
        seen = {}
        unique = []
        for item in iocs[key]:
            item_lower = item.lower()
            if item_lower not in seen:
                seen[item_lower] = True
                unique.append(item)
        iocs[key] = sorted(unique, key=str.lower)
    else:
        # Case-sensitive deduplication for commands, registry keys, etc.
        iocs[key] = sorted(list(set(iocs[key])))
```

**Behavior**:
- Preserves the **first occurrence's case**
- Sorts case-insensitively for natural ordering
- Example: `['NTDS.dit', 'ntds.dit', 'test.COM', 'Example.com']` → `['Example.com', 'NTDS.dit', 'test.COM']`

## 3. Expandable "Show More" Links

### Problem
When there are more than 20 IOCs of a type, the message "... and 8 more (all selected by default)" was just static text. Users couldn't see what those additional IOCs were without scrolling through code or proceeding with generation.

### Solution
Made the text clickable to expand/collapse additional IOCs.

**Features**:
- Shows first 20 IOCs by default
- Clickable link: "▼ Show X more (all selected by default)"
- Expands to reveal all hidden IOCs with checkboxes
- Collapses back: "▲ Show less"
- All IOCs remain checked by default (visible and hidden)
- Smooth toggle between show/hide states

**Implementation**: [static/js/index.js](static/js/index.js)

Lines 605-627: HTML generation with hidden container
```javascript
// Hidden container for remaining IOCs
if (data.iocs[iocType].length > 20) {
  html += '<div id="ioc-hidden-' + iocType + '" style="display:none;">';
  data.iocs[iocType].slice(20).forEach(function(ioc, idx) {
    // Render checkboxes for items 21+
    html += '<div style="margin-bottom:0.3em;">';
    html += '<label style="cursor:pointer;display:flex;align-items:start;gap:0.5em;">';
    html += '<input type="checkbox" class="ioc-checkbox" ... checked>';
    html += '<span>' + escapeHtml(ioc) + '</span>';
    html += '</label></div>';
  });
  html += '</div>';

  // Clickable "show more" link
  html += '<a href="#" id="show-more-' + iocType + '" ...>';
  html += '▼ Show ' + (data.iocs[iocType].length - 20) + ' more (all selected by default)';
  html += '</a>';
  html += '<a href="#" id="show-less-' + iocType + '" ... style="display:none;">';
  html += '▲ Show less';
  html += '</a>';
}
```

Lines 724-748: Event listeners for show/hide
```javascript
// Show/Hide more IOCs functionality
var iocOrder = ['ip', 'domain', 'cmd', 'hash', 'reg', 'evt', 'sw', 'file'];
iocOrder.forEach(function(iocType) {
  var showMoreLink = document.getElementById('show-more-' + iocType);
  var showLessLink = document.getElementById('show-less-' + iocType);
  var hiddenContainer = document.getElementById('ioc-hidden-' + iocType);

  if (showMoreLink && hiddenContainer) {
    showMoreLink.addEventListener('click', function(e) {
      e.preventDefault();
      hiddenContainer.style.display = 'block';
      showMoreLink.style.display = 'none';
      if (showLessLink) showLessLink.style.display = 'inline';
    });
  }

  if (showLessLink && hiddenContainer) {
    showLessLink.addEventListener('click', function(e) {
      e.preventDefault();
      hiddenContainer.style.display = 'none';
      showLessLink.style.display = 'none';
      if (showMoreLink) showMoreLink.style.display = 'inline';
    });
  }
});
```

**User Experience**:
1. User sees first 20 domains: `evil[.]com`, `malicious[.]ru`, ...
2. Sees link: "▼ Show 15 more (all selected by default)"
3. Clicks link → Expands to show all 35 domains
4. All domains have checkboxes and are checked
5. Link changes to: "▲ Show less"
6. Clicks again → Collapses back to first 20
7. Hidden IOCs remain checked and will be submitted

## Benefits

### 1. Cleaner Results
- No duplicate entries like `NTDS.dit` and `ntds.dit`
- No security vendor domains cluttering results
- No false TLDs like `.email` or `.id`

### 2. Better UX
- Users can review ALL IOCs before proceeding
- Expandable sections keep UI clean
- Visual indicators (▼/▲) show state
- No need to trust "X more are selected"

### 3. Accurate Detection
- Proper deduplication ensures no redundant detection rules
- Exclusions prevent false positives from legitimate services
- Case preservation maintains readability

## Test Results

### Deduplication Test
```
Input:  ['NTDS.dit', 'ntds.dit', 'test.com', 'TEST.COM', 'Example.com', 'example.COM']
Output: ['Example.com', 'NTDS.dit', 'test.com']

✓ Duplicates removed (case-insensitive)
✓ First occurrence's case preserved
✓ Sorted case-insensitively for natural ordering
```

### Exclusion Test
```
test[.]crowdstrike[.]com → Excluded ✓
alerts.splunkcloud.com → Excluded ✓
upload.file.io → Excluded ✓
something.email → Excluded (TLD) ✓
data.id → Excluded (TLD) ✓
```

### Expandable Links
```
20 visible IOCs + "▼ Show 15 more" link
Click → Expands to show all 35 IOCs
Click "▲ Show less" → Collapses to 20 again
All 35 IOCs are checked and submitted ✓
```

## Files Modified

1. **[archer/parsers/file_intelligence.py](archer/parsers/file_intelligence.py)**
   - Lines 522-529: Added `.email` and `.id` to TLD exclusions
   - Lines 571-584: Added security vendor domain exclusions
   - Lines 669-685: Implemented case-insensitive deduplication

2. **[static/js/index.js](static/js/index.js)**
   - Lines 590-631: Added expandable IOC sections with hidden containers
   - Lines 724-748: Added show/hide event listeners
   - Lines 766-774: Simplified IOC collection (no longer needs manual addition)

## Backward Compatibility

All changes are backward compatible:
- Deduplication only removes true duplicates
- Exclusions only filter known false positives
- Expandable links gracefully degrade (all IOCs in DOM regardless)

No API changes required - existing endpoints work as-is.
