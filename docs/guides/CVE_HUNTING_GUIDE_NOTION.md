# 🎯 CVE Hunting Feature - Test Guide


---

## ✅ Implementation Complete

### 📌 What's Been Implemented

1. **CVE Research Module** (`archer/intelligence/cve_hunter.py`)
   - NVD API integration
   - GitHub PoC search
   - Synthetic PoC generation (LLM)
   - CWE → ATT&CK mapping
   - IOC extraction

2. **UI Integration** (`templates/index.html`)
   - CVE input field with OR separator
   - Mutual exclusion with Threat Group input
   - Professional styling

3. **Backend Endpoint** (`archer/app.py`)
   - `/generate/cve` endpoint
   - Multi-CVE support (comma-separated)
   - Integration with existing detection pipeline

4. **JavaScript** (`static/js/index.js`)
   - Form routing based on input type
   - Input field mutual exclusion
   - Progress tracking


---

## 🧪 Testing Steps

### 📌 Test 1: Basic CVE Research (Log4Shell)

**Input:** `CVE-2021-44228`

**Expected Behavior:**
1. Navigate to Generate tab
2. Leave Threat Group blank
3. Enter `CVE-2021-44228` in CVE field
4. Notice Threat Group field becomes disabled
5. Click "Generate Detections"
6. Redirects to progress page
7. System should:
   - Research CVE from NVD
   - Find PoCs on GitHub
   - Map to T1190 (Exploit Public-Facing Application)
   - Extract JNDI injection patterns as IOCs
   - Generate detections for WAF, IPS, application logs

**Validation:**
```bash
# Check output files
ls data/generate/CVE_2021_44228*

# Should contain:
# - splunk_*.yml (multiple detection rules)
# - mde_*.yml (if MDE queries generated)
# - JSON correlation files (if correlation enabled)
```bash

### 📌 Test 2: Multiple CVEs

**Input:** `CVE-2021-44228, CVE-2022-22965`

**Expected Behavior:**
- Group name: `CVE_Hunt_CVE_2021_44228_plus_1`
- Researches both CVEs
- Combines techniques and IOCs
- Generates unified detection set

### 📌 Test 3: Mutual Exclusion

**Steps:**
1. Type "APT29" in Threat Group
2. Notice CVE field becomes disabled and grayed out
3. Clear Threat Group
4. CVE field becomes enabled again
5. Type "CVE-2024-1234" in CVE field
6. Notice Threat Group becomes disabled

### 📌 Test 4: Error Handling

**Input:** `INVALID-CVE-ID`

**Expected:**
- Should handle gracefully
- Check progress page for error status
- Or NVD API returns "CVE not found"


---

## 🧪 Manual Testing Checklist

- [ ] CVE input field visible on Generate tab
- [ ] OR separator displays correctly
- [ ] Mutual exclusion works (can't use both inputs)
- [ ] Single CVE submission works
- [ ] Multiple CVEs (comma-separated) work
- [ ] Progress page shows CVE research status
- [ ] Detection files generated in `data/generate/`
- [ ] Correlation works (if enabled)
- [ ] NVD API calls succeed (check console logs)


---

## 📌 Debugging

### 📌 Check Logs

```bash
# Start Archer and watch logs
python3 app.py

# Or with uvicorn
uvicorn archer.app:app --reload

# Look for:
# - "Researching CVE-2021-44228..."
# - NVD API responses
# - GitHub search results
# - "Found X unique techniques from Y CVE(s)"
```bash

### 📌 Check Progress File

```bash
cat data/progress/CVE_2021_44228.json
```bash

Should show:
```json
{
  "status": "researching_cve",
  "stage": "CVE Research",
  "cve_ids": ["CVE-2021-44228"],
  "created_yaml": 0
}
```bash

### 🔌 Verify NVD API (Optional)

Test NVD API directly:
```bash
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
```bash


---

## 📌 Known Limitations

1. **No API Keys Initially**
   - Works without NVD_API_KEY but rate limited (5 requests/30 sec)
   - Works without GITHUB_TOKEN but fewer PoC results
   - Add to `.env` for better performance

2. **Synthetic PoC Generation**
   - Requires OpenAI API key for LLM
   - Falls back to basic technique mapping if LLM unavailable

3. **Log Source Selection**
   - Currently uses all available log sources
   - Future: Intelligent selection based on CVE type


---

## 🔧 Environment Setup (Optional)

For best results, add to `.env`:

```bash
# NVD API Key (free registration)
NVD_API_KEY=your-api-key-here

# GitHub Token (personal access token)
GITHUB_TOKEN=ghp_your-token-here

# Already have:
OPENAI_API_KEY=sk-...
```bash


---

## 📌 Success Criteria

CVE hunting is working correctly if:

✅ Can enter CVE ID in UI
✅ Progress page shows CVE research phase
✅ Detection YAML files are created
✅ Techniques mapped correctly (check YAML headers)
✅ IOCs extracted (check detection logic)
✅ Works with multiple CVEs


---

## 🧪 Next Steps After Testing

Once CVE hunting is validated:

1. **Enhance Log Source Selection**
   - Create intelligent selector based on CVE characteristics
   - RCE → WAF + IPS
   - Windows vuln → Windows + Defender logs
   - Cloud → Cloud-specific logs

2. **Improve PoC Analysis**
   - Parse actual exploit code for IOCs
   - Extract network signatures
   - Identify behavioral patterns

3. **Add CVE Caching**
   - Cache NVD responses (30 days)
   - Cache PoC search results
   - Faster repeat queries

4. **Activity Timeline Integration**
   - Track CVE hunts in profile page
   - Show CVE research history
   - Download previous CVE detections


---

## 🔧 Troubleshooting

### 📌 Issue: No detections generated

**Check:**
- NVD API returned valid data?
- Techniques mapped correctly?
- IOCs extracted?

**Debug:**
```bash
# Check CVE cache
cat data/cve_cache/CVE-2021-44228.json

# Should contain:
# - nvd_data
# - techniques
# - iocs
# - pocs
```bash

### 📌 Issue: Progress stuck on "researching_cve"

**Cause:** NVD API timeout or error

**Solution:**
- Check internet connection
- Verify CVE ID is valid
- Check NVD API status: https://nvd.nist.gov/

### 📌 Issue: Form doesn't submit

**Check:**
- JavaScript console for errors
- Network tab for failed requests
- Ensure both fields aren't disabled


---

## 📌 Test Report Template

```bash
CVE Hunting Test Report
Date: [DATE]
Tester: [NAME]

Test Case: [Single CVE / Multiple CVEs / Error Handling]
CVE ID(s): [CVE-XXXX-XXXXX]

Results:
[ ] CVE research completed
[ ] Techniques identified: [LIST]
[ ] IOCs extracted: [COUNT]
[ ] Detections generated: [COUNT]
[ ] Correlation worked: [YES/NO]

Issues Found:
- [LIST ANY ISSUES]

Notes:
[ADDITIONAL OBSERVATIONS]
```bash

---

**Status**: Ready for testing! 🚀

Start with `CVE-2021-44228` (Log4Shell) as it's well-documented with many PoCs available.
