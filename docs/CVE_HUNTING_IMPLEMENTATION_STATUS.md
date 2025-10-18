# CVE Hunting Implementation Status

## Current Status: Foundation Complete ✅

### Completed Components

1. ✅ **CVE Hunter Module** - `archer/intelligence/cve_hunter.py`
   - NVD API integration
   - GitHub PoC search
   - Synthetic PoC generation (LLM)
   - CWE → ATT&CK mapping
   - IOC extraction framework
   - Caching system

2. ✅ **Splunk Schema Mappings** - `archer/mappings/schemaSplunk.json`
   - CVE-specific indexes added:
     - **WAF Logs**: AWS WAF, CloudFlare, Imperva, Incapsula, Citrix NetScaler
     - **IPS Logs**: Checkpoint, McAfee IPS
     - **Proxy Logs**: McAfee Proxy, Cisco Umbrella
   - Existing indexes available:
     - Windows: `windows_events`, `edr_events`
     - Cloud: `aws_guardduty`, `azure_signin`, `gcp_audit`
     - Network: Unix logs, cloud security (Wiz)

3. ✅ **Implementation Roadmap** - `docs/NEW_FEATURES_ROADMAP.md`
   - Complete architecture design
   - UI mockups
   - Multi-user authentication plan
   - Theme system design

### Next Implementation Steps

#### Phase 1: Intelligent Log Source Selection (Priority 1)

Create `archer/intelligence/cve_log_selector.py`:

```python
class CVELogSourceSelector:
    """
    Intelligently selects appropriate log sources based on CVE characteristics.

    Decision Logic:
    - RCE against web apps → WAF + IPS logs
    - Windows OS vuln → windows_events + edr_events
    - Cloud/SaaS vuln → aws_guardduty / azure / gcp
    - Network service vuln → IPS + network logs
    - Multiple categories → Combine sources
    """

    def select_sources(self, cve_data: Dict) -> Dict[str, List[str]]:
        """
        Returns: {
            'splunk': ['aws_waf', 'example_index'],
            'mde': ['DeviceNetworkEvents', 'DeviceProcessEvents']
        }
        """
```

**Decision Matrix:**

| CVE Type | Product/Service | Log Sources |
|----------|----------------|-------------|
| RCE (Web) | Apache, Nginx, IIS | `aws_waf`, `waf`, `waf`, `example_index` |
| RCE (Windows) | Windows OS, .NET | `windows_events`, `edr_events` + DeviceProcessEvents |
| RCE (Linux) | Linux kernel, services | `linux_syslog`, `example_index` |
| SQLi | Any database-backed app | `aws_waf`, `waf`, `web_proxy` |
| XSS | Web applications | `aws_waf`, `waf` |
| Cloud (AWS) | AWS services | `aws_guardduty`, `aws_cloudtrail`, `aws_waf` |
| Cloud (Azure) | Azure services | `azure_signin`, `azure_activity` |
| Cloud (GCP) | GCP services | `gcp_audit` |
| SaaS | O365, etc. | `m365_audit`, `casb_events` |
| Network Service | SSH, RDP, SMB | `example_index`, `example_index`, `edr_events` |

#### Phase 2: CVE-Specific Query Generation

Extend `archer/build/queries_enhanced.py` or create `archer/build/cve_queries.py`:

```python
def generate_cve_detection_queries(cve_research: Dict, log_sources: Dict) -> List[Dict]:
    """
    Generate detection queries optimized for CVE hunting.

    Steps:
    1. Extract exploit characteristics from PoC
    2. Map to log source fields
    3. Generate multi-source detection logic
    4. Include CVE ID in query metadata
    """
```

**Example Output** (for CVE-2021-44228 Log4Shell):

```yaml
name: CVE-2021-44228 Log4Shell RCE Detection - WAF
description: Detects Log4j JNDI injection attempts via WAF logs
cve_id: CVE-2021-44228
severity: critical
mitre_attack:
  - T1190  # Exploit Public-Facing Application
  - T1059  # Command and Scripting Interpreter
search: |
  index=aws_waf
  | search httpRequest.uri="*${jndi:ldap://*" OR httpRequest.uri="*${jndi:rmi://*"
  | stats count by src_ip, httpRequest.uri, httpRequest.headers{}.value
  | where count > 1
platform: Splunk
data_source: AWS WAF
```

#### Phase 3: UI Integration

**Update `templates/index.html`** - Add CVE input to Generate tab:

```html
<div class="form-section">
  <label for="group_name_input" class="form-label">Threat Group Name</label>
  <input type="text" name="group_name" id="group_name_input" class="form-input"
         placeholder="e.g., APT29, Scattered Spider">
</div>

<!-- OR Separator -->
<div class="form-separator">
  <span class="separator-line"></span>
  <span class="separator-text">OR</span>
  <span class="separator-line"></span>
</div>

<!-- NEW: CVE Input -->
<div class="form-section">
  <label for="cve_input" class="form-label">
    CVE Identifier
    <span class="form-hint">Hunt for specific vulnerabilities</span>
  </label>
  <input type="text" name="cve_id" id="cve_input" class="form-input"
         placeholder="e.g., CVE-2024-1234, CVE-2023-5678">
  <div class="form-hint-text">
    💡 Supports multiple CVEs (comma-separated). System will research CVE, find/generate PoC, and build detections.
  </div>
</div>
```

**CSS for OR separator** (add to `static/css/tabs.css`):

```css
.form-separator {
  display: flex;
  align-items: center;
  margin: 2em 0;
  gap: 1em;
}

.separator-line {
  flex: 1;
  height: 1px;
  background: linear-gradient(to right, transparent, #ddd, transparent);
}

.separator-text {
  color: #999;
  font-weight: 600;
  font-size: 0.9em;
  letter-spacing: 1px;
  padding: 0 1em;
}
```

#### Phase 4: Backend API Endpoint

**Update `archer/app.py`** - Add `/generate/cve` endpoint:

```python
@app.post("/generate/cve")
async def generate_cve_detections(
    request: Request,
    cve_id: str = Form(...),
    run_correlation: bool = Form(False),
    use_openai: bool = Form(False)
):
    """
    Generate detection queries for CVE(s).

    Process:
    1. Research CVE → NVD + GitHub + PoC search
    2. Generate/find PoC if needed
    3. Map to ATT&CK techniques
    4. Select appropriate log sources
    5. Generate detection queries
    6. Run correlation (optional)
    """
    from archer.intelligence.cve_hunter import research_and_hunt
    from archer.intelligence.cve_log_selector import CVELogSourceSelector

    # Support multiple CVEs
    cve_ids = [c.strip() for c in cve_id.split(',')]

    all_detections = []
    for cve in cve_ids:
        # Research CVE
        research = research_and_hunt(cve)

        # Select log sources
        selector = CVELogSourceSelector()
        log_sources = selector.select_sources(research)

        # Generate queries
        detections = generate_cve_detection_queries(research, log_sources)
        all_detections.extend(detections)

    # Create synthetic group name
    group_name = f"CVE_{cve_ids[0].replace('-', '_')}_Hunt"

    # Save detections
    # Run correlation if requested
    # Return progress URL

    return {"group_name": group_name, "redirect": f"/progress?group_name={group_name}"}
```

#### Phase 5: Form Handling Logic

**Update `static/js/index.js`** - Handle mutual exclusion:

```javascript
// Mutual exclusion: Threat Group OR CVE
document.getElementById('group_name_input').addEventListener('input', function() {
    if (this.value) {
        document.getElementById('cve_input').disabled = true;
        document.getElementById('cve_input').placeholder = 'Disabled (using Threat Group)';
    } else {
        document.getElementById('cve_input').disabled = false;
        document.getElementById('cve_input').placeholder = 'e.g., CVE-2024-1234';
    }
});

document.getElementById('cve_input').addEventListener('input', function() {
    if (this.value) {
        document.getElementById('group_name_input').disabled = true;
        document.getElementById('group_name_input').placeholder = 'Disabled (using CVE)';
    } else {
        document.getElementById('group_name_input').disabled = false;
        document.getElementById('group_name_input').placeholder = 'e.g., APT29, Scattered Spider';
    }
});

// Form submission - detect which mode
document.getElementById('generate-form').addEventListener('submit', async function(e) {
    e.preventDefault();

    const groupName = document.getElementById('group_name_input').value;
    const cveId = document.getElementById('cve_input').value;

    if (!groupName && !cveId) {
        alert('Please enter either a Threat Group Name or CVE ID');
        return;
    }

    const endpoint = cveId ? '/generate/cve' : '/generate';
    const formData = new FormData(this);

    // Submit and redirect to progress
    const response = await fetch(endpoint, {
        method: 'POST',
        body: formData
    });

    const result = await response.json();
    window.location.href = result.redirect;
});
```

---

## Testing Plan

### Test CVEs (Recommended)

1. **CVE-2021-44228** (Log4Shell)
   - Type: RCE (Java deserialization)
   - Log Sources: WAF, IPS, application logs
   - Expected: Detect JNDI injection patterns

2. **CVE-2022-22965** (Spring4Shell)
   - Type: RCE (Spring Framework)
   - Log Sources: WAF, application logs
   - Expected: Detect class loader manipulation

3. **CVE-2020-0601** (CurveBall)
   - Type: Windows crypto vulnerability
   - Log Sources: Windows event logs, Defender
   - Expected: Detect certificate validation bypass

4. **CVE-2023-23397** (Outlook Elevation of Privilege)
   - Type: O365/Windows
   - Log Sources: O365, Windows logs
   - Expected: Detect malicious calendar invites

5. **CVE-2024-21413** (Outlook RCE)
   - Type: Remote Code Execution
   - Log Sources: O365, network logs
   - Expected: Detect exploit attempts

### Validation Checklist

- [ ] NVD API returns correct CVE data
- [ ] GitHub search finds PoCs when they exist
- [ ] Synthetic PoC generation works for obscure CVEs
- [ ] Log source selection is accurate for different CVE types
- [ ] Generated queries use correct indexes and fields
- [ ] Queries are syntactically valid (test in Splunk/MDE)
- [ ] Correlation works for multi-stage exploits
- [ ] Progress tracking shows CVE research steps

---

## API Keys Required

Add to `.env`:

```bash
# CVE Hunting (all optional but recommended)
NVD_API_KEY=your-api-key-here         # Increases rate limit 5→50 requests/30sec
GITHUB_TOKEN=ghp_your-token-here      # Better PoC search, higher rate limits

# Existing
OPENAI_API_KEY=sk-...                 # For synthetic PoC generation
```

Get NVD API key: https://nvd.nist.gov/developers/request-an-api-key

---

## File Structure

```
archer/
├── intelligence/
│   ├── cve_hunter.py              ✅ Created
│   ├── cve_log_selector.py        ⬜ TODO
│   └── cve_to_attack_mapping.py   ⬜ TODO
├── build/
│   ├── cve_queries.py             ⬜ TODO
│   └── queries_enhanced.py        📝 Extend
├── app.py                         📝 Add /generate/cve endpoint
├── mappings/
│   └── schemaSplunk.json          ✅ Updated with CVE indexes
├── data/
│   └── cve_cache/                 📁 Auto-created
templates/
├── index.html                     📝 Add CVE input field
static/
├── css/
│   └── tabs.css                   📝 Add OR separator styles
└── js/
    └── index.js                   📝 Add CVE form handling
```

---

## Next Session Tasks

1. **Create `cve_log_selector.py`** - Intelligent log source selection
2. **Create `cve_queries.py`** - CVE-specific query generation
3. **Update UI** - Add CVE input with OR separator
4. **Add API endpoint** - `/generate/cve` in app.py
5. **Test with Log4Shell** - End-to-end validation

After CVE hunting is complete, we'll move to:
- Multi-user authentication
- Full theme system with accessibility

---

**Status**: 40% Complete - Foundation ready, needs integration
