# Archer Usage Guide

Complete guide to using Archer for threat detection generation through Web UI, CLI, and API.

---

## Table of Contents

1. [Web Interface](#web-interface)
   - [Generate Detections](#generate-detections) (Threat Groups, CVEs, Files, Blog URLs)
   - [Research Tab](#research-tab) (Actor Consolidation, Keyword Filtering, XLSX Export)
   - [Ask Archer](#ask-archer) (Conversational Q&A)
   - [Adversary Emulation](#adversary-emulation) (Atomic Red Team)
   - [Manage Detection Library](#manage-detection-library)
   - [Threat Briefing](#threat-briefing)
   - [Company Profiling](#company-profiling)
   - [Validate Detections](#validate-detections) (Docker)
2. [Command Line Interface (CLI)](#command-line-interface-cli)
3. [API Integration](#api-integration)

---

## Web Interface

Access Archer's web interface at `http://localhost:8000` after starting the service.

### Generate Detections

#### For Threat Groups

1. Navigate to **Generate** tab
2. Enter threat group name (e.g., "APT29", "Lazarus Group", "Scattered Spider")
3. Configure options:
   - **OSINT Enhancement**: Merge community detection patterns (Sigma, Elastic, etc.)
   - **OSINT Comparison**: Add metadata showing how your detections compare to OSINT
   - **Run Correlation**: Generate multi-stage attack correlations
   - **Correlation Min Relevance**: Threshold for correlation quality (0.5-1.0)
   - **AI Generators**: Use AI for advanced correlation (requires OpenAI API key)
4. Click **Generate Detections**
5. Monitor progress in real-time
6. Download ZIP when complete

**Detection ZIP Structure**:
```
APT29/
├── detections/              # Individual detection YAML files
│   ├── PasstheHash_DeviceProcessEvents.yaml
│   ├── PowerShell_windows_events.yaml
│   └── ...
├── correlations/            # Multi-stage attack correlations
│   └── APT29.json
└── attack_flows/            # MITRE ATT&CK Flow visualizations
    ├── APT29.json
    └── APT29.html
```

#### For CVEs

1. Navigate to **Generate** tab
2. Select **CVE** mode
3. Enter CVE ID(s) (e.g., "CVE-2021-44228" for Log4Shell)
4. Multiple CVEs: Comma-separated (e.g., "CVE-2021-44228,CVE-2022-22965")
5. Click **Generate Detections**

**Use Cases**:
- Generate detections for zero-day vulnerabilities
- Create detection coverage for vulnerability scanners
- Build detection libraries for patch cycles

#### From Uploaded Files

1. Navigate to **Upload** tab
2. Upload threat report (PDF, TXT, DOCX, JSON, CSV, YARA)
3. (Optional) Enable **Use OpenAI** for AI-enhanced extraction
4. Review extracted TTPs and IOCs
5. Select which TTPs to generate detections for
6. Click **Generate from Selected**

**Supported File Types**:
- **PDF** - Threat reports, whitepapers
- **TXT** - Plain text reports
- **DOCX** - Microsoft Word documents
- **JSON** - Structured threat intelligence
- **CSV** - Tabular threat data
- **YARA** - YARA rules for automatic analysis
- **XLSX/XLS** - Excel spreadsheets with indicator data
- **MD** - Markdown threat reports

#### From Blog URLs

1. Navigate to **Upload** tab
2. Enter a threat intelligence blog URL (e.g., a DFIR Report or CrowdStrike post)
3. Click **Analyze**
4. Archer fetches the page, extracts ATT&CK techniques and IOCs
5. Review the extracted TTPs and IOCs in the results panel
6. Select which TTPs to generate detections for
7. Click **Generate from Selected**

**SSRF Protection**: Internal/localhost URLs (127.0.0.1, 192.168.x.x, 10.x.x.x, 169.254.x.x) are blocked.

**Supported Sources**:
- DFIR Report, CrowdStrike, Microsoft Security Blog, Unit 42, Mandiant, Secureworks, Talos Intelligence, and any publicly accessible threat blog

---

### Research Tab

The Research tab provides actor-level technique consolidation and filtering for threat landscape analysis.

#### Keyword and Country Filtering

1. Navigate to **Research** tab
2. Enter keywords (e.g., "ransomware", "finance", "Iran") in the keyword filter
3. Optionally filter by specific threat actor names in the actor filter
4. Optionally filter by MITRE ATT&CK tactic using the tactic dropdown
5. Results show matching threat groups and their consolidated techniques

#### Actor Technique Consolidation

Select one or more threat actors to see a consolidated, deduplicated view of all techniques used across the selected groups. This reveals overlapping TTPs and helps prioritise detection engineering.

#### XLSX Export

Click **Export XLSX** to download a professional spreadsheet containing:
- Actor metadata (MITRE ID, aliases, description)
- Consolidated technique list with tactic mappings
- Coverage analysis

#### Hunt Buttons

From the Research tab results, click **Hunt** next to any technique to jump directly to the Generate tab with that technique pre-filled, ready for detection generation.

**Note**: The Research tab limits results to 20 actors per query to maintain performance.

---

### Ask Archer

The Ask Archer panel is a conversational Q&A interface available on the home page. It answers questions about ATT&CK techniques, threat groups, SIEM query languages, and Archer-generated detections using your configured LLM provider.

1. Locate the Ask Archer input at the bottom of the home page
2. Type a question (e.g., "Write a Splunk query to detect encoded PowerShell commands")
3. Press Enter or click Send
4. View the AI-generated response

**Example questions**:
- "What is T1059.001?"
- "Give me a Splunk query for Scattered Spider"
- "How does Lazarus Group typically gain initial access?"
- "Compare KQL and SPL syntax for process creation events"

---

### Adversary Emulation

The Emulate tab integrates with Atomic Red Team for adversary simulation and live technique execution.

1. Navigate to **Emulate** tab
2. Enter a technique ID (e.g., "T1059.001") or threat group name
3. Select emulation mode:
   - **Simulate** - Dry run without execution
   - **Execute** - Live execution (use with caution)
4. (Optional) Configure remote hosts for distributed execution
5. Click **Emulate**

> **Warning**: Live execution mode runs real attack commands. Only use in isolated lab environments with explicit authorization.

**Requires**: Atomic Red Team installed locally or via Docker.

---

### Manage Detection Library

1. Navigate to **Library** tab
2. View all saved detections
3. **Search**: Filter by keyword, technique, or platform
4. **Tag**: Organize detections with custom tags
5. **Share**: Change visibility (private/shared)
6. **Export**: Download as JSON, CSV, or XML
7. **Delete**: Remove unwanted detections

**Library Features**:
- **Filtering**: By platform (Splunk, MDE, Elastic), technique ID, threat group
- **Tagging**: Custom tags for organization (e.g., "priority", "validated", "tuned")
- **Versioning**: Track changes to detections over time
- **Collaboration**: Share detections with team members

### Threat Briefing

Generate a grounded, prioritised detection plan for any MITRE ATT&CK threat group. Unlike the general Ask Archer chat, the Threat Briefing reads real technique data from Archer's ATT&CK database and checks your existing detection coverage before calling the LLM — so the answer is always grounded in facts, not generalities.

1. Navigate to the **Generate** tab
2. Enter a threat group name (e.g., "Scattered Spider", "APT29") in the group name field
3. Click **Threat Briefing** (the secondary button below Generate)
4. Wait for the briefing to load — Archer will:
   - Load all techniques attributed to the group from MITRE ATT&CK STIX data (all three attribution paths: direct, via software, via campaign)
   - Check which techniques already have detection YAML files in your library
   - Send the full technique list with coverage status to the LLM
5. Review the results:
   - **Coverage stats** — total techniques, how many are already covered, how many are gaps
   - **Attack chain** — kill-chain tactic progression for this group
   - **Briefing summary** — 2–3 sentence executive overview
   - **Top 5 prioritised techniques** — ranked by: coverage gap, kill-chain position, attribution confidence, detection opportunity

**Why use Threat Briefing?**

The general "Ask Archer" chat answers from general ATT&CK knowledge. Threat Briefing answers from your actual data:
- Technique list sourced from MITRE ATT&CK STIX (all three attribution paths)
- Coverage check uses your generated detection library, not generic assumptions
- Prioritisation accounts for which gaps are most operationally critical

**Coverage badge meanings:**
- **✓ Covered** — Archer has a detection YAML for this technique in your library
- **✗ Gap** — No detection exists yet; this is where to focus

---

### Company Profiling

Generate targeted detections based on your organization's threat profile.

1. Navigate to **Profile** tab
2. Enter company domain (e.g., "microsoft.com")
3. Select profiling options:
   - **Industry-based threat analysis** - Threats targeting your industry
   - **Geographic threat analysis** - Threats active in your region
   - **Technology stack analysis** - Threats targeting your tech stack
   - **Supply chain analysis** - Threats targeting your supply chain
4. Review threat group relevance scores
5. Select relevant threat groups
6. Generate detections for selected groups

**Profiling Benefits**:
- Focus detection engineering on relevant threats
- Prioritize high-risk threat actors
- Optimize detection coverage for your environment
- Reduce false positives from irrelevant detections

### Validate Detections

Test your detection queries against sample events in containerized SIEM environments.

> **Requirement:** Docker must be installed and running for validation to work.

#### Step-by-Step Usage

1. Navigate to **Validate** tab
2. Paste your detection query
3. Select the target SIEM vendor (auto-detected from query syntax)
4. Enter indicators for event generation:
   - **Command Line Patterns**: `powershell.exe -NoP -W Hidden`
   - **Process/File Names**: `mimikatz.exe`
5. Click **Start Validation**
6. Review results:
   - **True Positives**: Malicious events detected
   - **False Negatives**: Malicious events missed
   - **False Positives**: Benign events incorrectly flagged
   - **Precision/Recall/F1**: Overall detection effectiveness
7. Apply suggested refinements if detection fails
8. Re-run until satisfied

**Supported SIEM Vendors:**
- **Splunk (SPL)**: Uses official Splunk Docker image
- **Elastic (Query DSL)**: Uses Elasticsearch Docker image
- **Google SecOps (YARA-L)**: Custom Google SecOps simulator
- **MDE (KQL)**: Custom Advanced Hunting simulator

**📚 Detailed Guide**: [Runtime Validation Guide](features/RUNTIME_VALIDATION.md)

### Settings

Configure API keys and preferences for enhanced functionality.

#### AI API Keys
- **OpenAI**: For AI-enhanced TTP extraction and correlation
- **Anthropic**: For Claude-based extraction

#### SIEM API Keys
- **Splunk**: API credentials for query execution
- **Microsoft Defender**: OAuth2 credentials for MDE
- **Elastic**: API keys for Elastic Security

#### Correlation Parameters
Tune correlation quality and coverage:
- **Threshold**: Minimum quality score (0-100%)
- **Per-Vendor**: Max correlations per vendor
- **Tech Frequency**: Max technique appearances

#### Security Settings
- **MFA**: Enable two-factor authentication (TOTP)
- **Session Timeout**: Configure automatic logout
- **Password Policy**: Enforce password complexity

**Note**: For untested features (Query Execution, Adversary Emulation), see [docs/UNTESTED.md](UNTESTED.md)

### Reading Correlation Results

When correlations are generated, the results page shows each correlation with an **attack flow diagram** and **per-technique detection queries**.

#### Attack Flow Diagram

Each correlation displays a horizontal tactic flow — boxes connected by arrows representing the kill-chain stages covered:

```
PERSISTENCE → PRIVILEGE ESCALATION → DEFENSE EVASION → LATERAL MOVEMENT
```

- **Blue border** — primary tactics directly involved in the correlation pair
- **Technique count badge** — number of techniques covering that tactic
- **Tactic emoji** — quick visual reference for each kill-chain stage

#### Individual Detection Queries

Below the attack flow, each technique in the correlation has its own detection query block:

```
┌─────────────────────────────────────────────┐
│ Technique Name   T1078.004   Initial Access  │  📋
│─────────────────────────────────────────────│
│ DeviceSignInLogs                            │
│ | where Application == "Office 365"...      │
└─────────────────────────────────────────────┘
          ── chained with ──
┌─────────────────────────────────────────────┐
│ Technique Name   T1484.001   Persistence    │  📋
│─────────────────────────────────────────────│
│ DeviceRegistryEvents                        │
│ | where RegistryKey contains "Run"...       │
└─────────────────────────────────────────────┘
```

Each block shows:
- **Technique name** — formatted name from the YAML file
- **ATT&CK ID badge** — e.g., `T1078.004`
- **Tactic badge** — kill-chain stage
- **📋 Copy button** — copy the individual query to clipboard

Click **Show Combined Query** to see the full chained JOIN query that combines all individual queries into a single correlation rule.

#### Metadata Row

Above the attack flow, each correlation shows:
- **Relevance %** — correlation quality score (0–100%)
- **Time Window** — JOIN window (e.g., 1h)
- **Tactics** — all MITRE ATT&CK tactics covered

#### Tables/Indexes

Below the metadata, the data sources referenced by the correlation are shown as pills:
- MDE: table names (e.g., `DeviceEvents`, `DeviceProcessEvents`)
- Splunk: index names (e.g., `index=windows_events`)

---

## Command Line Interface (CLI)

Archer includes a powerful CLI for running core functionality without the web interface.

### Basic Commands

```bash
# View all available commands
python archer.py --help

# Generate detections for a threat group
python archer.py generate "APT29"

# Generate detections AND run correlation
python archer.py generate "APT29" --correlate

# Build correlations for specific threat group
python archer.py correlate "Scattered Spider"

# Hunt for specific technique
python archer.py hunt "PowerShell"
```

### Generate Detections

**Basic Generation**:
```bash
# Generate detections for threat group
python archer.py generate "APT29"

# With OSINT enhancement
python archer.py generate "APT29" --osint

# With correlation
python archer.py generate "APT29" --correlate
```

**Advanced Options**:
```bash
# Specify output directory
python archer.py generate "APT29" --output /path/to/output

# Specify platforms
python archer.py generate "APT29" --platforms splunk,mde

# Limit techniques
python archer.py generate "APT29" --max-techniques 10
```

### Build Correlations

```bash
# Build correlations for threat group
python archer.py correlate "APT29"

# Adjust correlation parameters
python archer.py correlate "APT29" --threshold 50 --per-vendor 30

# Output to specific directory
python archer.py correlate "APT29" --output /path/to/correlations
```

### Tune Correlation Parameters

Test different parameter combinations to optimize correlation quality vs. coverage.

```bash
# Test different parameter combinations
python scripts/test_correlation_params.py -t 40 -v 60 -f 20

# Options:
#   -t, --threshold     Minimum quality score (0-100%)
#   -v, --per-vendor    Max correlations per vendor
#   -f, --tech-freq     Max technique appearances
```

**Quick Presets**:

**Small SOC** (high quality, low volume):
```bash
python scripts/test_correlation_params.py -t 50 -v 25 -f 15
```
- ~20-30 high-quality correlations
- Focus on most reliable patterns
- Minimal false positives

**Standard** (balanced):
```bash
python scripts/test_correlation_params.py -t 40 -v 60 -f 20  # ⭐ Default
```
- ~40-60 balanced correlations
- Good quality with reasonable coverage
- Recommended for most teams

**Large SOC** (comprehensive coverage):
```bash
python scripts/test_correlation_params.py -t 40 -v 100 -f 30
```
- ~80-110 comprehensive correlations
- Maximum coverage
- May include more experimental patterns

**📚 Detailed Parameter Guide**: [docs/architecture/CORRELATION_QUICK_REFERENCE.md](architecture/CORRELATION_QUICK_REFERENCE.md)

### Complete CLI Workflow

End-to-end detection generation and correlation workflow:

```bash
# 1. Generate detections
python archer.py generate "APT29"

# 2. Build correlations
python archer.py correlate "APT29"

# 3. Results saved in data/groups/ and data/correlate/
ls data/groups/APT29/
ls data/correlate/APT29/
```

### Hunt for Techniques

Search for detections covering specific techniques:

```bash
# Hunt for technique by keyword
python archer.py hunt "PowerShell"

# Hunt by technique ID
python archer.py hunt "T1059.001"

# Hunt by tactic
python archer.py hunt "Execution"
```

---

## API Integration

Archer provides a REST API for programmatic access and workflow automation.

### Quick Start

**Python Example**:
```python
import requests

# Create session
session = requests.Session()

# Login
session.post(
    'http://localhost:8000/login',
    data={'email': 'user@example.com', 'password': 'your_password'}
)

# Generate detections
response = session.post(
    'http://localhost:8000/generate',
    data={'group_name': 'APT29', 'run_correlation': 'true'}
)

print(f"Started generation: {response.json()['redirect']}")
```

**JavaScript Example**:
```javascript
const axios = require('axios');

// Create session
const session = axios.create({
  baseURL: 'http://localhost:8000',
  withCredentials: true
});

// Login
await session.post('/login', {
  email: 'user@example.com',
  password: 'your_password'
});

// Generate detections
const response = await session.post('/generate', {
  group_name: 'APT29',
  run_correlation: true
});

console.log(`Started generation: ${response.data.redirect}`);
```

**cURL Example**:
```bash
# Login
curl -c cookies.txt -X POST http://localhost:8000/login \
  -d "email=user@example.com" \
  -d "password=your_password"

# Generate detections
curl -b cookies.txt -X POST http://localhost:8000/generate \
  -d "group_name=APT29" \
  -d "run_correlation=true"
```

### Core Workflows

#### 1. Generate Detections from Threat Group

```python
import requests
import time

session = requests.Session()

# Login
session.post(
    'http://localhost:8000/login',
    data={'email': 'user@example.com', 'password': 'your_password'}
)

# Generate detections
generate_response = session.post(
    'http://localhost:8000/generate',
    data={
        'group_name': 'APT29',
        'osint_enhancement': 'true',
        'run_correlation': 'true'
    }
)

# Poll progress
while True:
    progress = session.get(
        f'http://localhost:8000/progress_status?group_name=APT29'
    ).json()

    print(f"Progress: {progress['progress']['percentage']}%")

    if progress['progress']['status'] == 'complete':
        break

    time.sleep(2)

# Download results
zip_file = session.get(f'http://localhost:8000/api/download/all/APT29')
with open('APT29.zip', 'wb') as f:
    f.write(zip_file.content)
```

#### 2. Upload and Analyze Threat Report

```python
# Upload file
with open('threat_report.pdf', 'rb') as f:
    upload_response = session.post(
        'http://localhost:8000/upload',
        files={'file': f},
        data={'use_openai': 'true'}
    )

# Get extracted TTPs
ttps = upload_response.json()['ttps']

# Generate detections for selected TTPs
selected_ttps = [ttp['id'] for ttp in ttps[:5]]  # First 5 TTPs
session.post(
    'http://localhost:8000/generate_from_upload',
    json={'selected_ttps': selected_ttps}
)
```

#### 3. Company Threat Profiling

```python
# Profile company
profile_response = session.post(
    'http://localhost:8000/profile',
    data={
        'company_domain': 'microsoft.com',
        'industry_analysis': 'true',
        'geographic_analysis': 'true'
    }
)

# Get relevant threat groups
threat_groups = profile_response.json()['threat_groups']

# Generate detections for top 5 threat groups
for group in threat_groups[:5]:
    session.post(
        'http://localhost:8000/generate',
        data={'group_name': group['name']}
    )
```

### Interactive API Documentation

Archer provides auto-generated interactive API documentation:

- **Swagger UI**: `http://localhost:8000/docs`
  - Interactive interface to test API endpoints
  - Complete parameter documentation
  - Example requests and responses

- **ReDoc**: `http://localhost:8000/redoc`
  - Clean, readable API reference
  - Searchable endpoint documentation
  - Code examples in multiple languages

- **OpenAPI Schema**: `http://localhost:8000/openapi.json`
  - Machine-readable API specification
  - Import into Postman, Insomnia, etc.
  - Generate client libraries

### Complete API Guide

For comprehensive API documentation including authentication, error handling, and all workflows:

**📚 [API Integration Guide](features/API_INTEGRATION_GUIDE.md)** - Complete REST API documentation with examples

---

## Best Practices

### Web Interface

- **Use OSINT Enhancement** for comprehensive detection coverage
- **Enable Correlation** for multi-stage attack detection
- **Tag detections** for easy organization and retrieval
- **Configure mappings** before generating detections
- **Review extracted TTPs** from uploaded files before generating

### CLI

- **Use `--correlate`** flag for automated correlation generation
- **Test correlation parameters** to optimize for your environment
- **Organize output directories** by threat group or campaign
- **Automate workflows** with shell scripts or cron jobs

### API

- **Implement retry logic** for resilient integrations
- **Poll progress endpoints** to avoid timeouts
- **Use connection pooling** for performance
- **Handle authentication expiry** gracefully
- **Log API requests** for debugging

---

## Troubleshooting

### Web Interface Issues

**Issue**: Cannot access web interface

**Solution**:
```bash
# Check if Archer is running
docker ps  # Docker installation
ps aux | grep uvicorn  # Local installation

# Check logs
docker-compose logs archer  # Docker
tail -f logs/archer.log  # Local
```

**Issue**: Slow detection generation

**Solution**:
- Reduce number of techniques with `--max-techniques`
- Disable OSINT enhancement for faster generation
- Check system resources (CPU, memory)

### CLI Issues

**Issue**: `python archer.py` command not found

**Solution**:
```bash
# Activate virtual environment (local installation)
source venv/bin/activate

# Or use full path
python3 /path/to/archer/archer.py --help
```

**Issue**: Correlation generation takes too long

**Solution**:
- Increase threshold to reduce correlation count
- Decrease per-vendor limit
- Check [Correlation Quick Reference](architecture/CORRELATION_QUICK_REFERENCE.md)

### API Issues

**Issue**: 401 Unauthorized errors

**Solution**:
- Verify login credentials
- Check session cookie is preserved
- Re-authenticate if session expired

**Issue**: Request timeouts

**Solution**:
- Use progress polling instead of waiting for completion
- Increase request timeout in client
- Generate detections for smaller threat groups

---

## Next Steps

- **Review Generated Detections**: [Suggested First Steps](../GETTING_STARTED.md#suggested-first-steps)
- **Import to SIEM**: [Import Detections Guide](../GETTING_STARTED.md#import-detections-to-your-siem)
- **Tune Correlations**: [Correlation Quick Reference](architecture/CORRELATION_QUICK_REFERENCE.md)
- **Explore API**: [API Integration Guide](features/API_INTEGRATION_GUIDE.md)

---

**Need Help?** Check the [documentation index](DOCS.md) or open an [issue](https://github.com/cmdaltr/archer/issues).

**Last Updated**: 2025-03-04
