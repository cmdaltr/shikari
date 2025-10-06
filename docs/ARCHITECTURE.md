# Archer Architecture: Emulation & VECTR Integration

**Version:** 2.0
**Date:** January 2025
**Status:** Implemented

## Table of Contents

1. [Overview](#overview)
2. [Core Architecture](#core-architecture)
3. [Optional Feature Modules](#optional-feature-modules)
4. [Data Flow](#data-flow)
5. [Configuration Management](#configuration-management)
6. [Integration Workflows](#integration-workflows)
7. [Security Considerations](#security-considerations)
8. [Future Enhancements](#future-enhancements)

---

## Overview

Archer is a modular threat hunting detection generator with optional adversary emulation and hunt tracking integrations. The architecture follows a plugin-based design where core functionality remains independent while optional features can be enabled as needed.

### Design Principles

1. **Core Independence**: Core detection generation works without optional modules
2. **Modular Integration**: Optional features are self-contained modules
3. **Configuration-Driven**: Feature flags control module availability
4. **Bidirectional Sync**: Data flows both ways between Archer and external tools
5. **Evidence-Based**: Real attack data enhances theoretical detections

---

## Core Architecture

```
archer/
├── Core Modules
│   ├── mitre/              # MITRE ATT&CK integration
│   │   ├── enterprise.py   # Enterprise ATT&CK data
│   │   ├── retrieve.py     # Procedure extraction
│   │   └── extract.py      # Technique parsing
│   │
│   ├── build/              # Detection generation
│   │   ├── orchestrator.py # Main workflow controller
│   │   ├── detections.py   # Query compilation
│   │   ├── yaml.py         # YAML file generation
│   │   └── queries.py      # Query building
│   │
│   ├── parsers/            # Query parsing
│   │   ├── mde.py          # Microsoft Defender parsing
│   │   ├── splunk.py       # Splunk parsing
│   │   └── semantics.py    # Semantic analysis
│   │
│   └── genai/              # AI-powered correlations
│       ├── engine.py       # Correlation generation
│       └── models.py       # AI model wrappers
│
├── Optional Modules (Plugin Architecture)
│   ├── emulation/          # Adversary emulation
│   │   ├── atomic.py       # Atomic Red Team
│   │   ├── parser.py       # Evidence extraction
│   │   └── enrich.py       # Detection enrichment
│   │
│   └── vectr/              # VECTR integration
│       ├── client.py       # API client
│       ├── campaigns.py    # Campaign management
│       ├── testcases.py    # Test case management
│       └── export.py       # Sync functionality
│
└── config.py               # Centralized configuration
```

### Core Components

#### 1. MITRE ATT&CK Integration
- Fetches STIX data from MITRE repositories
- Extracts threat group procedures
- Maps techniques to tactics
- Provides technique descriptions

#### 2. Detection Builder
- Generates KQL/Splunk queries
- Creates YAML detection files
- Handles platform compatibility
- Manages query templates

#### 3. Correlation Engine
- Combines related queries
- Performs semantic analysis
- Scores relevance
- Generates multi-query correlations

---

## Optional Feature Modules

### Emulation Module (`archer/emulation/`)

**Purpose**: Execute real attack techniques and collect evidence to enhance detections.

**Components**:

```python
# atomic.py
class AtomicRedTeam:
    - execute_technique()      # Run atomic tests
    - collect_evidence()       # Capture artifacts
    - list_techniques()        # Available tests

# parser.py
class EmulationParser:
    - parse_atomic_results()   # Extract indicators
    - generate_kql()           # Create queries from evidence
    - enrich_yaml()            # Add evidence to YAMLs

# enrich.py
def enrich_detections_with_emulation():
    - Match emulation → detections
    - Add evidence sections
    - Generate additional queries
```

**Data Flow**:
```
Atomic Red Team Tests
         ↓
    Execute (simulate or live)
         ↓
    Collect Evidence
    (commands, processes, files, registry)
         ↓
    Parse Indicators
         ↓
    Enrich YAML Files
    + Generate KQL Queries
```

**Configuration**:
```python
class EmulationConfig:
    enabled = ENABLE_EMULATION
    atomic_path = ATOMIC_REDTEAM_PATH
    execution_mode = EMULATION_EXECUTE_MODE  # simulate or live
```

---

### VECTR Module (`archer/vectr/`)

**Purpose**: Track threat hunts, validate detections, and collaborate with purple teams.

**Components**:

```python
# client.py
class VECTRClient:
    - _request()               # HTTP API calls
    - create_campaign()        # Campaign CRUD
    - create_test_case()       # Test case CRUD
    - list_*()                 # List operations

# campaigns.py
class CampaignManager:
    - create_hunt_campaign()   # New hunt campaign
    - get_campaign_summary()   # Statistics
    - export_campaign()        # Save to JSON

# testcases.py
class TestCaseManager:
    - create_detection_test_case()  # YAML → Test case
    - update_test_result()          # Record results
    - get_detection_coverage()      # Coverage analysis

# export.py
def export_to_vectr():         # Archer → VECTR
def import_from_vectr():       # VECTR → Archer
def sync_with_vectr():         # Bidirectional
```

**Data Flow**:
```
Export:
  Archer YAML Detections
           ↓
     VECTR Campaign
           ↓
     Test Cases Created
           ↓
   Purple Team Testing

Import:
     Test Results
           ↓
    Update YAMLs
           ↓
  Add vectr_validation
           ↓
  Confidence Scoring
```

**Configuration**:
```python
class VECTRConfig:
    enabled = ENABLE_VECTR
    url = VECTR_URL
    api_token = VECTR_API_TOKEN
    default_campaign = VECTR_DEFAULT_CAMPAIGN
```

---

## Data Flow

### Complete Workflow with All Features

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. THREAT GROUP INPUT                                           │
│    User specifies: "APT29"                                      │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. CORE: MITRE ATT&CK RETRIEVAL                                 │
│    • Fetch threat group from STIX                               │
│    • Extract techniques (T1059.001, T1071.001, etc.)            │
│    • Get procedures and descriptions                            │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. CORE: DETECTION GENERATION                                   │
│    • Build KQL/Splunk queries                                   │
│    • Create YAML files (data/generate/)                         │
│    • Map to platforms (MDE, Splunk, Sentinel)                   │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. OPTIONAL: EMULATION (if ENABLE_EMULATION=true)               │
│    • Run Atomic Red Team tests                                  │
│    • Collect execution evidence                                 │
│    • Parse indicators (commands, processes, files)              │
│    • Enrich YAML files with emulation_evidence                  │
│    • Generate additional validated queries                      │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. CORE: CORRELATION BUILDING                                   │
│    • Analyze query relationships                                │
│    • Perform semantic grouping                                  │
│    • Calculate relevance scores                                 │
│    • Generate multi-query correlations (data/correlate/)        │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. OPTIONAL: VECTR EXPORT (if ENABLE_VECTR=true)                │
│    • Create hunt campaign in VECTR                              │
│    • Export detections as test cases                            │
│    • Include operator guidance from emulation                   │
│    • Map to MITRE ATT&CK in VECTR                               │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 7. PURPLE TEAM TESTING (Manual, in VECTR)                       │
│    • Execute detections in target environment                   │
│    • Run emulation tests                                        │
│    • Record results (pass/fail/partial)                         │
│    • Track false positives                                      │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 8. OPTIONAL: VECTR IMPORT                                       │
│    • Fetch test results from VECTR                              │
│    • Update YAML files with vectr_validation                    │
│    • Add detection confidence scores                            │
│    • Track validation status                                    │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 9. FINAL OUTPUT                                                 │
│    • Validated detection YAMLs                                  │
│    • Correlation queries                                        │
│    • Coverage reports                                           │
│    • Evidence-based confidence scores                           │
└─────────────────────────────────────────────────────────────────┘
```

### Data Directory Structure

```
data/
├── generate/                    # Core output
│   ├── T1059001_MDE_001.yaml   # Detection queries
│   ├── T1071001_Splunk_001.yaml
│   └── *_example.yaml          # Example files (git tracked)
│
├── correlate/                   # Core correlations
│   ├── APT29.json              # Group correlations
│   └── *_example.json          # Examples (git tracked)
│
├── hunt/                        # Hunt-specific output
│   └── *.yaml
│
├── emulation/                   # Optional: Emulation data
│   ├── T1059.001_atomic_*.json # Test results
│   └── evidence/               # Captured artifacts
│       ├── T1059.001_1_stdout.log
│       └── .gitkeep
│
└── vectr/                       # Optional: VECTR data
    ├── campaigns/               # Campaign exports
    │   ├── APT29_Hunt_*.json
    │   └── .gitkeep
    └── exports/                 # Export artifacts
        └── .gitkeep
```

---

## Configuration Management

### Centralized Config (`archer/config.py`)

```python
class CoreConfig:
    """Core Archer settings"""
    generate_dir = "data/generate"
    correlate_dir = "data/correlate"
    hunt_dir = "data/hunt"
    genai_mode = GENAI_MODE  # heuristic, semantic, ai_generators, local_llm

class EmulationConfig:
    """Optional emulation settings"""
    enabled = ENABLE_EMULATION  # Default: false

    # Atomic Red Team
    atomic_path = ATOMIC_REDTEAM_PATH
    atomic_runner = ATOMIC_RUNNER

    # MITRE CALDERA (planned)
    caldera_url = CALDERA_API_URL
    caldera_api_key = CALDERA_API_KEY

    # Execution
    output_dir = "data/emulation"
    evidence_dir = "data/emulation/evidence"

    @classmethod
    def is_atomic_configured(cls):
        return cls.enabled and os.path.exists(cls.atomic_path)

class VECTRConfig:
    """Optional VECTR settings"""
    enabled = ENABLE_VECTR  # Default: false

    # Connection
    url = VECTR_URL
    api_token = VECTR_API_TOKEN

    # Defaults
    default_campaign = VECTR_DEFAULT_CAMPAIGN
    default_environment = VECTR_DEFAULT_ENVIRONMENT

    # Output
    output_dir = "data/vectr"

    @classmethod
    def is_configured(cls):
        return cls.enabled and cls.api_token is not None
```

### Environment Variables

```bash
# Core Settings
GENAI_MODE=semantic

# Emulation (Optional)
ENABLE_EMULATION=true
ATOMIC_REDTEAM_PATH=/opt/atomic-red-team
EMULATION_EXECUTE_MODE=simulate  # or 'live'

# VECTR (Optional)
ENABLE_VECTR=true
VECTR_URL=https://vectr.example.com:8081
VECTR_API_TOKEN=eyJhbGc...
VECTR_DEFAULT_CAMPAIGN=Archer-ThreatHunt
VECTR_DEFAULT_ENVIRONMENT=Production
```

---

## Integration Workflows

### Workflow 1: Core Only (No Optional Features)

```bash
# Standard threat hunting workflow
python3 archer.py generate "APT29"

# Optionally run correlation
python3 archer.py generate "APT29" --correlate
# OR
python3 archer.py correlate --verbose

# Output:
# - data/generate/*.yaml
# - data/correlate/APT29.json (if --correlate used)
```

**Use Case**: Quick detection generation without validation

> **Note**: Correlation is now **opt-in** via `--correlate` flag or separate `correlate` command.

---

### Workflow 2: With Emulation

```bash
# Enable emulation
export ENABLE_EMULATION=true
export ATOMIC_REDTEAM_PATH=/opt/atomic-red-team

# Generate detections
python3 archer.py generate "APT29"

# Run emulation and enrich
python3 archer.py emulate T1059.001 --enrich
python3 archer.py emulate T1071.001 --enrich

# Optionally build correlations (now with emulation evidence)
python3 archer.py correlate --verbose

# Output:
# - data/generate/*.yaml (with emulation_evidence sections)
# - data/correlate/APT29.json (higher confidence)
# - data/emulation/T*.json (test results)
```

**Use Case**: Evidence-based detections with validated indicators

---

### Workflow 3: With VECTR Tracking

```bash
# Enable VECTR
export ENABLE_VECTR=true
export VECTR_URL=https://vectr.local:8081
export VECTR_API_TOKEN=your-token

# Generate detections
python3 archer.py generate "APT29"

# Export to VECTR
python3 archer.py vectr export --threat-group "APT29"
# Returns: Campaign ID: camp_123abc

# (Purple team tests detections in VECTR)

# Import results
python3 archer.py vectr import \
  --campaign-id camp_123abc \
  --update-yamls

# Generate coverage report
python3 archer.py vectr coverage --campaign-id camp_123abc

# Output:
# - data/generate/*.yaml (with vectr_validation sections)
# - data/vectr/campaigns/*.json
# - Coverage reports
```

**Use Case**: Organized hunt campaigns with validation tracking

---

### Workflow 4: Complete Integration (Emulation + VECTR)

```bash
# Enable all features
export ENABLE_EMULATION=true
export ENABLE_VECTR=true
export ATOMIC_REDTEAM_PATH=/opt/atomic-red-team
export VECTR_URL=https://vectr.local:8081
export VECTR_API_TOKEN=your-token

# Step 1: Generate detections
python3 archer.py generate "APT29"

# Step 2: Run emulation and enrich
python3 archer.py emulate T1059.001 --enrich --verbose
python3 archer.py emulate T1071.001 --enrich --verbose

# Step 3: Optionally build correlations
python3 archer.py correlate --verbose

# Step 4: Export to VECTR (includes emulation evidence as operator guidance)
python3 archer.py vectr export --threat-group "APT29"
# Returns: Campaign ID: camp_123abc

# Step 5: Purple team executes tests in VECTR

# Step 6: Continuous sync
python3 archer.py vectr sync --campaign-id camp_123abc --threat-group "APT29"

# Step 7: Generate final report
python3 archer.py vectr coverage --campaign-id camp_123abc > coverage.md
```

**Use Case**: Enterprise-grade detection development with full validation

**Output Structure**:
```yaml
# Example enriched YAML
name: PowerShell Encoded Command Execution
description: Detects encoded PowerShell execution
query: |
  DeviceProcessEvents
  | where ProcessCommandLine has "-encodedcommand"
tags:
  - APT29 (Group)
  - PowerShell
relevantTechniques:
  - T1059.001

# From emulation
emulation_evidence:
  source: Atomic Red Team
  technique_id: T1059.001
  processes: [powershell.exe]
  sample_commands:
    - powershell.exe -nop -w hidden -encodedcommand ...

# From VECTR
vectr_validation:
  campaign_id: camp_123abc
  test_case_id: tc_001
  status: completed
  result: pass
  detected: true
  confidence: high
  tested_date: 2025-01-05T14:30:00Z
  false_positives: 0
```

---

## Security Considerations

### Emulation Module

**Risks**:
- Live execution runs actual attack techniques
- Could trigger real alerts
- May cause system instability

**Mitigations**:
1. **Default Simulation Mode**: No commands execute by default
2. **Explicit Execution Flag**: Requires `--execute` flag
3. **Platform Checking**: Verifies OS compatibility
4. **Isolated Environments**: Recommend lab-only execution
5. **Cleanup Commands**: Automatic cleanup after tests
6. **Timeout Protection**: 5-minute execution timeout

**Best Practices**:
```bash
# SAFE: Simulation mode (default)
python3 archer.py emulate T1059.001

# DANGEROUS: Live execution (isolated lab only!)
python3 archer.py emulate T1059.001 --execute
```

### VECTR Module

**Risks**:
- API credentials in environment
- Network communication to VECTR server
- Sensitive detection data export

**Mitigations**:
1. **Token-Based Auth**: No passwords in config
2. **HTTPS Communication**: Encrypted API calls
3. **Token Validation**: Checked before operations
4. **Permission Scoping**: VECTR RBAC controls access
5. **Audit Logging**: VECTR logs all API calls

**Best Practices**:
```bash
# Store token securely
export VECTR_API_TOKEN=$(cat ~/.vectr/token)

# Use HTTPS
export VECTR_URL=https://vectr.local:8081

# Rotate tokens regularly
# (via VECTR web interface)
```

---

## Future Enhancements

### Emulation Module Roadmap

- [ ] **MITRE CALDERA Integration**
  - Autonomous adversary emulation
  - Multi-step attack chains
  - C2 server integration

- [ ] **MACAT Integration**
  - Mapped attack chain analysis
  - Automated correlation testing

- [ ] **Network Capture**
  - PCAP analysis from emulation
  - Network indicator extraction
  - C2 pattern detection

- [ ] **Memory Analysis**
  - Process memory dumps
  - In-memory IOC extraction
  - Malware behavior analysis

- [ ] **EDR Integration**
  - Direct EDR telemetry correlation
  - Real-time detection validation
  - Alert tuning recommendations

### VECTR Module Roadmap

- [ ] **Web UI Integration**
  - Campaign management dashboard
  - Visual coverage analytics
  - Interactive test case editor

- [ ] **Automated Scheduling**
  - Periodic sync jobs
  - Scheduled test execution
  - Automated reporting

- [ ] **Webhook Support**
  - Real-time result notifications
  - Event-driven sync
  - Status updates to Slack/Teams

- [ ] **Advanced Analytics**
  - MITRE ATT&CK heatmaps
  - Trend analysis
  - Detection efficacy metrics

- [ ] **Multi-Environment**
  - Cross-environment testing
  - Environment-specific tuning
  - Deployment tracking

### Core Platform Enhancements

- [ ] **Additional Query Platforms**
  - Elastic Security
  - CrowdStrike
  - Carbon Black

- [ ] **Machine Learning**
  - Anomaly detection baselines
  - False positive prediction
  - Auto-tuning recommendations

- [ ] **CI/CD Integration**
  - GitHub Actions workflows
  - Automated testing pipelines
  - Version control for detections

---

## Conclusion

Archer's plugin architecture provides:

1. **Core Functionality**: Robust detection generation without dependencies
2. **Optional Enhancements**: Emulation and VECTR when needed
3. **Modular Design**: Clean separation of concerns
4. **Flexible Workflows**: Use what you need, when you need it
5. **Evidence-Based**: Real attack data enhances theoretical detections
6. **Enterprise Ready**: Scalable, trackable, validated

The architecture supports both rapid detection prototyping and enterprise-grade validation workflows, making Archer suitable for organizations of any size.
