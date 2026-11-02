# Runtime Detection Validation

**Last Updated:** 2026-02-08
**Status:** Fully Operational

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Architecture](#architecture)
4. [Using the Validate Tab](#using-the-validate-tab)
5. [API Reference](#api-reference)
6. [SIEM Simulators](#siem-simulators)
7. [Event Generation](#event-generation)
8. [Refinement System](#refinement-system)
9. [Troubleshooting](#troubleshooting)

---

## Overview

Runtime Detection Validation tests your detection queries against sample events in containerized SIEM environments. Unlike pre-generation validation (which prevents cross-platform contamination), runtime validation tests whether your queries actually detect the attacks they're designed to catch.

### Key Features

- **Query time** - `query_time_ms` times the query on its own, apart from ingesting the sample events (`execution_time_ms` covers both). Sample events say little about cost at production volumes: the static run cost on each detection (`shikari/validation/cost.py`) and hit counts ([#16](https://github.com/cmdaltr/shikari/issues/16)) cover that
- **CI gate** - `python -m shikari.validation.ci` (see [Detections as code](../guide/22-detections-as-code.md#check-detections-in-ci))

- **Docker-based SIEM Testing** - Spin up ephemeral SIEM containers for validation
- **Multi-Vendor Support** - Splunk, Elastic, Google SecOps, and MDE
- **LLM-Generated Events** - AI creates realistic malicious and benign sample events
- **Precision/Recall Metrics** - Quantify detection effectiveness with F1 scores
- **AI-Assisted Refinement** - Get suggestions to improve failing detections
- **Iterative Testing** - Refine and re-test until satisfied

### Workflow

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. Open Validate tab → Paste query in textarea                     │
│     ↓                                                               │
│  2. Add indicators (command patterns, process names)                │
│     ↓                                                               │
│  3. Click "Start Validation" → SIEM container starts                │
│     ↓                                                               │
│  4. Sample events generated (malicious + benign)                    │
│     ↓                                                               │
│  5. Query executed → Metrics calculated (TP, FP, TN, FN, F1)        │
│     ↓                                                               │
│  6. If failed: AI suggests improvements                             │
│     ↓                                                               │
│  7. Apply fix → Re-test → Iterate until satisfied                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

### Docker

Docker must be installed and running for validation to work.

**Installation:**
- **macOS**: [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/)
- **Windows**: [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
- **Linux**: [Docker Engine](https://docs.docker.com/engine/install/)

**Verification:**
```bash
docker --version
docker info
```

If Docker is not available, the Validate tab will display a warning message explaining what's missing.

### Starting SIEM Containers

There are two ways to use SIEM containers for validation:

#### Option 1: Pre-start with Docker Compose (Recommended)

Pre-start the SIEM containers you need using docker-compose profiles:

```bash
# Start specific SIEMs
docker-compose --profile secops up -d      # Google SecOps only
docker-compose --profile mde up -d         # MDE only
docker-compose --profile splunk up -d      # Splunk only
docker-compose --profile elastic up -d     # Elasticsearch only

# Start multiple SIEMs
docker-compose --profile secops --profile mde up -d

# Start all SIEMs
docker-compose --profile validation up -d
```

The validation system automatically detects and uses these containers when available.

#### Option 2: On-Demand (Ephemeral)

If no pre-started containers are found, the system spawns ephemeral containers on-demand. These are stopped when the validation session ends. This is slower but requires no manual setup.

### Resource Requirements

SIEM containers require:
- **Splunk**: ~2GB RAM, ~1GB disk
- **Elastic**: ~1GB RAM, ~500MB disk
- **Google SecOps Simulator**: ~512MB RAM
- **MDE Simulator**: ~512MB RAM

---

## Architecture

### Components

```
shikari/validation/
├── __init__.py              # Module exports and Docker check
├── api.py                   # FastAPI router (/api/validation/*)
├── orchestrator.py          # Workflow coordinator
├── docker_manager.py        # Container lifecycle management
├── event_generator.py       # LLM-powered sample event creation
├── detection_tester.py      # Query execution and result analysis
└── detection_refiner.py     # AI-assisted query improvement

shikari/siem/
├── secops/                        # Google SecOps simulator
│   ├── Dockerfile                 # Container definition
│   ├── simulator.py               # Flask API
│   └── yaral_parser.py            # YARA-L rule engine
└── mde/                           # MDE simulator
    ├── Dockerfile                 # Container definition
    ├── simulator.py               # Flask API
    └── kql_parser.py              # KQL query engine

docker-compose.yml                 # Main compose file (all services with profiles)
```

### Data Flow

```
┌──────────────┐     ┌───────────────────┐     ┌─────────────────┐
│   Frontend   │────▶│  ValidationAPI    │────▶│  Orchestrator   │
│  (JS/HTML)   │◀────│  (/api/validation)│◀────│                 │
└──────────────┘     └───────────────────┘     └────────┬────────┘
                                                        │
                     ┌──────────────────────────────────┼──────────────────────────────────┐
                     │                                  │                                  │
              ┌──────▼──────┐                    ┌──────▼──────┐                    ┌──────▼──────┐
              │   Docker    │                    │   Event     │                    │  Detection  │
              │   Manager   │                    │  Generator  │                    │   Tester    │
              └──────┬──────┘                    └─────────────┘                    └──────┬──────┘
                     │                                                                     │
              ┌──────▼──────────────────────────────────────────────────────────────────────▼──────┐
              │                              SIEM Containers                                       │
              │  ┌─────────┐   ┌─────────┐   ┌─────────────┐   ┌─────────────┐                    │
              │  │ Splunk  │   │ Elastic │   │Google SecOps│   │     MDE     │                    │
              │  │  :8000  │   │  :9200  │   │  Simulator  │   │  Simulator  │                    │
              │  │  :8089  │   │         │   │    :8081    │   │    :8082    │                    │
              │  │  :8088  │   │         │   │             │   │             │                    │
              │  └─────────┘   └─────────┘   └─────────────┘   └─────────────┘                    │
              └───────────────────────────────────────────────────────────────────────────────────┘
```

---

## Using the Validate Tab

### Accessing the Feature

1. Navigate to the Shikari web UI (`http://localhost:8000`)
2. Click the **Validate** tab (with the play ▶ icon)
3. The validation panel appears with:
   - A **Detection Query** textarea to paste your query
   - A **vendor dropdown** (auto-detects based on query syntax)
   - **Indicators** fields for generating test events
   - A **Start Validation** button

### Step-by-Step Usage

#### 1. Check Docker Status

When you open the Validate tab, the system checks Docker availability. If Docker is not running, you'll see a warning:

```
⚠️ Docker Required
Docker is not running. Start the Docker daemon to enable detection validation.
```

#### 2. Enter Your Detection Query

Paste your detection query into the text area. The system auto-detects the SIEM vendor based on query syntax:

- **Splunk (SPL)**: `index=`, `sourcetype=`, `| stats`, `| table`
- **Elastic (Query DSL)**: `process.command_line`, `@timestamp`, `"query"`, `"bool"`
- **Google SecOps (YARA-L)**: `rule`, `events:`, `$e.metadata`, `re.regex(`
- **MDE (KQL)**: `DeviceProcessEvents`, `DeviceNetworkEvents`, `| where`

You can also manually select the vendor from the dropdown.

#### 3. Add Indicators

Enter indicators that should be present in malicious events:

- **Command Line Patterns**: `powershell.exe -NoP -W Hidden`, `cmd.exe /c`
- **Process/File Names**: `mimikatz.exe`, `procdump.exe`

These indicators help the event generator create realistic test data.

#### 4. Start Validation

Click **Start Validation**. The system will:

1. **Start SIEM** - Spin up the appropriate Docker container
2. **Generate Events** - Create 10 malicious + 20 benign sample events
3. **Test Detection** - Execute your query against the events
4. **Analyze Results** - Calculate metrics and identify issues

#### 5. Review Results

The results panel shows:

**Metrics Grid:**
| Metric | Description |
|--------|-------------|
| True Positives (TP) | Malicious events correctly detected |
| False Negatives (FN) | Malicious events missed |
| False Positives (FP) | Benign events incorrectly flagged |
| True Negatives (TN) | Benign events correctly ignored |

**Scores:**
- **Precision**: TP / (TP + FP) - How many flagged events were actually malicious
- **Recall**: TP / (TP + FN) - How many malicious events were detected
- **F1 Score**: Harmonic mean of precision and recall

#### 6. Apply Refinements

If the detection failed, you'll see AI-generated suggestions:

```
┌─────────────────────────────────────────────────────────────┐
│ FIELD_FIX (85% confidence)                                  │
│                                                             │
│ Description: Use correct field name for process command     │
│                                                             │
│ Original:  process.cmdline                                  │
│ Suggested: process.command_line                             │
│                                                             │
│ [Apply This Fix]                                            │
└─────────────────────────────────────────────────────────────┘
```

Click **Apply This Fix** to update your query, then **Re-run Validation** to test again.

#### 7. Iterate Until Satisfied

Repeat the refinement cycle until your detection achieves acceptable metrics.

---

## API Reference

### Endpoints

All endpoints are prefixed with `/api/validation`.

#### Check Docker Status

```
GET /api/validation/docker-status
```

**Response:**
```json
{
  "available": true,
  "message": "Docker is available for validation testing.",
  "supported_vendors": ["splunk", "elastic", "secops", "mde"]
}
```

#### Check SIEM Availability

```
GET /api/validation/siem-availability
```

Returns status of docker-compose profile containers. Use this to see which SIEMs are pre-started and ready for immediate use.

**Response:**
```json
{
  "available": true,
  "message": "2 of 4 SIEM containers running",
  "siems": {
    "splunk": {
      "available": false,
      "container_name": "shikari-splunk",
      "status": "stopped",
      "start_command": "docker-compose --profile splunk up -d"
    },
    "elastic": {
      "available": false,
      "container_name": "shikari-elastic",
      "status": "stopped",
      "start_command": "docker-compose --profile elastic up -d"
    },
    "secops": {
      "available": true,
      "container_name": "shikari-secops",
      "api_port": 8081,
      "status": "running"
    },
    "mde": {
      "available": true,
      "container_name": "shikari-mde",
      "api_port": 8082,
      "status": "running"
    }
  },
  "start_all_command": "docker-compose --profile validation up -d"
}
```

#### Create Session

```
POST /api/validation/sessions
```

**Request Body:**
```json
{
  "technique_id": "T1059.001",
  "technique_name": "PowerShell",
  "query": "index=windows_events process_name=\"powershell.exe\"",
  "vendor": "splunk",
  "indicators": {
    "cmd": ["powershell.exe -NoP"],
    "sw": ["mimikatz.exe"]
  }
}
```

**Response:**
```json
{
  "success": true,
  "session": {
    "session_id": "abc123-...",
    "technique_id": "T1059.001",
    "status": "created",
    ...
  }
}
```

#### Start SIEM Container

```
POST /api/validation/start-siem
```

Connects to an existing docker-compose container if running, otherwise spawns an ephemeral container.

**Request Body:**
```json
{
  "session_id": "abc123-...",
  "port_offset": 0
}
```

**Response includes:**
- `from_compose`: Whether using a docker-compose container
- `container_type`: "docker-compose" or "ephemeral"
```

#### Generate Events

```
POST /api/validation/generate-events
```

**Request Body:**
```json
{
  "session_id": "abc123-...",
  "indicators": {
    "cmd": ["powershell.exe -NoP -W Hidden"],
    "sw": ["mimikatz.exe"]
  },
  "malicious_count": 10,
  "benign_count": 20
}
```

#### Test Detection

```
POST /api/validation/test
```

**Request Body:**
```json
{
  "session_id": "abc123-...",
  "query": "index=windows_events process_name=\"powershell.exe\""
}
```

**Response:**
```json
{
  "success": true,
  "result": {
    "passed": false,
    "true_positives": 7,
    "false_negatives": 3,
    "false_positives": 2,
    "true_negatives": 18,
    "precision": 0.78,
    "recall": 0.70,
    "f1_score": 0.74
  },
  "iteration": 1
}
```

#### Get Refinement Suggestions

```
GET /api/validation/suggestions/{session_id}
```

**Response:**
```json
{
  "success": true,
  "suggestions": [
    {
      "type": "FIELD_FIX",
      "description": "Use correct field name",
      "original": "process.cmdline",
      "suggested": "process.command_line",
      "confidence": 0.85,
      "explanation": "The field 'process.cmdline' doesn't exist..."
    }
  ],
  "failure_analysis": {
    "type": "field_mismatch",
    "description": "Query uses incorrect field names",
    "causes": ["process.cmdline should be process.command_line"]
  }
}
```

#### Apply Refinement

```
POST /api/validation/refine
```

**Request Body:**
```json
{
  "session_id": "abc123-...",
  "suggestion_index": 0
}
```

#### Quick Validate (All-in-One)

```
POST /api/validation/quick-validate
```

Performs all steps in a single call: create session, start SIEM, generate events, test detection, get suggestions.

#### Stop Session

```
POST /api/validation/stop/{session_id}
```

Stops the validation session. Ephemeral containers are stopped automatically.
Docker-compose containers are released but kept running for reuse.

#### Cleanup SIEM Containers

```
POST /api/validation/cleanup-siem/{vendor}
POST /api/validation/cleanup-siem/all
```

Stops docker-compose SIEM containers when you're done with validation.

**Examples:**
```bash
# Stop specific SIEM
curl -X POST http://localhost:8000/api/validation/cleanup-siem/splunk

# Stop all SIEMs
curl -X POST http://localhost:8000/api/validation/cleanup-siem/all
```

**Response:**
```json
{
  "success": true,
  "message": "Stopped container shikari-splunk",
  "was_running": true
}

---

## SIEM Simulators

### Splunk

Uses the official `splunk/splunk:latest` Docker image with:
- HTTP Event Collector (HEC) for data ingestion
- REST API for query execution (`/services/search/jobs`)
- Ports: 8000 (web), 8089 (API), 8088 (HEC)

### Elasticsearch

Uses `docker.elastic.co/elasticsearch/elasticsearch:8.x` with:
- Bulk API for data ingestion
- Query DSL and EQL for search
- Port: 9200

### Google SecOps Simulator

Custom Python Flask application simulating Google SecOps:

**Features:**
- UDM-formatted event ingestion
- YARA-L rule parsing and execution
- In-memory event store for fast testing

**Endpoints:**
- `POST /api/events` - Ingest events
- `POST /api/query` - Execute YARA-L rules
- `GET /api/validate` - Validate rule syntax
- `POST /api/clear` - Clear event store

### MDE Simulator

Custom Python Flask application simulating Microsoft Defender:

**Features:**
- Device event JSON ingestion
- KQL query parsing and execution
- SQLite or in-memory storage

**Endpoints:**
- `POST /api/events` - Ingest events
- `POST /api/advancedhunting/run` - Execute KQL queries
- `POST /api/query` - Validate query syntax

---

## Event Generation

### How It Works

The event generator uses LLM to create realistic sample events:

1. **Input**: Technique ID, name, and indicators
2. **Schema**: Uses vendor-specific schemas (ECS, UDM, MDE tables)
3. **Output**: Malicious events (should trigger) and benign events (should not trigger)

### Event Types

**Malicious Events:**
- Contain the specified indicators
- Match the technique's expected behavior
- Should be detected by a good query

**Benign Events:**
- Normal system activity
- Similar structure but without malicious indicators
- Should NOT trigger false positives

### Example Generated Events

**Malicious (Splunk format):**
```json
{
  "_time": "2026-02-08T10:30:00Z",
  "process_name": "powershell.exe",
  "process_command_line": "powershell.exe -NoP -W Hidden -Enc ...",
  "user": "CORP\\admin",
  "host": "WORKSTATION01"
}
```

**Benign (Splunk format):**
```json
{
  "_time": "2026-02-08T10:31:00Z",
  "process_name": "notepad.exe",
  "process_command_line": "notepad.exe C:\\Documents\\notes.txt",
  "user": "CORP\\user1",
  "host": "WORKSTATION02"
}
```

---

## Refinement System

### Suggestion Types

| Type | Description | Example |
|------|-------------|---------|
| `FIELD_FIX` | Incorrect field name | `process.cmdline` → `process.command_line` |
| `PATTERN_FIX` | Regex or wildcard issues | `*powershell*` → `*powershell.exe*` |
| `LOGIC_FIX` | AND/OR/NOT logic problems | Missing OR condition |
| `EXCLUSION_ADD` | Add exclusion for false positives | Exclude system processes |
| `SCOPE_ADJUST` | Query too broad or narrow | Add additional filters |
| `SYNTAX_FIX` | Query syntax errors | Missing quotes, parentheses |

### Confidence Scoring

Each suggestion includes a confidence score (0.0-1.0):
- **0.9+**: High confidence, almost certainly correct
- **0.7-0.9**: Good confidence, likely to help
- **0.5-0.7**: Medium confidence, worth trying
- **<0.5**: Low confidence, experimental

---

## Troubleshooting

### Docker Not Available

**Symptom:** Warning message "Docker is not installed"

**Solution:**
1. Install Docker Desktop
2. Start Docker Desktop
3. Verify: `docker info`

### Container Startup Fails

**Symptom:** "Failed to start SIEM" error

**Solutions:**
- Check available disk space
- Ensure ports aren't in use: `lsof -i :8000,9200,8081,8082`
- Check Docker logs: `docker logs shikari-splunk`
- Try restarting Docker

### No Events Generated

**Symptom:** 0 malicious events or 0 benign events

**Solutions:**
- Verify indicators are provided
- Check LLM API connectivity (if using external LLM)
- Review logs for generation errors

### Query Always Fails

**Symptom:** 0 true positives, high false negatives

**Possible Causes:**
- Incorrect field names for the target SIEM
- Events not matching expected schema
- Query syntax errors

**Solution:** Review the AI suggestions and apply field/pattern fixes.

### High False Positives

**Symptom:** Many false positives flagged

**Possible Causes:**
- Query too broad (e.g., just `process_name=powershell.exe`)
- Missing exclusions for legitimate activity

**Solution:** Add exclusions or additional filters as suggested.

---

## Related Documentation

- [Pre-Generation Validation](DETECTION_VALIDATION.md) - Cross-platform validation during generation
- [Docker Guide](DOCKER.md) - General Docker usage with Shikari
- [API Integration Guide](../features/API_INTEGRATION_GUIDE.md) - Complete API reference

---

**Need Help?** Check the [documentation index](../DOCS_INDEX.md) or open an [issue](https://github.com/cmdaltr/shikari/issues).
