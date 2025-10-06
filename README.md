# 🏹 Archer: Threat Hunting Detection Generator

Archer is a modular Python service for automated threat hunting with optional adversary emulation and hunt tracking integrations. Generate detection queries, validate with real attack execution, and track hunts with VECTR integration.

## ✨ Features

### Core Capabilities
- 🎯 **MITRE ATT&CK Integration** - Automated detection generation from threat group TTPs
- 🔍 **Multi-Platform Support** - KQL (Microsoft Defender/Sentinel) and Splunk (SPL) queries
- 🧠 **AI-Powered Correlations** - Semantic analysis and query correlation
- 🌐 **Web UI & CLI** - FastAPI web interface plus command-line tools

### Optional Modules
- 💥 **Adversary Emulation** (NEW) - Atomic Red Team integration for evidence-based detections
- 📊 **VECTR Integration** (NEW) - Hunt tracking, validation, and purple team collaboration
- 🔗 **n8n Workflow Automation** - API endpoints for workflow integration

---
<br>

## 1️⃣ Prerequisites

- **Docker & Docker Compose** (for containerized setup)
- **Python 3.11+** (for local setup)
- **Optional**: Atomic Red Team (for emulation module)
- **Optional**: VECTR instance (for hunt tracking)

---
<br>

## 2️⃣ Clone the repository

```bash
git clone https://github.com/cmdshiftd/archer.git
cd archer
```

---
<br>

## 3️⃣ Setup Options

### Option A: Run with Docker (Recommended)

1. Build and start the service using Docker Compose:

```bash
docker-compose up --build
```

2. The FastAPI service will be available at `http://localhost:8000`.

3. To stop the service, press `Ctrl+C` and then run:

```bash
docker-compose down
```

---
<br>

### Option B: Run Locally with Python

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the FastAPI service:

```bash
uvicorn archer.main:app --reload
```

The service will be available at `http://localhost:8000`.

---
<br>

### Option C: Use as a Console Script (CLI)

Archer includes a powerful CLI for running core functionality without the web interface.

#### Basic Commands

```bash
# View all available commands
python3 archer.py --help

# Generate detections for a threat group
python3 archer.py generate "APT29"

# Build correlations
python3 archer.py correlate --verbose

# Hunt for specific technique
python3 archer.py hunt "PowerShell"
```

#### Adversary Emulation (Optional)

Run Atomic Red Team tests and enrich detections with evidence:

```bash
# Enable emulation module
export ENABLE_EMULATION=true
export ATOMIC_REDTEAM_PATH=/opt/atomic-red-team

# Simulate tests for a single technique (safe)
python3 archer.py emulate --technique-id T1059.001 --enrich

# Simulate tests for entire threat group
python3 archer.py emulate --threat-group "APT29" --enrich

# Limit to first 10 techniques
python3 archer.py emulate --threat-group "APT29" --max-techniques 10 --enrich

# Live execution (LAB ONLY!)
python3 archer.py emulate --threat-group "APT29" --execute --enrich
```

See [docs/EMULATION.md](docs/EMULATION.md) for detailed emulation documentation.

#### VECTR Integration (Optional)

Track hunts and validate detections with VECTR:

```bash
# Enable VECTR module
export ENABLE_VECTR=true
export VECTR_URL=https://vectr.local:8081
export VECTR_API_TOKEN=your-api-token

# Export detections to VECTR campaign
python3 archer.py vectr export --threat-group "APT29"

# List campaigns
python3 archer.py vectr list

# Import test results
python3 archer.py vectr import --campaign-id camp_123abc --update-yamls

# Bidirectional sync
python3 archer.py vectr sync --campaign-id camp_123abc --threat-group "APT29"

# Generate coverage report
python3 archer.py vectr coverage --campaign-id camp_123abc
```

See [docs/VECTR.md](docs/VECTR.md) for detailed VECTR documentation.

#### Complete Workflow Example

```bash
# 1. Generate detections
python3 archer.py generate "APT29"

# 2. Run emulation and enrich
python3 archer.py emulate --threat-group "APT29" --enrich

# 3. Build correlations
python3 archer.py correlate --verbose

# 4. Export to VECTR for tracking
python3 archer.py vectr export --threat-group "APT29"

# 5. (After testing in VECTR) Import results
python3 archer.py vectr import --campaign-id camp_123abc --update-yamls
```

---
<br>

## ⚙️ Using Archer with n8n

Archer integrates seamlessly with [n8n](https://n8n.io/) for workflow automation.

### Example: Trigger Archer Hunt via HTTP Request Node

1. Add an HTTP Request node in n8n.

2. Configure it to make a POST request to Archer's endpoint:

```
POST http://localhost:8000/hunt
Content-Type: application/json

{
  "techniques": ["T1059", "T1086"],
  "filters": {
    "platform": "windows"
  }
}
```

3. The response will contain the hunt queries in YAML format, which can be parsed and used in subsequent workflow nodes.

---
<br>

### Tips for n8n Integration

- Use the **Function** node to parse YAML responses into JSON for easier manipulation.

- Chain multiple Archer calls to build complex threat hunting workflows.

- Combine Archer outputs with enrichment services (e.g., VirusTotal, MISP) within n8n.

---
<br>

## 📚 Documentation & Resources

### Archer Documentation
- [Architecture Overview](docs/ARCHITECTURE.md) - Complete system architecture
- [Emulation Guide](docs/EMULATION.md) - Adversary emulation integration
- [VECTR Guide](docs/VECTR.md) - Hunt tracking and validation
- [Correlations](docs/CORRELATIONS.md) - Correlation query builder

### External Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [VECTR](https://vectr.io/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [n8n Workflow Automation](https://n8n.io/)

---
<br>

## 🤝 Contributing

Feel free to open issues or submit pull requests to improve Archer.

---
<br>

## 📝 License

This project is licensed under the MIT License. See the LICENSE file for details.