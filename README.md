# 🏹 Archer: Threat Hunting Detection Generator

Archer is a modular Python service for automated threat hunting with optional adversary emulation and hunt tracking integrations. Generate detection queries, validate with real attack execution, and track hunts with VECTR integration.

## ✨ Features

### Core Capabilities
- 🎯 **MITRE ATT&CK Integration** - Automated detection generation from threat group TTPs
- 📤 **File Upload & Intelligence Extraction** - Upload threat intel files (PDF, TXT, JSON, CSV, YARA) for automatic TTP/IOC extraction
- 🔍 **Multi-Platform Support** - KQL (Microsoft Defender/Sentinel) and Splunk (SPL) queries
- 🧠 **AI-Powered Correlations** - Semantic analysis and query correlation
- 🌐 **Web UI & CLI** - VirusTotal-inspired tabbed interface plus command-line tools

### Optional Modules
- 💥 **Adversary Emulation** - Atomic Red Team integration for evidence-based detections
  - 🖥️ **Remote Execution** - SSH/WinRM support for cross-platform testing (Linux, macOS, Windows)
  - 🔑 **SSH Key Authentication** - Secure passwordless authentication
  - 🔒 **WinRM HTTPS** - Encrypted Windows remote management (default)
- 📊 **VECTR Integration** - Hunt tracking, validation, and purple team collaboration
- 🔍 **Query Execution** - Execute queries via MDE and Splunk APIs
  - 🌐 **MDE Advanced Hunting** - KQL query execution with OAuth2
  - 📊 **Splunk Search API** - SPL query execution with job management
- 🔗 **n8n Workflow Automation** - API endpoints for workflow integration

---
<br>

## 1️⃣ Prerequisites

- **Docker & Docker Compose** (for containerized setup)
- **Python 3.11+** (for local setup)
- **Optional**: Atomic Red Team (for emulation module)
- **Optional**: VECTR instance (for hunt tracking)
- **Optional**: SSH access or WinRM (for remote emulation)
- **Optional**: MDE or Splunk API credentials (for query execution)

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
uvicorn archer.app:app --reload
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

# Generate detections AND run correlation
python3 archer.py generate "APT29" --correlate

# Build correlations for specific threat group
python3 archer.py correlate "Scattered Spider"

# Hunt for specific technique
python3 archer.py hunt "PowerShell"
```

#### Adversary Emulation (Optional)

Run Atomic Red Team tests locally or remotely and enrich detections with evidence:

```bash
# Emulate specific technique locally (safe simulation)
python3 archer.py emulate T1059.001 --enrich

# Emulate entire threat group locally
python3 archer.py emulate "APT29" --enrich --max-techniques 10

# Live execution locally (LAB ONLY!)
python3 archer.py emulate T1059.001 --execute --enrich

# Remote execution via SSH (Linux/macOS)
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.100 \
  --remote-user admin \
  --ssh-key ~/.ssh/id_rsa \
  --enrich

# Remote execution via WinRM (Windows) - HTTPS default
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.101 \
  --remote-user Administrator \
  --remote-password 'P@ssw0rd' \
  --remote-platform windows \
  --enrich

# Remote execution via WinRM with HTTP (lab only)
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.101 \
  --remote-user Administrator \
  --remote-password 'P@ssw0rd' \
  --remote-platform windows \
  --http \
  --enrich
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

#### Query Execution (Optional)

Execute queries directly against MDE or Splunk APIs:

```bash
# Set up MDE credentials
export MDE_TENANT_ID=your-tenant-id
export MDE_CLIENT_ID=your-client-id
export MDE_CLIENT_SECRET=your-client-secret

# Set up Splunk credentials
export SPLUNK_HOST=splunk.example.com
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD=your-password

# Execute queries (coming soon - module ready, CLI integration pending)
# python3 archer.py generate "APT29" --execute-queries
# python3 archer.py correlate "Scattered Spider" --execute-queries
```

See [docs/QUERY_EXECUTION.md](docs/QUERY_EXECUTION.md) for detailed query execution documentation.

#### Complete Workflow Example

```bash
# 1. Generate detections
python3 archer.py generate "APT29"

# 2. Run emulation and enrich (local or remote)
python3 archer.py emulate "APT29" --enrich --max-techniques 10

# 3. Build correlations
python3 archer.py correlate "APT29"

# 4. (Optional) Export to VECTR for tracking
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
- [Getting Started Guide](docs/GETTING_STARTED.md) - Setup and troubleshooting
- [Architecture Overview](docs/ARCHITECTURE.md) - Complete system architecture
- [File Upload Feature](docs/UPLOAD_FEATURE.md) - Upload threat intel files for TTP/IOC extraction
- [Emulation Guide](docs/EMULATION_GUIDE.md) - Adversary emulation and remote execution
- [Query Execution Guide](docs/QUERY_API_GUIDE.md) - MDE and Splunk API integration
- [VECTR Integration](docs/VECTR_INTEGRATION.md) - Hunt tracking and validation
- [Correlation Guide](docs/CORRELATION_GUIDE.md) - Correlation query builder

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