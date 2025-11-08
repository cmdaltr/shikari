<div align="center">
<a href="https://github.com/cmdaltr/archer">
<img src="static/images/archer_banner.png" alt="Archer - Automated Multi-Vendor Threat Hunting & Detection Framework" width="600px" height="600px">
</a>
</div>

<br>

Archer is a modular Python service for automated threat hunting with optional adversary emulation and hunt tracking integrations. Generate detection queries, validate with real attack execution, and track hunts with VECTR integration.

<br>

## ✨ Features

### Core Capabilities
- 🎯 **MITRE ATT&CK Integration** - Automated detection generation from threat group TTPs
- 📤 **File Upload & Intelligence Extraction** - Upload threat intel files (PDF, TXT, JSON, CSV, YARA) for automatic TTP/IOC extraction
- 🔍 **Multi-Platform Support** - KQL (Microsoft Defender/Sentinel) and Splunk (SPL) queries
- 🧠 **AI-Powered Correlations** - Semantic analysis and query correlation
- 🌐 **Web UI & CLI** - VirusTotal-inspired tabbed interface plus command-line tools

<details>
<summary><h3 style="display:inline">🤷🏼‍♀️ Optional Modules</h3></summary>

<br>

> Code Exists - ⚠️ Untested, unless stated

Can be enabled via environment variables:

- 💥 **Adversary Emulation** - Atomic Red Team integration for evidence-based detections ✅ **Tested**
  - 🖥️ **Remote Execution** - SSH/WinRM support for cross-platform testing (Linux, macOS, Windows)
  - 🔑 **SSH Key Authentication** - Secure passwordless authentication
  - 🔒 **WinRM HTTPS** - Encrypted Windows remote management (default)
  - Enable with: `ENABLE_EMULATION=true`
  - Code implemented but not validated with live Atomic Red Team deployment
- 🔍 **Query Execution** - Execute queries via MDE and Splunk APIs
  - 🌐 **MDE Advanced Hunting** - KQL query execution with OAuth2
  - 📊 **Splunk Search API** - SPL query execution with job management
  - Available in web UI Settings
  - Code implemented but not validated against live MDE/Splunk environments
~~- 🔗 **n8n Workflow Automation** - API endpoints for workflow integration~~
  ~~- All API endpoints accessible for n8n HTTP Request nodes~~
  ~~- Endpoints available but not validated with live n8n workflows~~

</details>

<details>
<summary><h3 style="display:inline">🔜 Coming Soon</h3></summary>

<br>

> ⚠️ Not Functional

- 📊 **VECTR Integration** - Hunt tracking and purple team collaboration
  - CLI framework stub exists but not yet functional
  - Requires VECTR instance integration and testing
- 💥 **CALDERA Integration** - Automated adversary emulation platform
  - Configuration exists but integration not implemented
  - Enable with: `CALDERA_API_URL` and `CALDERA_API_KEY`
- 💥 **MACAT Integration** - macOS adversary emulation framework
  - Configuration exists but integration not implemented
  - Enable with: `MACAT_PATH`

</details>

### Security & User Management
- 🔐 **Enterprise Authentication** - Bcrypt password hashing, session management, MFA support (TOTP)
- 🛡️ **Security Features** - Rate limiting, CSRF protection, account lockout, audit logging
- 👥 **Admin User Management** - Complete CRUD API for user accounts (create, read, update, deactivate)
- 📧 **Email Integration** - SMTP-based password reset with secure token delivery
- 🔑 **API Key Encryption** - Fernet encryption for stored SIEM/AI API credentials
- 📊 **Comprehensive Audit Logs** - Track all authentication events and admin actions
- 🔒 **Role-Based Access Control** - Admin and Standard user roles with granular permissions

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
git clone https://github.com/cmdaltr/archer.git
cd archer
```

---
<br>

## ⚠️ IMPORTANT: Configure Mapping Files

**Before generating detections**, you MUST configure mapping files for your environment!

Archer ships with **generic, example mapping files** that reference placeholder index names like `edr_events`, `windows_events`, etc. These will NOT work in your environment.

### Quick Setup

Run the interactive setup wizard:

```bash
python scripts/setup_mappings.py
```

This will guide you through configuring:
- ✅ Your actual index/source names (Splunk, Sentinel, etc.)
- ✅ Field name mappings for your log format
- ✅ Which data sources you have available

### Manual Setup

Alternatively, edit the mapping files directly:

```bash
# Copy example files
cp archer/mappings/schemaSplunk.json archer/mappings/schemaSplunk_custom.json
cp archer/mappings/schemaMDE.json archer/mappings/schemaMDE_custom.json

# Edit with your actual index names and field mappings
vim archer/mappings/schemaSplunk_custom.json
```

### Documentation

For detailed instructions, see: **[docs/MAPPING_SETUP_GUIDE.md](docs/MAPPING_SETUP_GUIDE.md)**

**Why This Matters:**
- ❌ Without proper mappings, generated queries will reference non-existent indices
- ❌ Field names won't match your log format
- ❌ Detections will return no results or false positives

✅ **Take 10 minutes now to configure mappings correctly!**

---
<br>

## 3️⃣ Setup Options

### Option A: Run with Docker (Recommended)

1. Build and start the service using Docker Compose:

```bash
docker-compose up --build
```

2. The FastAPI service will be available at `http://localhost:8000`.

3. **Access with default admin credentials**:

On first startup, a default admin account is automatically created:

```
Email: admin@archer.app
Password: £missary_0f_the_G0rg0nite$
```

> ⚠️ **SECURITY WARNING**: Change this password immediately after first login via Profile → Change Password

Alternatively, you can create a custom admin user:

```bash
python3 scripts/create_admin.py
```

You'll be prompted for:
- Email address
- Full name
- Password (with confirmation)

4. To stop the service, press `Ctrl+C` and then run:

```bash
docker-compose down
```

---
<br>

### Option B: Run Locally with Python

1. Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Start the FastAPI service:

```bash
uvicorn archer.app:app --reload
```

The service will be available at `http://localhost:8000`.

4. **Access with default admin credentials**:

On first startup, a default admin account is automatically created:

```
Email: admin@archer.app
Password: £missary_0f_the_G0rg0nite$
```

> ⚠️ **SECURITY WARNING**: Change this password immediately after first login via Profile → Change Password

Alternatively, you can create a custom admin user in a new terminal window:

```bash
source venv/bin/activate  # Activate the virtual environment
python3 scripts/create_admin.py
```

You'll be prompted for:
- Email address
- Full name
- Password (with confirmation)

> **Note**: The database (`data/archer.db`) is automatically created when you first start the application. No manual database setup is required.

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

# Test correlation parameters (adjust quality/coverage)
python scripts/test_correlation_params.py -t 40 -v 60 -f 20
```

#### Tuning Correlation Parameters

Archer's correlation engine has three tunable parameters that control quality vs coverage:

```bash
# Test different parameter combinations
python scripts/test_correlation_params.py \
  --threshold 40 \        # Minimum quality score (0-100%)
  --per-vendor 60 \       # Max correlations per vendor
  --tech-freq 20          # Max technique appearances

# Or use short options
python scripts/test_correlation_params.py -t 40 -v 60 -f 20
```

**Defaults:** threshold=40%, per-vendor=60, tech-freq=20

**Quick Presets:**
- **Small SOC:** `-t 50 -v 25 -f 15` (~20-30 high-quality correlations)
- **Standard:** `-t 40 -v 60 -f 20` (~40-60 balanced correlations) ⭐ **Default**
- **Large SOC:** `-t 40 -v 100 -f 30` (~80-110 comprehensive coverage)

See [Correlation Quick Reference](docs/CORRELATION_QUICK_REFERENCE.md) for detailed parameter explanations and test results.

Alternatively, adjust parameters via **Profile → Config** page in the web UI.
```

#### Adversary Emulation (Optional - Untested)

⚠️ **Status**: Code implemented but not validated with live Atomic Red Team deployment.

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

See [docs/guides/EMULATION_GUIDE.md](docs/guides/EMULATION_GUIDE.md) for detailed emulation documentation.


#### Query Execution (Optional - Untested)

⚠️ **Status**: Code implemented but not validated against live MDE/Splunk environments.

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

# Execute queries via web UI Settings → Query Execution
# CLI integration for query execution is planned for future release
```

See [docs/guides/QUERY_API_GUIDE.md](docs/guides/QUERY_API_GUIDE.md) for detailed query execution documentation.

#### Complete Workflow Example

```bash
# 1. Generate detections
python3 archer.py generate "APT29"

# 2. Run emulation and enrich (local or remote)
python3 archer.py emulate "APT29" --enrich --max-techniques 10

# 3. Build correlations
python3 archer.py correlate "APT29"

# 4. Execute queries via web UI (Settings → Query Execution)
#    Results can be exported and analyzed
```

---
<br>

~~## ⚙️ Using Archer with n8n (Untested)~~

~~⚠️ **Status**: API endpoints available but not validated with live n8n workflows.~~

~~Archer provides API endpoints that can be integrated with [n8n](https://n8n.io/) for workflow automation.~~

~~### Example: Trigger Archer Hunt via HTTP Request Node~~

~~1. Add an HTTP Request node in n8n.~~

~~2. Configure it to make a POST request to Archer's endpoint:~~

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

~~3. The response will contain the hunt queries in YAML format, which can be parsed and used in subsequent workflow nodes.~~

---
<br>

~~### Tips for n8n Integration~~

~~- Use the **Function** node to parse YAML responses into JSON for easier manipulation.~~

~~- Chain multiple Archer calls to build complex threat hunting workflows.~~

~~- Combine Archer outputs with enrichment services (e.g., VirusTotal, MISP) within n8n.~~

---
<br>

## 📚 Documentation & Resources

### Archer Documentation

**📖 [Complete Documentation Index](docs/DOCS.md)** - Browse all documentation by category

**Quick Links:**
- **Getting Started:** [Setup Guide](docs/guides/GETTING_STARTED.md) | [Mapping Setup](docs/guides/MAPPING_SETUP_GUIDE.md)
- **API Integration:** [API Documentation](docs/reference/API_DOCUMENTATION.md) | [API Reference](docs/reference/API_REFERENCE.md)
- **Correlation Tuning:** [Quick Reference](docs/reference/CORRELATION_QUICK_REFERENCE.md) ⚙️ (threshold, per-vendor, tech frequency)
- **Features:** [Security](docs/features/SECURITY_FEATURES.md) | [AI Training](docs/features/AI_TRAINING.md) | [OSINT](docs/features/OSINT_INTEGRATION.md)
- **Architecture:** [Correlation Engine](docs/architecture/CORRELATION_ENGINE.md) | [Performance](docs/architecture/PERFORMANCE_ARCHITECTURE.md)

### External Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [VECTR](https://vectr.io/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
~~- [n8n Workflow Automation](https://n8n.io/)~~

---
<br>

## 🤝 Contributing

Feel free to open issues or submit pull requests to improve Archer.

---
<br>

## 📝 License

This project is licensed under the MIT License. See the LICENSE file for details.