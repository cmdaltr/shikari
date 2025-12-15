# Getting Started with Archer

Complete guide to installing, configuring, and using Archer for automated threat detection generation.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Initial Configuration](#initial-configuration)
4. [First Steps](#first-steps)
5. [Usage](#usage)
6. [Additional Information](#additional-information)

---

## 🚀 Quick Start

### 1. Prerequisites

**Git** (Required for all installations)
- [Windows](https://git-scm.com/download/win) - Git for Windows
- [macOS](https://git-scm.com/download/mac) - Install via Homebrew: `brew install git` or Xcode Command Line Tools
- [Linux](https://git-scm.com/download/linux) - Install via package manager: `apt install git` (Ubuntu/Debian) or `yum install git` (RHEL/CentOS)

---

**Option A: Docker (Recommended)**
- **Docker Desktop** (includes Docker Compose)
  - [Windows](https://docs.docker.com/desktop/install/windows-install/) - Requires WSL2
  - [macOS](https://docs.docker.com/desktop/install/mac-install/) - Intel or Apple Silicon
  - [Linux](https://docs.docker.com/desktop/install/linux-install/) - Ubuntu, Debian, Fedora, Arch

**Option B: Local Python**
- **Python 3.11+** - [Download](https://www.python.org/downloads/)

---

### 2. Installation

```bash
# Clone the repository
git clone https://github.com/cmdaltr/archer.git
cd archer
```

---

**Option A: Docker (Recommended)**
``` bash
# Start with Docker (recommended)
docker-compose up --build
```

**Option B: Local Python**
``` bash
# Start locally
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn archer.app:app --reload
```

### 3. Access
The service will be available at `http://localhost:8000`.

#### Default Login

> ⚠️ **Change this password immediately** after first login!
```
Email: admin@archer.app
Password: £missary_0f_the_G0rg0nite$
```

### 4. Configure

Before generating detections, configure mapping files for your SIEM environment:

```bash
python scripts/validation/setup_mappings.py
```

This configures your actual index names and field mappings so generated queries work in your environment.

## Additional Steps

### Leveraging AI
- **OpenAI API Key** - For AI-enhanced TTP extraction
- **Anthropic API Key** - For Claude-based extraction

### Adversary Emulation
- **Atomic Red Team** - For adversary emulation module
- **SSH/WinRM Access** - For remote emulation testing
- **MDE or Splunk API Credentials** - For query execution

(see [docs/UNTESTED.md](docs/UNTESTED.md))

---

## Managing Archer

**Option A: Docker (Recommended)**

* **Pros**: Isolated environment, easy deployment, consistent across platforms
  * Data is stored in Docker volumes and persists across restarts
* **Cons**: Requires Docker

``` bash
# Starting Archer
docker-compose up --build

# Stoping Archer
docker-compose down
```

**Option B: Local Python**

* **Pros**: Direct access to code, easier debugging
* **Cons**: Requires Python 3.11+, manual dependency management

``` bash
# Start locally
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn archer.app:app --reload
```


## Initial Configuration

### Step 1: Access Archer

Open your browser and navigate to: `http://localhost:8000`

### Step 2: Login with Default Admin Account

> ⚠️ **SECURITY WARNING**: Change this password immediately!
```
Email: admin@archer.app
Password: £missary_0f_the_G0rg0nite$
```

**To change password**:
1. Login with default credentials
2. Go to **Profile** → **Change Password**
3. Enter new strong password

### Step 3: Create Additional Admin Users (Optional)

```bash
# Docker installation
docker-compose exec archer python scripts/admin/create_admin.py

# Local installation
python scripts/admin/create_admin.py
```

You'll be prompted for:
- Email address
- Full name
- Password (with confirmation)

### Step 4: Configure Mapping Files (CRITICAL!)

**⚠️ IMPORTANT**: Archer ships with placeholder mapping files that **will not work** in your environment!

Mapping files tell Archer:
- Your actual index/source names (e.g., `windows_security` instead of `windows_events`)
- Field name mappings for your log format
- Which data sources you have available

#### Quick Setup (Recommended)

Run the interactive setup wizard:

```bash
# Docker installation
docker-compose exec archer python scripts/validation/setup_mappings.py

# Local installation
python scripts/validation/setup_mappings.py
```

This wizard will guide you through:
1. Selecting your SIEM platform (Splunk, Microsoft Defender, etc.)
2. Entering your actual index/source names
3. Mapping field names to your log format
4. Validating the configuration

#### Manual Setup

```bash
# Copy example files
cp archer/mappings/schemaSplunk.json archer/mappings/schemaSplunk_custom.json
cp archer/mappings/schemaMDE.json archer/mappings/schemaMDE_custom.json

# Edit with your actual values
vim archer/mappings/schemaSplunk_custom.json
```

**Example Splunk Mapping**:
```json
{
  "index": "windows_security",  // YOUR actual index name
  "source": "WinEventLog:Security",
  "fields": {
    "EventCode": "EventCode",    // YOUR field names
    "Computer": "host",
    "User": "user"
  }
}
```

#### Why This Matters

❌ **Without proper mappings**:
- Generated queries reference non-existent indices
- Field names don't match your log format
- Detections return no results or false positives

✅ **With proper mappings**:
- Queries work immediately in your environment
- Field names match your logs
- Detections are production-ready

**📚 Detailed Documentation**: [docs/guides/MAPPING_SETUP_GUIDE.md](docs/guides/MAPPING_SETUP_GUIDE.md)

---

## Suggested First Steps

### 1. Explore the Dashboard

After logging in, you'll see the main dashboard with:
- **Home** - Overview and quick actions
- **Generate** - Create detections for threat groups
- **Upload** - Analyze threat reports
- **Profile** - Company threat profiling
- **Library** - Manage your detections
- **Settings** - Configure API keys and preferences

### 2. Generate Your First Detections

Archer offers three methods to generate detections:

1. **Threat Group Detection** - Generate detections based on threat actor TTPs
2. **CVE-Based Detection** - Generate detections for specific vulnerabilities
3. **Threat Report Upload** - Extract TTPs from uploaded threat intelligence files

**📚 [Complete Generation Guide](docs/USAGE.md#generate-detections)** - Detailed steps for each method

**Quick Start**:
- Navigate to **Generate** tab
- Enter threat group name (e.g., "APT29") or CVE ID (e.g., "CVE-2021-44228")
- Configure options (OSINT Enhancement, Correlation)
- Click **Generate Detections**
- Download results as ZIP file

### 3. Review Generated Detections

Your detection package includes:
- **Individual detection YAML files** - Platform-specific queries (Splunk, MDE, Elastic)
- **Multi-stage attack correlations** - Related detections for complex attack chains
- **MITRE ATT&CK Flow visualizations** - Visual representation of threat coverage

**📚 [Detection Package Structure](docs/USAGE.md#for-threat-groups)** - Complete file structure and contents

### 4. Import Detections to Your SIEM

**Splunk** (SPL Queries):
```bash
# Extract YAML files
unzip APT29.zip

# Convert YAML to Splunk alerts
# (Manual: Copy queries from YAML files to Splunk Alert creation)
```

**Microsoft Defender** (KQL Queries):
```bash
# Extract YAML files
unzip APT29.zip

# Import to Microsoft 365 Defender Custom Detections
# (Manual: Copy queries from YAML files to Custom Detection rules)
```

**Elastic** (EQL Queries):
```bash
# Extract YAML files
unzip APT29.zip

# Import to Elastic Detection Rules
# (Manual: Copy queries from YAML files to Detection engine)
```

---

## Usage

Archer provides three ways to generate and manage threat detections:

- **Web Interface** - VirusTotal-inspired tabbed interface at `http://localhost:8000`
- **Command Line Interface (CLI)** - Console scripts for automation
- **REST API** - Programmatic access for workflow integration

**📚 [Complete Usage Guide](docs/USAGE.md)** - Detailed documentation for Web UI, CLI, and API

### Quick Usage Examples

**Web UI**:
1. Navigate to **Generate** tab
2. Enter threat group name (e.g., "APT29")
3. Configure options (OSINT, Correlation)
4. Click **Generate Detections**
5. Download ZIP when complete

**CLI**:
```bash
# Generate detections
python archer.py generate "APT29" --correlate

# Hunt for technique
python archer.py hunt "PowerShell"
```

**API**:
```python
import requests

session = requests.Session()
session.post('http://localhost:8000/login', data={'email': 'user@example.com', 'password': 'password'})
session.post('http://localhost:8000/generate', data={'group_name': 'APT29'})
```

For complete workflows, parameter tuning, and troubleshooting, see **[docs/USAGE.md](docs/USAGE.md)**

---

## Additional Information

### Documentation

**📖 [Complete Documentation Index](docs/DOCS.md)** - Browse all documentation by category

**Quick Links by Use Case**:

**For SOC Analysts**:
- [Getting Started Guide](docs/guides/GETTING_STARTED.md) - Basic setup
- [Correlation Guide](docs/guides/CORRELATION_GUIDE.md) - Using the correlation builder
- [CVE Hunting Guide](docs/guides/CVE_HUNTING_GUIDE.md) - CVE-based detection

**For Security Engineers**:
- [Correlation Quick Reference](docs/architecture/CORRELATION_QUICK_REFERENCE.md) - Tune correlation parameters
- [Detection Validation](docs/features/DETECTION_VALIDATION.md) - Validate detection quality
- [Testing Guide](docs/guides/TESTING_GUIDE.md) - Testing workflows

**For Platform Administrators**:
- [Mapping Setup Guide](docs/guides/MAPPING_SETUP_GUIDE.md) - Configure for your environment
- [API Integration Guide](docs/guides/API_INTEGRATION_GUIDE.md) - REST API integration
- [Security Features](docs/features/SECURITY_FEATURES.md) - User management and security

**For Developers**:
- [Correlation Engine](docs/architecture/CORRELATION_ENGINE.md) - Engine internals
- [Performance Architecture](docs/architecture/PERFORMANCE_ARCHITECTURE.md) - System design
- [Schema Normalization](docs/architecture/SCHEMA_NORMALIZATION.md) - Field mapping
- [API Integration Guide](docs/guides/API_INTEGRATION_GUIDE.md) - REST API workflows

### Scripts & Utilities

**Data Collection**:
```bash
# Collect CVE training data
python scripts/train_ai.py cve --year 2024

# Convert threat reports to training data
python scripts/train_ai.py reports --dir reports/

# Extract OSINT detection samples
python scripts/train_ai.py osint --all
```

**User Management**:
```bash
# Create admin user
python scripts/admin/create_admin.py

# Reset user password
python scripts/reset_password.py
```

**Schema Validation**:
```bash
# Verify YAML schema compliance
python scripts/verify_schema.py

# Analyze schema field usage
python scripts/analyze_schema_fields.py
```

**OSINT Updates**:
```bash
# Update OSINT repositories
python scripts/update_osint.py
```

**📚 Complete Scripts Reference**: [docs/SCRIPTS.md](docs/SCRIPTS.md)

### Additional Features

Archer includes additional features that are implemented but not yet validated with live deployments:

- **Adversary Emulation** - Atomic Red Team integration with remote execution
- **Query Execution** - MDE and Splunk API integration
- **Future Integrations** - VECTR, CALDERA, MACAT

📚 **[UNTESTED.md](docs/UNTESTED.md)** - Complete documentation for implemented but untested features
📚 **[FUTURE.md](docs/FUTURE.md)** - Roadmap and planned features

### Troubleshooting

**Issue: Cannot login with default credentials**

**Solution**:
```bash
# Reset admin password
python scripts/reset_password.py

# Or create new admin
python scripts/admin/create_admin.py
```

**Issue: Generated queries don't work in my SIEM**

**Solution**: Configure mapping files!
```bash
python scripts/validation/setup_mappings.py
```
See [docs/guides/MAPPING_SETUP_GUIDE.md](docs/guides/MAPPING_SETUP_GUIDE.md)

**Issue: Docker container won't start**

**Solution**:
```bash
# Check Docker logs
docker-compose logs archer

# Rebuild from scratch
docker-compose down -v
docker-compose up --build
```

**Issue: Port 8000 already in use**

**Solution**:
```bash
# Find process using port 8000
lsof -i :8000  # macOS/Linux
netstat -ano | findstr :8000  # Windows

# Kill the process or change Archer's port
# Edit docker-compose.yml: "8001:8000"
```

---

**Need Help?** Check the [documentation index](docs/DOCS.md) or open an [issue](https://github.com/cmdaltr/archer/issues).
