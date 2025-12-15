# Untested Features

This document describes features that have been implemented in Archer but have not been validated with live deployments or production environments.

> ⚠️ **Status**: Code exists but not validated with live deployments

These features may work as intended but require testing and validation before being considered production-ready. Use at your own risk and please report any issues or successes to help validate these features.

---

## Adversary Emulation

**Status**: ✅ Tested locally but not validated with live Atomic Red Team deployment

### Overview

Atomic Red Team integration for evidence-based detection enrichment. Execute adversary techniques locally or remotely and use the generated evidence to enhance detection queries.

### Capabilities

- 💥 **Atomic Red Team Integration** - Execute atomic tests for MITRE ATT&CK techniques
- 🖥️ **Remote Execution** - SSH/WinRM support for cross-platform testing (Linux, macOS, Windows)
- 🔑 **SSH Key Authentication** - Secure passwordless authentication
- 🔒 **WinRM HTTPS** - Encrypted Windows remote management (default)
- 📊 **Evidence-Based Enrichment** - Enhance detections with real execution artifacts

### Configuration

Enable with environment variable:
```bash
ENABLE_EMULATION=true
```

### Prerequisites

- **Atomic Red Team** - Clone the repository locally
- **SSH Access** - For Linux/macOS remote execution
- **WinRM Access** - For Windows remote execution
- **Lab Environment** - Never run live execution in production!

### Basic Usage

```bash
# Emulate specific technique locally (safe simulation)
python3 archer.py emulate T1059.001 --enrich

# Emulate entire threat group locally
python3 archer.py emulate "APT29" --enrich --max-techniques 10

# Live execution locally (LAB ONLY!)
python3 archer.py emulate T1059.001 --execute --enrich
```

### Remote Execution

**SSH (Linux/macOS)**:
```bash
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.100 \
  --remote-user admin \
  --ssh-key ~/.ssh/id_rsa \
  --enrich
```

**WinRM (Windows) - HTTPS**:
```bash
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.101 \
  --remote-user Administrator \
  --remote-password 'P@ssw0rd' \
  --remote-platform windows \
  --enrich
```

**WinRM (Windows) - HTTP (lab only)**:
```bash
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.101 \
  --remote-user Administrator \
  --remote-password 'P@ssw0rd' \
  --remote-platform windows \
  --http \
  --enrich
```

### Complete Workflow

```bash
# 1. Generate detections
python3 archer.py generate "APT29"

# 2. Run emulation and enrich (local or remote)
python3 archer.py emulate "APT29" --enrich --max-techniques 10

# 3. Build correlations
python3 archer.py correlate "APT29"

# 4. Review enriched detections with real execution evidence
```

### Documentation

**📚 [Complete Emulation Guide](guides/EMULATION_GUIDE.md)** - Detailed documentation with advanced workflows

### Known Limitations

- Not validated with full Atomic Red Team installation
- Remote execution relies on external SSH/WinRM connectivity
- Evidence collection depends on log visibility
- May require environment-specific tuning

---

## Query Execution

**Status**: Code implemented but not validated against live MDE/Splunk environments

### Overview

Execute generated detection queries directly against your SIEM platform via API. Validate detection quality and tune queries based on real results.

### Capabilities

- 🌐 **MDE Advanced Hunting** - KQL query execution with OAuth2 authentication
- 📊 **Splunk Search API** - SPL query execution with job management
- 🔒 **Secure Authentication** - OAuth2 for MDE, token-based for Splunk
- 📈 **Result Analysis** - View query results and tune detections

### Configuration

#### Microsoft Defender (MDE)

Set up credentials via environment variables:
```bash
export MDE_TENANT_ID=your-tenant-id
export MDE_CLIENT_ID=your-client-id
export MDE_CLIENT_SECRET=your-client-secret
```

Or configure via Web UI: **Settings → Query Execution → MDE Configuration**

#### Splunk

Set up credentials via environment variables:
```bash
export SPLUNK_HOST=splunk.example.com
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD=your-password
```

Or configure via Web UI: **Settings → Query Execution → Splunk Configuration**

### Prerequisites

- **MDE**: Azure AD app registration with SecurityEvents.Read.All permission
- **Splunk**: Splunk Enterprise/Cloud instance with API access
- **API Credentials**: Valid authentication credentials
- **Network Access**: Connectivity to SIEM APIs

### Usage

**Web UI** (Recommended):
1. Navigate to **Settings → Query Execution**
2. Configure API credentials
3. Select generated detection to test
4. Click **Execute Query**
5. Review results and tune query

**CLI**:
```bash
# CLI integration for query execution is planned for future release
# Currently available via web UI only
```

### Authentication

**MDE OAuth2 Flow**:
1. Register Azure AD application
2. Grant SecurityEvents.Read.All permission
3. Generate client secret
4. Configure credentials in Archer

**Splunk Token Authentication**:
1. Create Splunk user with search permissions
2. Generate authentication token (or use username/password)
3. Configure credentials in Archer

### Documentation

**📚 [Complete Query API Guide](guides/QUERY_API_GUIDE.md)** - Detailed API integration documentation

### Known Limitations

- Not validated against live MDE/Splunk deployments
- API rate limits not fully tested
- Large result sets may require pagination tuning
- Error handling may need environment-specific adjustments

---

## Testing & Validation

If you test any of these features, please help the community by:

1. **Opening an issue** with your results: [GitHub Issues](https://github.com/cmdaltr/archer/issues)
2. **Sharing configurations** that worked in your environment
3. **Reporting bugs** or unexpected behavior
4. **Contributing fixes** via pull requests

### What to Test

**Adversary Emulation**:
- [ ] Local Atomic Red Team execution
- [ ] Remote SSH execution (Linux/macOS)
- [ ] Remote WinRM execution (Windows)
- [ ] Evidence-based enrichment quality
- [ ] Detection accuracy after enrichment

**Query Execution**:
- [ ] MDE OAuth2 authentication
- [ ] MDE query execution and results
- [ ] Splunk token authentication
- [ ] Splunk query execution and results
- [ ] API error handling
- [ ] Rate limiting behavior

### Validation Checklist

When testing, please document:
- ✅ Environment (OS, SIEM platform, versions)
- ✅ Configuration used
- ✅ What worked
- ✅ What didn't work
- ✅ Any errors encountered
- ✅ Suggested improvements

---

## Contributing Validation Results

Your validation helps make these features production-ready!

**To contribute**:
1. Test a feature following the documentation
2. Document your setup, results, and any issues
3. Open a GitHub issue with the tag `validation-result`
4. Include environment details and configuration
5. Share any fixes or improvements you made

**Example validation report**:
```markdown
**Feature**: Adversary Emulation
**Environment**: Ubuntu 22.04, Atomic Red Team v3.0
**Status**: ✅ Working
**Notes**: Local execution works perfectly. Remote SSH needed minor SSH config changes.
**Fixes Applied**: Added SSH connection timeout handling
```

---

## Migration to Tested Features

Once a feature is validated by the community:
1. The feature will be documented as production-ready
2. This documentation will be moved to the main feature docs
3. The feature will be removed from this UNTESTED.md file
4. Known issues and workarounds will be documented

---

**Last Updated**: 2024-11-14
