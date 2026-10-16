# Untested Features

This document describes features that have been implemented in Archer but have not been validated with live deployments or production environments.

> ⚠️ **Status**: Code exists but not validated with live deployments

These features may work as intended but require testing and validation before being considered production-ready. Use at your own risk and please report any issues or successes to help validate these features.

---

## Lab recording (Coming soon)

**Status**: Code written and unit-tested, not yet run on a real lab

`scripts/telemetry/record-atomics.ps1` runs Atomic Red Team tests on a Windows, Linux or macOS test machine and saves each test's logs (Windows event logs; auditd and the journal; eslogger, the unified log and launch item plist changes on macOS). `python -m archer.telemetry --mde-export` fetches each test's Defender for Endpoint rows through Microsoft Graph's Advanced Hunting. Runs copied into `data/telemetry/lab/` appear on the Emulate page as **Your lab**.

Setup, step by step: [Recording a lab](../guide/20-recording-a-lab.md).

### Known limitations

- The script parses in PowerShell 7 and its macOS plist functions were exercised; no atomic has been run with it
- `--mde-export` matches devices by the manifest's host name (`DeviceName startswith`), and takes up to 5,000 rows per table per test
- Running atomics from Archer itself (`archer.py emulate`, the console's `emulate`, **Run Emulation** on Results) depended on an `archer.emulation` package that has been removed; those entry points say Coming soon

## Query Execution

**Status**: Code implemented but not validated against live MDE/Splunk environments

> `archer/query/mde.py` uses the MDE Advanced Hunting API (`api.securitycenter.microsoft.com`), which Microsoft is retiring in favour of Microsoft Graph's `runHuntingQuery`. Before validating it, move it to Graph as `archer/telemetry/mde.py` already does (application permission `ThreatHunting.Read.All`).

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

Or configure via Web UI: **Profile → API Keys → SIEM Platforms**

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

**📚 [API Integration Guide](../features/API_INTEGRATION_GUIDE.md)** - API integration documentation

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

**Lab recording**:
- [ ] `record-atomics.ps1` on Windows (events.xml), Ubuntu (audit.log, journal.log) and macOS (es.ndjson, unified.ndjson, plists.ndjson)
- [ ] `--mde-export` against a Defender for Endpoint trial tenant
- [ ] A run appearing as Your lab, and a group's detections checked against it

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
**Feature**: Lab recording
**Environment**: Ubuntu 24.04, auditd with Neo23x0's rules, PowerShell 7.5
**Status**: ✅ Working
**Notes**: 10 techniques recorded; audit.log and journal.log in every test folder.
**Fixes Applied**: None
```

---

## Migration to Tested Features

Once a feature is validated by the community:
1. The feature will be documented as production-ready
2. This documentation will be moved to the main feature docs
3. The feature will be removed from this UNTESTED.md file
4. Known issues and workarounds will be documented

---

**Last Updated**: 2026-10-16
