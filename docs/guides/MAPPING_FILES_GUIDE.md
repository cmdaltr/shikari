# Mapping Files Configuration Guide

This guide explains how to configure Archer's mapping files to customize detection generation for your specific environment, data sources, and security platforms.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Mapping Files Explained](#mapping-files-explained)
3. [Indicator Mapping Configuration](#indicator-mapping-configuration)
4. [Platform Mapping Configuration](#platform-mapping-configuration)
5. [Field Mapping Configuration](#field-mapping-configuration)
6. [Common Customization Scenarios](#common-customization-scenarios)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Overview

Archer uses three key mapping files to translate threat intelligence into platform-specific detection queries:

| Mapping File | Purpose | Location |
|--------------|---------|----------|
| `indicatorMapping.json` | Maps indicator types to data sources and fields | `archer/mappings/` |
| `platformMapping.json` | Defines platform compatibility for log sources | `archer/mappings/` |
| `fieldMapping.json` | Maps generic field names to vendor-specific fields | `archer/mappings/` |

These files determine **which detections are generated** and **how queries are constructed** for your environment.

---

## Mapping Files Explained

### Why Customize Mapping Files?

Out of the box, Archer supports common enterprise configurations for:
- **Microsoft Defender for Endpoint (MDE)**
- **Splunk Enterprise Security**
- **Elastic Security**

You should customize mapping files if:
- ✅ You use custom log sources or data models
- ✅ Your field names differ from standard schemas
- ✅ You have platform-specific data sources (AWS, GCP, Azure)
- ✅ You want to enable/disable certain detection types
- ✅ You need to support additional security platforms

---

## Indicator Mapping Configuration

**File**: `archer/mappings/indicatorMapping.json`

This file maps **indicator types** extracted from MITRE ATT&CK procedures to **data sources** and **field names**.

### Structure

```json
{
  "indicator_type": {
    "MDE": {
      "TableName": ["FieldName1", "FieldName2"]
    },
    "Splunk": ["index=source_type"],
    "Elastic": ["index_pattern"]
  }
}
```

### Example: Command-Line Indicators

```json
{
  "cmd": {
    "MDE": {
      "DeviceProcessEvents": [
        "ProcessCommandLine",
        "InitiatingProcessCommandLine"
      ],
      "DeviceFileEvents": [
        "InitiatingProcessCommandLine"
      ],
      "DeviceEvents": [
        "AdditionalFields"
      ]
    },
    "Splunk": [
      "index=windows_events",
      "index=edr_events"
    ]
  }
}
```

### Supported Indicator Types

| Type | Description | Examples |
|------|-------------|----------|
| `cmd` | Command-line arguments | `powershell.exe -enc`, `mimikatz` |
| `file` | File names and paths | `evil.dll`, `C:\temp\payload.exe` |
| `ip` | IP addresses | `192.168.1.100`, `10.0.0.5` |
| `domain` | Domain names | `malicious.com`, `c2.evil.net` |
| `hash` | File hashes (MD5, SHA1, SHA256) | `d41d8cd98f00b204...` |
| `process` | Process names | `rundll32.exe`, `cmd.exe` |
| `registry` | Registry keys/values | `HKLM\SOFTWARE\...` |
| `user` | Usernames | `administrator`, `SYSTEM` |
| `service` | Service names | `bits`, `wuauserv` |
| `port` | Network ports | `443`, `8080` |
| `url` | URLs | `http://malicious.com/payload` |
| `email` | Email addresses | `attacker@evil.com` |
| `operation` | Operation names (Sentinel) | `Write`, `Delete`, `Create` |

### Adding a New Indicator Type

To support a new indicator type (e.g., `certificate`):

```json
{
  "certificate": {
    "MDE": {
      "DeviceNetworkEvents": ["RemoteCertificate"]
    },
    "Splunk": [
      "index=network"
    ],
    "Elastic": [
      "logs-network-*"
    ]
  }
}
```

### Platform-Specific Customization

**Example**: Adding AWS CloudTrail support for IP indicators

```json
{
  "ip": {
    "MDE": {
      "DeviceNetworkEvents": ["RemoteIP", "LocalIP"]
    },
    "Splunk": [
      "index=aws_cloudtrail sourcetype=aws:cloudtrail"
    ],
    "Elastic": [
      "logs-aws.cloudtrail-*"
    ]
  }
}
```

---

## Platform Mapping Configuration

**File**: `archer/mappings/platformMapping.json`

This file defines which **operating systems and cloud platforms** are supported by each **data source**.

### Structure

```json
{
  "data_source_name": ["platform1", "platform2", "platform3"]
}
```

### Example: Windows and macOS Process Monitoring

```json
{
  "DeviceProcessEvents": ["windows", "macos", "linux"],
  "windows_events": ["windows"],
  "macos_logs": ["macos"],
  "edr_events": ["windows", "macos", "linux"]
}
```

### Common Platform Values

| Platform | Use Case |
|----------|----------|
| `windows` | Windows endpoints (Defender, Sysmon, Event Logs) |
| `macos` | macOS endpoints |
| `linux` | Linux servers and endpoints |
| `aws` | AWS CloudTrail, GuardDuty, VPC Flow Logs |
| `azure` | Azure Activity Logs, Azure AD |
| `gcp` | Google Cloud Platform logs |
| `office365` | Microsoft 365 audit logs |
| `saas` | Generic SaaS applications |
| `network` | Network devices (firewalls, IDS/IPS) |
| `containers` | Docker, Kubernetes |

### Adding Cloud Platform Support

**Example**: Enable Azure AD monitoring

```json
{
  "azure_signin": ["azure", "saas"],
  "AADSignInEventsBeta": ["azure", "office365"]
}
```

---

## Field Mapping Configuration

**File**: `archer/mappings/fieldMapping.json`

This file maps **generic field names** to **vendor-specific field names** across different security platforms.

### Structure

```json
{
  "generic_field": {
    "vendor": "vendor_specific_field"
  }
}
```

### Example: Process Name Mapping

```json
{
  "process_name": {
    "mde": "ProcessName",
    "splunk": "process_name",
    "elastic": "process.name",
    "sentinel": "ProcessName"
  }
}
```

### Common Field Mappings

| Generic Field | MDE | Splunk | Elastic | Sentinel |
|---------------|-----|--------|---------|----------|
| `process_name` | `ProcessName` | `process_name` | `process.name` | `ProcessName` |
| `command_line` | `ProcessCommandLine` | `process` | `process.command_line` | `CommandLine` |
| `user` | `AccountName` | `user` | `user.name` | `AccountName` |
| `src_ip` | `RemoteIP` | `src_ip` | `source.ip` | `SourceIP` |
| `dest_ip` | `LocalIP` | `dest_ip` | `destination.ip` | `DestinationIP` |
| `file_name` | `FileName` | `file_name` | `file.name` | `FileName` |
| `file_path` | `FolderPath` | `file_path` | `file.path` | `FolderPath` |

### Adding Custom Data Model Support

**Example**: Adding CIM (Common Information Model) for Splunk

```json
{
  "process_name": {
    "mde": "ProcessName",
    "splunk": "process",
    "splunk_cim": "Processes.process_name",
    "elastic": "process.name"
  }
}
```

---

## Common Customization Scenarios

### Scenario 1: Custom Splunk Indexes

**Problem**: Your organization uses different index names than the defaults.

**Solution**: Update `indicatorMapping.json`

```json
{
  "cmd": {
    "Splunk": [
      "index=custom_windows_logs",
      "index=custom_edr_logs"
    ]
  }
}
```

### Scenario 2: Multi-Cloud Environment

**Problem**: You need detections for AWS, Azure, and GCP.

**Solution**: Update both `indicatorMapping.json` and `platformMapping.json`

**indicatorMapping.json**:
```json
{
  "ip": {
    "Splunk": [
      "index=aws_cloudtrail",
      "index=azure_activity",
      "index=gcp_logs"
    ]
  }
}
```

**platformMapping.json**:
```json
{
  "aws_cloudtrail": ["aws"],
  "azure_activity": ["azure"],
  "gcp_logs": ["gcp"]
}
```

### Scenario 3: Custom EDR Solution

**Problem**: You use CrowdStrike, Carbon Black, or another EDR.

**Solution**: Add new vendor mappings

**indicatorMapping.json**:
```json
{
  "cmd": {
    "CrowdStrike": {
      "ProcessRollup2": ["CommandLine", "ParentCommandLine"]
    }
  }
}
```

**fieldMapping.json**:
```json
{
  "command_line": {
    "mde": "ProcessCommandLine",
    "crowdstrike": "CommandLine"
  }
}
```

### Scenario 4: Disabling Certain Data Sources

**Problem**: You don't have certain log sources and want to prevent empty detections.

**Solution**: Remove or comment out unused sources in `indicatorMapping.json`

```json
{
  "cmd": {
    "MDE": {
      "DeviceProcessEvents": ["ProcessCommandLine"]
      // "DeviceFileEvents": ["InitiatingProcessCommandLine"]  // Disabled
    }
  }
}
```

### Scenario 5: Adding Network Detection Support

**Problem**: You want to generate network-based detections for firewall logs.

**Solution**: Add network indicator mappings

```json
{
  "ip": {
    "Splunk": [
      "index=firewall sourcetype=paloalto:firewall"
    ]
  },
  "port": {
    "Splunk": [
      "index=firewall"
    ]
  }
}
```

---

## Best Practices

### 1. **Backup Before Modifying**

Always create backups of mapping files before making changes:

```bash
cp archer/mappings/indicatorMapping.json archer/mappings/indicatorMapping.json.backup
```

### 2. **Validate JSON Syntax**

Use a JSON validator to ensure your changes are syntactically correct:

```bash
python -m json.tool archer/mappings/indicatorMapping.json
```

### 3. **Test with Small Groups First**

After modifying mappings, test with a small threat group:

```bash
curl -X POST "http://127.0.0.1:8000/generate/group" \
  -d "group_name=APT1&osint_comparison=false"
```

### 4. **Document Your Changes**

Keep a changelog of mapping customizations:

```markdown
# Mapping Customizations

## 2025-10-30
- Added AWS CloudTrail support for IP indicators
- Disabled DeviceFileEvents (not available in our environment)
- Changed Splunk index from `windows_events` to `edr_windows`
```

### 5. **Version Control**

Track mapping files in version control to enable rollback:

```bash
git add archer/mappings/
git commit -m "Custom mapping for AWS CloudTrail support"
```

### 6. **Start with Defaults**

Don't remove default mappings unless you're certain. Instead, add your custom sources alongside defaults:

```json
{
  "cmd": {
    "Splunk": [
      "index=windows_events",      // Default
      "index=custom_edr"         // Your addition
    ]
  }
}
```

---

## Troubleshooting

### Issue: No Detections Generated

**Symptoms**: Archer processes a group but creates no YAML files.

**Causes**:
1. Indicator type not mapped to any data source
2. Platform incompatibility (e.g., Linux technique with Windows-only data sources)
3. No indicators extracted from MITRE procedures

**Solutions**:
- Check console output for "⚠️ Skipping" messages
- Verify indicator types exist in `indicatorMapping.json`
- Review platform compatibility in `platformMapping.json`
- Enable debug logging to see indicator extraction:

```bash
ARCHER_DEBUG=1 .venv/bin/uvicorn archer.app:app --reload
```

### Issue: Queries Look Wrong

**Symptoms**: Generated queries have incorrect field names or syntax.

**Causes**:
1. Field mapping doesn't match your data source schema
2. Typo in field names
3. Data source doesn't support certain fields

**Solutions**:
- Review generated YAML files in `data/generate/`
- Verify field names match your actual data:

```kql
// MDE
DeviceProcessEvents
| getschema

// Splunk
index=windows_events | head 1 | fields *
```

- Update `fieldMapping.json` with correct field names

### Issue: Platform-Specific Detections Not Generated

**Symptoms**: Missing detections for AWS/Azure/Linux techniques.

**Causes**:
1. Platform not mapped in `platformMapping.json`
2. Indicator types not mapped for that platform
3. Platform validation rejecting the detection

**Solutions**:
- Add platform to `platformMapping.json`
- Map indicator types to platform-specific data sources
- Check `archer/build/platform_validator_v2.py` for platform rules

### Issue: Too Many or Too Few Detections

**Symptoms**: Archer generates more/fewer detections than expected.

**Causes**:
1. Too many data sources mapped (generates duplicate detections)
2. Too few indicator types mapped (misses valid detections)

**Solutions**:
- Review indicator-to-source mappings for duplicates
- Add missing indicator types for your environment
- Use platform mapping to control which sources are used

---

## Advanced Configuration

### Custom Query Templates

Archer uses query templates in `archer/mappings/template.yaml`. You can customize:

- YAML structure and metadata
- Default severity levels
- Custom tags and categories

**Example**: Adding custom metadata

```yaml
# archer/mappings/template.yaml
name: §name§
id: §id§
technique: §tid§
# Add custom fields
environment: production
severity_override: §severity§
compliance_frameworks:
  - MITRE ATT&CK
  - NIST 800-53
```

### Dynamic Field Selection

For advanced use cases, you can modify the query builder logic in:
- `archer/build/queries.py` - KQL/SPL query construction
- `archer/build/detections.py` - Detection compilation logic

---

## Getting Help

If you need assistance with mapping configuration:

1. **Check the FAQ**: [FAQ Section](#) in main documentation
2. **Review Examples**: See `archer/mappings/*.json` for reference
3. **Open an Issue**: [GitHub Issues](https://github.com/cmdshiftd/archer/issues)
4. **Community Support**: Reach out on GitHub Discussions

---

## Summary

✅ **Key Takeaways**:
- Mapping files control which detections are generated and how
- Always backup files before modifying
- Start with small changes and test thoroughly
- Document your customizations
- Use version control for mapping files

🎯 **Quick Start Checklist**:
- [ ] Identify your data sources and platforms
- [ ] Review default mapping files
- [ ] Backup existing mappings
- [ ] Make incremental changes
- [ ] Test with a small threat group
- [ ] Validate generated queries in your environment
- [ ] Document changes for your team

---

**Last Updated**: 2025-10-30
**Version**: 1.0
**Applies to**: Archer Detection Generator
