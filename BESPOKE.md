# Bespoke Organization-Specific Configuration

The `data/bespoke/` directory contains **organization-specific** content for customizing Archer to your environment. This includes schema mappings, exclusions, reference queries, and configuration settings.

## 🎯 Quick Start

1. **Copy the example files:**
   ```bash
   cd data/bespoke
   cp exclusions.yaml.example exclusions.yaml
   cp config.yaml.example config.yaml
   ```

2. **Edit the files** with your organization's specific exclusions and settings

3. **Reload the configuration** via API or restart the server:
   ```bash
   curl -X POST http://localhost:8000/api/bespoke/reload
   ```

---

## 🗺️ Mapping Files

The `mappings/` directory contains core schema and configuration files that define how Archer generates queries for your SIEM platforms.

| File | Purpose |
|------|---------|
| `schemaSplunk.json` | Splunk index/sourcetype to field mappings |
| `schemaMDE.json` | Microsoft Defender table mappings |
| `schemaElastic.json` | Elastic index mappings |
| `schemaGoogleSecOps.json` | Google SecOps UDM mappings |
| `indicatorMapping.json` | Maps indicator types (cmd, file, reg) to platform fields |
| `entityMappings.json` | KQL entity type mappings |
| `dataSources.json` | MITRE ATT&CK data source definitions |
| `platforms.json` | Platform configuration |
| `members.json` | Team member LAN ID to team assignments |
| `techniquePlatformIndicators.json` | Technique validation matrix |

---

## 🔍 Reference Queries

Reference queries are **production-tested detection queries** that Archer uses as:
1. **Templates** - Reference patterns for generating new queries with similar structure
2. **Few-shot examples** - Examples provided to the LLM for learning query style and best practices

### Adding Reference Queries

Add queries to the appropriate vendor directory in `reference_queries/`:

| Vendor | Location | Format |
|--------|----------|--------|
| Splunk | `Splunk/all_reference_queries.yaml` or individual files | SPL |
| MDE | `MDE/*.yaml` (one file per query) | KQL |

**Required fields (all vendors):**

```yaml
id: [unique-identifier]
name: [Detection Name]
technique_id: T[XXXX].[XXX]
query: |
  [Your query here]
```

**Optional fields:**

```yaml
description: [What this detection finds]
platform: [AWS|Azure|Windows|Linux|O365]
log_source: [index or table name]
severity: [low|medium|high|critical]
tactics: [MITRE tactics]
tags: [categorization tags]
indicators:
  cmd: [command line indicators]
  reg: [registry indicators]
  file: [file indicators]
metadata:
  author: [Your name/team]
  source: manual
```

<details>
<summary><b>Full Splunk Example</b></summary>

```yaml
id: splunk-aws-001
name: Account Access Removal in AWS
technique_id: T1531
platform: AWS
log_source: aws_cloudtrail
description: |
  Detects account access removal activities in AWS including DeleteRole,
  DeleteUserProfile, and RemovePermission events.
tags:
  - Cloud
  - AWS
event_names:
  - DeleteRole
  - DeleteUserProfile
  - RemovePermission
query: |
  index=aws_cloudtrail earliest=-7d eventName IN ("DeleteRole", "DeleteUserProfile", "RemovePermission")
  | eval identity=mvappend(recipientAccountId, userName, sourceIPAddress)
  | rename userIdentity.arn AS resource eventName AS operation
  | eval time=strftime(_time, "%F %H:%M")
  | stats count values(identity) AS identity BY time resource operation
  | eval technique="Account Access Removal"
  | table time identity resource operation technique count
  | sort -time -count
metadata:
  author: CTH
  source: manual
```
</details>

<details>
<summary><b>Full MDE/KQL Example</b></summary>

```yaml
id: mde-ssh-001
name: SSH Key File Access
technique_id: T1021.004
description: |
  Detects access to SSH key files which may indicate lateral movement preparation.
severity: medium
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
tactics:
  - Lateral Movement
tags:
  - SSH
  - Lateral Movement
query: |
  DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FolderPath has ".ssh" and FileName in ("id_rsa", "id_ed25519", "authorized_keys")
  | summarize by Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
indicators:
  file:
    - id_rsa
    - id_ed25519
    - authorized_keys
metadata:
  author: CTH
  source: manual
```
</details>

### File Naming Conventions

| Platform | Format | Example |
|----------|--------|---------|
| Splunk | `[technique_name]_[platform].yaml` | `account_access_removal_aws.yaml` |
| MDE | `[TechniqueName]_MDE_[DataSource].yaml` | `SSH_DeviceProcessEvents.yaml` |
| GoogleSecOps | `[TechniqueName]_Chronicle.yaml` | `SSH_Chronicle.yaml` |
| Elastic | `[TechniqueName]_Elastic.yaml` | `SSH_Elastic.yaml` |

### Required Fields (All Platforms)

| Field | Description | Required |
|-------|-------------|----------|
| `id` | Unique identifier | Yes |
| `name` | Human-readable name | Yes |
| `technique_id` | MITRE ATT&CK technique ID | Yes |
| `query` | The actual detection query | Yes |

### Recommended Fields

| Field | Description |
|-------|-------------|
| `description` | What the detection finds |
| `log_source` | Index/table being queried |
| `indicators` | IOCs or patterns detected |
| `tags` | Categorization tags |
| `tactics` | MITRE ATT&CK tactics |

### Query Style Guidelines

#### Splunk Queries

1. **Standard output format:**
```spl
| eval time=strftime(_time, "%F %H:%M")
| stats count values(identity) AS identity BY time resource operation
| eval technique="[Technique Name]"
| table time identity resource operation technique count
| sort -time -count
```

2. **Identity enrichment pattern:**
```spl
| eval identity=mvappend(field1, field2, field3)
| eval identity=mvfilter(identity!="null")
```

3. **Exclusion pattern:**
```spl
| search NOT (identity IN ("local service", "network service", "system"))
```

#### MDE/KQL Queries

1. **Standard time filter:**
```kql
| where Timestamp > ago(30d)
```

2. **Exclusion with datatable:**
```kql
let Exclusions = datatable(item:string) ["item1", "item2"];
| where not(FieldName has_any(Exclusions))
```

3. **Summarization:**
```kql
| summarize by Timestamp, DeviceName, ActionType, AccountName, [other fields]
```

### How Archer Uses Reference Queries

1. **Template Matching**: When generating a detection for a specific technique/platform, Archer looks for existing reference queries with the same `technique_id` or similar `log_source`.

2. **Pattern Extraction**: The `query_patterns` section helps Archer understand common patterns like:
   - Field extraction methods
   - Identity enrichment approaches
   - Output formatting conventions

3. **Few-shot Learning**: Reference queries are provided to the LLM as examples of well-structured, production-tested detections. They take priority over OSINT examples.

4. **Indicator Mapping**: The `indicators` field helps Archer understand what IOCs are relevant to each technique.

### Testing Reference Queries

Before adding a query to the reference collection:

1. **Validate syntax** - Ensure the query runs without errors
2. **Test in production** - Run against real data to verify results
3. **Tune exclusions** - Add necessary exclusions to reduce false positives
4. **Document indicators** - List the key IOCs or patterns being detected
5. **Add OSINT sources** - Reference external detection rules that informed your query

---

## 🚫 Exclusions Configuration

### exclusions.yaml

Global exclusions automatically applied to every generated query. Use this to filter out known-good activity in your environment.

```yaml
# Processes to always exclude from detections
process_exclusions:
  - "C:\\Program Files\\YourSecurityTool\\*.exe"
  - "C:\\Program Files\\CustomApp\\agent.exe"

# Users/accounts to always exclude
user_exclusions:
  - "svc_backup"
  - "svc_monitoring"

# Hosts to always exclude
host_exclusions:
  - "YOURDC01"
  - "YOURSIEM01"

# IP ranges to exclude
ip_exclusions:
  - "10.0.0.0/8"
  - "192.168.1.0/24"

# Custom field exclusions (any field name)
custom_exclusions:
  CommandLine:
    - "*update.exe /silent*"
  SHA256:
    - "abc123..."
```

### How Exclusions Are Applied

#### KQL/MDE Queries

Exclusions are added after the first `| where` clause:

```kql
DeviceProcessEvents
| where Timestamp > ago(1h) and
  InitiatingProcessFolderPath != "C:\\Program Files\\YourEDR\\agent.exe" and
  AccountName != "svc_backup" and
  DeviceName != "DC01"
| where FileName =~ "cmd.exe"
```

#### Splunk SPL Queries

Exclusions are added after the `index=` specification:

```spl
index=security NOT process_path="C:\\Program Files\\YourEDR\\*.exe" NOT user="svc_backup" NOT host="DC01"
| search EventCode=4688
```

---

## 💼 Organization Configuration

### config.yaml

Organization-specific configuration settings:

```yaml
organization:
  name: "Your Organization"
  default_index: "security"
  default_sourcetype: "WinEventLog:Security"

field_overrides:
  CommandLine: "process.command_line"
  ParentProcessName: "process.parent.name"

query_settings:
  apply_exclusions: true
  max_results: 1000
  default_timespan: "1h"
```

### members.json

Team member assignments for author attribution:

```json
{
    "CTH": [
        {
            "username": "jsmith",
            "name": "John Smith",
            "region": "NA"
        }
    ],
    "CTI": [
        {
            "username": "jdoe",
            "name": "Jane Doe",
            "region": "EMEA"
        }
    ]
}
```

Used to map detection authors to teams (CTH = Cyber Threat Hunting, CTI = Cyber Threat Intelligence, etc.)

---

## 🛂 Custom Sample Searches

Store organization-specific detection queries in `searches/` that are tailored for your environment:

```yaml
# searches/T1003.001_custom.yaml
- technique_id: T1003.001
  platform: MDE
  description: "Custom LSASS detection for our environment"
  severity: high
  query: |
    DeviceProcessEvents
    | where Timestamp > ago(1h)
    | where FileName =~ "lsass.exe"
    // Custom exclusions for our EDR
    | where InitiatingProcessFolderPath !startswith "C:\\Program Files\\OurEDR\\"
  notes: "Tuned for our EDR deployment"
```

## 📑 Additional Notes

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status/bespoke` | GET | Get bespoke configuration status |
| `/api/bespoke/sample-searches` | GET | Get custom sample searches |
| `/api/bespoke/reload` | POST | Reload configuration from disk |

#### Examples

```bash
# Check bespoke status
curl http://localhost:8000/api/status/bespoke

# Get sample searches for a technique
curl "http://localhost:8000/api/bespoke/sample-searches?technique_id=T1003.001"

# Reload after editing config files
curl -X POST http://localhost:8000/api/bespoke/reload
```

---

### Git Tracking

| Path | Tracked | Notes |
|------|---------|-------|
| `mappings/` directory | Yes | Structure only |
| `mappings/*.json` | No | Org-specific schema files |
| `reference_queries/` | Yes | Shared reference queries |
| `exclusions.yaml` | No | Org-specific exclusions |
| `config.yaml` | No | Org-specific settings |
| `searches/` contents | No | Org-specific detections |

New users must populate `mappings/` with schema files from a reference install or create their own.

---

### Security Notes

- Sensitive files (`exclusions.yaml`, `config.yaml`, `mappings/*.json`) are **gitignored** - contents will not be committed to the public repository
- Store sensitive exclusions (internal IPs, hostnames) only in this directory
- Review exclusions regularly to ensure they don't hide actual attacks
- Test new exclusions in a development environment first

---

### Troubleshooting

#### Exclusions not being applied?

1. Check that `exclusions.yaml` exists (not just `.example`)
2. Verify YAML syntax: `python -c "import yaml; yaml.safe_load(open('exclusions.yaml'))"`
3. Reload configuration: `curl -X POST http://localhost:8000/api/bespoke/reload`
4. Check status: `curl http://localhost:8000/api/status/bespoke`

#### Configuration not loading?

Check the server logs for warnings like:
- `Warning: Failed to load exclusions.yaml: ...`
- `Warning: Failed to load config.yaml: ...`

#### Reference queries not appearing in prompts?

1. Verify YAML syntax in reference query files
2. Check that `technique_id` matches MITRE format (e.g., `T1021.001`)
3. Ensure the `query` field contains valid query text
4. Restart the server to reload the reference query cache
