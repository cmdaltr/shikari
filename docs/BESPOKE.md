# Bespoke Organization-Specific Configuration

The `bespoke/` directory (at the project root) contains **organization-specific** content. The directory structure is committed but files within are gitignored.

## Quick Start

1. **Copy the example files:**
   ```bash
   cp exclusions.yaml.example exclusions.yaml
   cp config.yaml.example config.yaml
   ```

2. **Edit the files** with your organization's specific exclusions and settings

3. **Reload the configuration** via API or restart the server:
   ```bash
   curl -X POST http://localhost:8000/api/bespoke/reload
   ```

## Directory Structure

```
bespoke/
  exclusions.yaml           # Global exclusions applied to all queries
  config.yaml               # Organization-specific settings
  mappings/                 # Index, table and field mappings (generic defaults copied in at start-up)
    sources/members.json    # Team member assignments (LAN ID to team mapping; optional, never shipped)
  sample_searches/          # Custom detection examples
    *.yaml                  # Your custom searches
  exclusions.yaml.example   # Template for exclusions
  config.yaml.example       # Template for config
```

## Files

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

### sample_searches/

Store organization-specific detection queries that are tailored for your environment:

```yaml
# sample_searches/T1003.001_custom.yaml
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

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status/bespoke` | GET | Get bespoke configuration status |
| `/api/bespoke/sample-searches` | GET | Get custom sample searches |
| `/api/bespoke/reload` | POST | Reload configuration from disk |

### Examples

```bash
# Check bespoke status
curl http://localhost:8000/api/status/bespoke

# Get sample searches for a technique
curl "http://localhost:8000/api/bespoke/sample-searches?technique_id=T1003.001"

# Reload after editing config files
curl -X POST http://localhost:8000/api/bespoke/reload
```

## How Exclusions Are Applied

### KQL/MDE Queries

Exclusions are added after the first `| where` clause:

```kql
DeviceProcessEvents
| where Timestamp > ago(1h) and
  InitiatingProcessFolderPath != "C:\\Program Files\\YourEDR\\agent.exe" and
  AccountName != "svc_backup" and
  DeviceName != "DC01"
| where FileName =~ "cmd.exe"
```

### Splunk SPL Queries

Exclusions are added after the `index=` specification:

```spl
index=security NOT process_path="C:\\Program Files\\YourEDR\\*.exe" NOT user="svc_backup" NOT host="DC01"
| search EventCode=4688
```

### Elastic ES|QL Queries

ES|QL is piped, so exclusions append as a trailing `| WHERE` over ECS fields. IP
ranges use `CIDR_MATCH`, process wildcards use `RLIKE`:

```esql
FROM logs-endpoint.events.*
| WHERE process.name == "cmd.exe"
| WHERE process.executable != "/opt/YourEDR/agent" AND user.name != "svc_backup"
    AND host.name != "DC01" AND NOT CIDR_MATCH(source.ip, "10.0.0.0/8")
```

### Google SecOps YARA-L Rules

YARA-L has no trailing filter, so exclusions are added as negated predicates
inside the `events:` section, repeated for every event variable the rule binds
(so an excluded host or user drops the whole match, not one stage). UDM fields
such as `principal.ip` are repeated, so the form is `not field = "x"` ("no value
equals"), never `field != "x"`; IP ranges use `net.ip_in_range_cidr()`:

```yaral
events:
  $e.metadata.event_type = "PROCESS_LAUNCH"
  // bespoke exclusions
  not $e.principal.user.userid = "svc_backup"
  not $e.principal.hostname = "DC01"
  not net.ip_in_range_cidr($e.principal.ip, "10.0.0.0/8")
```

## Security Notes

- This directory is **gitignored** - contents will not be committed to the public repository
- Store sensitive exclusions (internal IPs, hostnames) only in this directory
- Review exclusions regularly to ensure they don't hide actual attacks
- Test new exclusions in a development environment first

## Troubleshooting

### Exclusions not being applied?

1. Check that `exclusions.yaml` exists (not just `.example`)
2. Verify YAML syntax: `python -c "import yaml; yaml.safe_load(open('exclusions.yaml'))"`
3. Reload configuration: `curl -X POST http://localhost:8000/api/bespoke/reload`
4. Check status: `curl http://localhost:8000/api/status/bespoke`

### Configuration not loading?

Check the server logs for warnings like:
- `Warning: Failed to load exclusions.yaml: ...`
- `Warning: Failed to load config.yaml: ...`
