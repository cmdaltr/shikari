# Reference Queries for Shikari Detection Generation

This directory contains production-tested detection queries that Shikari uses as:
1. **Templates** - Reference patterns for generating new queries with similar structure
2. **Few-shot examples** - Examples provided to the LLM for learning query style and best practices

## Directory Structure

```
reference_queries/
├── README.md                    # This file
├── Splunk/
│   ├── all_reference_queries.yaml   # All Splunk queries in structured format
│   └── [individual_query].yaml      # Optional individual query files
├── MDE/
│   ├── CloudGroups_MDE.yaml
│   ├── RemoteDesktopProtocol_MDE_DeviceEvents.yaml
│   ├── RemoteDesktopProtocol_MDE_DeviceRegistryEvents.yaml
│   ├── SSH_DeviceFileEvents.yaml
│   └── SSH_DeviceProcessEvents.yaml
├── GoogleSecOps/                # Future: Google SecOps queries
└── Elastic/                     # Future: Elastic Security queries
```

## Adding New Reference Queries

### Splunk Queries

#### Option 1: Add to the consolidated file
Edit `Splunk/all_reference_queries.yaml` and add your query under the appropriate section:

```yaml
- id: splunk-[platform]-[number]
  name: [Detection Name]
  technique_id: T[XXXX].[XXX]
  log_source: [index_name]
  event_names:        # Optional: list of event names for filtering
    - EventName1
    - EventName2
  indicators:         # Optional: IOCs the query detects
    - indicator1
    - indicator2
  query: |
    index=[your_index] earliest=-7d [your query here]
    | eval time=strftime(_time, "%F %H:%M")
    | stats count values(identity) AS identity BY time resource operation
    | eval technique="[Technique Name]"
    | table time identity resource operation technique count
    | sort -time -count
```

#### Option 2: Create individual YAML files
Create a new file in `Splunk/` following this format:

```yaml
id: splunk-ref-XXX
name: [Detection Name]
technique_id: T[XXXX].[XXX]
platform: [AWS|Azure|Windows|Linux|O365]
log_source: [splunk_index_name]
description: |
  [Description of what this detection finds]
tags:
  - [Tag1]
  - [Tag2]
query: |
  [Your full Splunk query]
query_patterns:
  field_extraction:
    - '[key rex/rename patterns used]'
  identity_enrichment:
    - '[identity building patterns]'
  output_format:
    - '[table/sort patterns]'
metadata:
  author: [Your name/team]
  source: manual
```

### MDE (Microsoft Defender for Endpoint) Queries

Create a new YAML file in `MDE/` following this format:

```yaml
id: [uuid]
name: [Detection Name]
technique_id: T[XXXX].[XXX]
description: |
  [Description with MITRE ATT&CK reference]
severity: [low|medium|high|critical]
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - [DeviceProcessEvents|DeviceFileEvents|DeviceEvents|DeviceRegistryEvents|DeviceNetworkEvents]
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - [MITRE Tactic]
tags:
  - [Tag - e.g., "Scattered Spider (Group)"]
query: |
  [Your KQL query]
  | where Timestamp > ago(30d)
  | where [your conditions]
  | summarize by [fields]
entityMappings:
- entityType: Account
  fieldMappings:
    - identifier: AadUserId
      columnName: AccountName
# Add more entity mappings as needed
version: 1.0
kind: Scheduled
metadata:
    source:
        kind: Shikari
    author:
        name: [your_id]
    support:
        tier: CTH
indicators:
  cmd:
    - [command line indicators]
  reg:
    - [registry indicators]
  # Add other indicator types as needed
```

### File Naming Conventions

| Platform | Format | Example |
|----------|--------|---------|
| Splunk | `[technique_name]_[platform].yaml` | `account_access_removal_aws.yaml` |
| MDE | `[TechniqueName]_MDE_[DataSource].yaml` | `SSH_DeviceProcessEvents.yaml` |
| Google SecOps | `[TechniqueName]_UDM.yaml` | `SSH_UDM.yaml` |
| Elastic | `[TechniqueName]_ESQL.yaml` | `SSH_ESQL.yaml` |

## Required Fields

### Minimum Required Fields (All Platforms)

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

## Query Style Guidelines

### Splunk Queries

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

### MDE/KQL Queries

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

## How Shikari Uses These Queries

1. **Template Matching**: When generating a detection for a specific technique/platform, Shikari looks for existing reference queries with the same `technique_id` or similar `log_source`.

2. **Pattern Extraction**: The `query_patterns` section helps Shikari understand common patterns like:
   - Field extraction methods
   - Identity enrichment approaches
   - Output formatting conventions

3. **Few-shot Learning**: Reference queries are provided to the LLM as examples of well-structured, production-tested detections.

4. **Indicator Mapping**: The `indicators` field helps Shikari understand what IOCs are relevant to each technique.

## Testing Your Reference Queries

Before adding a query to the reference collection:

1. **Validate syntax** - Ensure the query runs without errors
2. **Test in production** - Run against real data to verify results
3. **Tune exclusions** - Add necessary exclusions to reduce false positives
4. **Document indicators** - List the key IOCs or patterns being detected
5. **Add OSINT sources** - Reference external detection rules that informed your query

## Contact

For questions about reference queries or to contribute new detections, contact the CTH team.
