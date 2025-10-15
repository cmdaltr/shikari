# Schema Customization Guide

## Overview

Archer generates detection queries that are specific to your organization's log sources and field naming conventions. Since Splunk field names and log source configurations differ across organizations, you need to provide your custom schema mappings to ensure generated queries work in your environment.

## Why Schema Customization is Required

### The Challenge

Different organizations have different:
- **Field names**: One org might use `user`, another `UserName`, another `account_name`
- **Log sources (indexes)**: `index=windows` vs `index=windows_events` vs `index=wineventlog`
- **Data models**: Some use CIM (Common Information Model), others use custom schemas
- **Vendor configurations**: Splunk Cloud vs Enterprise, different data ingestion methods

### Archer's Solution

Archer uses **schema mapping files** in `archer/mappings/` to translate generic detection logic into your organization's specific query syntax.

## Schema Files

### Location

```
archer/
└── mappings/
    ├── schemaSplunk.json    # Splunk/Enterprise Security schema
    ├── schemaMDE.json       # Microsoft Defender for Endpoint schema
    └── dataSources.json     # Log source to technique mappings
```

### Schema Structure

#### schemaSplunk.json

This file maps **technique categories** to **log sources** and defines the **field extraction/transformation logic** for each source.

**Format:**

```json
{
    "technique_category": {
        "log_source_name": "| SPL commands with field mappings"
    }
}
```

**Technique Categories:**
- `cmd` - Command execution techniques
- `reg` - Registry modification techniques
- `evt` - Windows event log techniques
- `sw` - Software/application techniques
- `file` - File system operations
- `network` - Network activity
- `process` - Process creation/manipulation

**Example:**

```json
{
    "cmd": {
        "windows_events": "\n| fields _time EventCode ComputerName user process_name new_process_name parent_process_name parent_process_path process_command_line_arguments\n| fillnull value=-\n| eval Time=strftime(_time, \"%F %T\")\n| stats min(Time) AS mintime max(Time) AS maxtime values(process_command_line_arguments) AS process_command_line_arguments BY EventCode ComputerName user process_name new_process_name parent_process_name parent_process_path\n| table mintime maxtime EventCode ComputerName user process_name new_process_name parent_process_name parent_process_path process_command_line_arguments",

        "edr_events": "\n| fields _time category properties.DeviceName properties.AccountName properties.FileName properties.ProcessCommandLine properties.InitiatingProcessAccountName properties.InitiatingProcessFileName properties.InitiatingProcessCommandLine properties.InitiatingProcessParentFileName properties.LocalIP properties.RemoteIP properties.RemoteUrl\n| rename properties.DeviceName AS DeviceName properties.AccountName AS AccountName properties.FileName AS FileName properties.ProcessCommandLine AS ProcessCommandLine properties.InitiatingProcessAccountName AS InitiatingProcessAccountName properties.InitiatingProcessFileName AS InitiatingProcessFileName properties.InitiatingProcessCommandLine AS InitiatingProcessCommandLine properties.InitiatingProcessParentFileName AS InitiatingProcessParentFileName properties.LocalIP AS LocalIP properties.RemoteIP AS RemoteIP properties.RemoteUrl AS RemoteUrl\n| fillnull value=-\n| eval Time=strftime(_time, \"%F %T\")\n| stats min(Time) AS mintime max(Time) AS maxtime BY DeviceName FileName ProcessCommandLine InitiatingProcessAccountName InitiatingProcessFileName InitiatingProcessCommandLine InitiatingProcessParentFileName\n| table mintime maxtime DeviceName FileName ProcessCommandLine InitiatingProcessAccountName InitiatingProcessFileName InitiatingProcessCommandLine InitiatingProcessParentFileName"
    }
}
```

#### schemaMDE.json

This file maps **MDE Advanced Hunting tables** to **field selection logic**.

**Format:**

```json
{
    "TableName": "\n| summarize by field1, field2, field3, ..."
}
```

**Example:**

```json
{
    "DeviceProcessEvents": "\n| summarize by Timestamp, DeviceName, ActionType, AccountName, AccountUpn, FolderPath, FileName, SHA256, SHA1, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessParentFileName, InitiatingProcessVersionInfoCompanyName, InitiatingProcessVersionInfoProductName, IsProcessRemoteSession, AdditionalFields",

    "DeviceNetworkEvents": "\n| summarize by Timestamp, DeviceName, ActionType, LocalIP, LocalPort, RemoteIP, RemotePort, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessParentFileName, InitiatingProcessVersionInfoCompanyName, InitiatingProcessVersionInfoProductName, RemoteUrl, AdditionalFields"
}
```

## How to Customize for Your Organization

### Step 1: Identify Your Log Sources

List all the log sources (Splunk indexes, MDE tables, etc.) you have available:

**For Splunk:**
```bash
# Run in Splunk Search:
| eventcount summarize=false index=* | dedup index | table index
```

**For MDE:**
- DeviceProcessEvents
- DeviceNetworkEvents
- DeviceFileEvents
- DeviceRegistryEvents
- DeviceLogonEvents
- DeviceEvents

### Step 2: Identify Your Field Names

**For Splunk Windows Events:**

Run this search to see available fields:
```spl
index=YOUR_WINDOWS_INDEX EventCode=4688
| fieldsummary
| table field
```

Common fields you need to map:
- Computer/host identifier: `ComputerName`, `host`, `dest`, `Computer`
- Username: `user`, `User`, `Account_Name`, `SubjectUserName`
- Process name: `process_name`, `Process_Name`, `Image`, `NewProcessName`
- Command line: `CommandLine`, `process`, `ProcessCommandLine`
- Parent process: `parent_process_name`, `ParentProcessName`, `ParentImage`

### Step 3: Update schemaSplunk.json

Edit `archer/mappings/schemaSplunk.json` to reflect your environment.

**Template for a Windows log source:**

```json
{
    "cmd": {
        "YOUR_INDEX_NAME": "\n| fields _time YOUR_TIMESTAMP_FIELD YOUR_COMPUTER_FIELD YOUR_USER_FIELD YOUR_PROCESS_FIELD YOUR_COMMANDLINE_FIELD YOUR_PARENT_PROCESS_FIELD\n| fillnull value=-\n| eval Time=strftime(_time, \"%F %T\")\n| stats min(Time) AS mintime max(Time) AS maxtime values(YOUR_COMMANDLINE_FIELD) AS command_lines BY YOUR_COMPUTER_FIELD YOUR_USER_FIELD YOUR_PROCESS_FIELD YOUR_PARENT_PROCESS_FIELD\n| table mintime maxtime YOUR_COMPUTER_FIELD YOUR_USER_FIELD YOUR_PROCESS_FIELD YOUR_PARENT_PROCESS_FIELD command_lines"
    }
}
```

### Step 4: Test Your Schema

Generate a detection for a simple technique to verify the query uses your fields:

```bash
# CLI
python3 cli.py build-group --group-name "APT28" --genai --local

# Web UI
# Enter "APT28" and generate detections
```

Inspect the generated YAML files in `data/generate/` to verify field names match your schema.

## Real-World Examples

### Example 1: Splunk Enterprise Security with CIM

```json
{
    "cmd": {
        "win_eventlog": "\n| fields _time dest user process parent_process CommandLine ParentCommandLine EventCode\n| fillnull value=\"-\"\n| eval Time=strftime(_time, \"%F %T\")\n| stats min(Time) AS first_seen max(Time) AS last_seen values(CommandLine) AS command_lines BY dest user process parent_process EventCode\n| table first_seen last_seen dest user process parent_process command_lines EventCode"
    },
    "reg": {
        "win_eventlog": "\n| fields _time dest user registry_path registry_value_name registry_value_data process\n| fillnull value=\"-\"\n| eval Time=strftime(_time, \"%F %T\")\n| stats min(Time) AS first_seen max(Time) AS last_seen BY dest user registry_path registry_value_name registry_value_data process\n| table first_seen last_seen dest user registry_path registry_value_name registry_value_data process"
    }
}
```

### Example 2: Splunk Cloud with Custom Fields

```json
{
    "cmd": {
        "windows_security_logs": "\n| fields _time host Account_Name Image CommandLine ParentImage ParentCommandLine event_id\n| fillnull value=\"unknown\"\n| eval timestamp=strftime(_time, \"%Y-%m-%d %H:%M:%S\")\n| stats earliest(timestamp) AS first_occurrence latest(timestamp) AS last_occurrence values(CommandLine) AS executed_commands BY host Account_Name Image ParentImage event_id\n| table first_occurrence last_occurrence host Account_Name Image ParentImage executed_commands event_id"
    }
}
```

### Example 3: Microsoft Defender (No Changes Typically Needed)

MDE schemas are more standardized, but you can customize field selection:

```json
{
    "DeviceProcessEvents": "\n| summarize by Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName",

    "DeviceNetworkEvents": "\n| summarize by Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine"
}
```

## Schema Integration with AI Query Generation

When using the **Query Learning System** (enhanced AI-powered generation), Archer injects your schema into the LLM prompt:

```
## Field Schema for SPLUNK

Use these specific field names in your query (organizational schema):
  **index=windows_events**: EventCode, ComputerName, user, process_name,
  new_process_name, parent_process_name, process_command_line_arguments

## High-Quality Example Queries
[Examples from Splunk Security Content repository...]

Generate a SPLUNK query that:
1. Detects the indicators listed above for technique T1003
2. Uses the organizational field schema provided
3. Follows the structure shown in the example queries
```

This ensures generated queries:
- ✅ Use your organization's field names
- ✅ Query your organization's indexes/log sources
- ✅ Follow professional query patterns from example repositories
- ✅ Are ready to deploy without manual field name translation

## Common Pitfalls and Solutions

### Issue 1: Generated Queries Don't Return Results

**Cause**: Field names in schema don't match actual field names in logs

**Solution**:
```bash
# Test actual field names in Splunk
index=YOUR_INDEX | head 1 | fieldsummary | table field

# Update schemaSplunk.json with exact field names (case-sensitive!)
```

### Issue 2: Query Syntax Errors

**Cause**: SPL command syntax errors in schema mapping

**Solution**:
- Test your SPL snippets in Splunk first
- Use `\n` for newlines in JSON
- Escape special characters properly: `\"` for quotes

### Issue 3: Missing Data Sources

**Cause**: Technique requires a log source you haven't mapped

**Solution**:
- Add the missing log source to your schema
- Or disable generation for that technique category

### Issue 4: Overly Complex Queries

**Cause**: Schema includes too much post-processing (stats, eval, etc.)

**Solution**:
- Keep schema mappings focused on field extraction and renaming
- Let Archer's query builder handle detection logic
- Example - TOO MUCH:
  ```json
  "| stats count by user | where count > 10 | eval risk_score=count*5"
  ```
- Example - JUST RIGHT:
  ```json
  "| fields _time user process CommandLine | fillnull value=\"-\""
  ```

## Validation

After customizing your schema, validate it:

1. **Syntax Check** - Ensure JSON is valid:
   ```bash
   python3 -m json.tool archer/mappings/schemaSplunk.json
   ```

2. **Field Check** - Generate test detections and verify queries:
   ```bash
   python3 cli.py build-group --group-name "APT29" --genai --local
   grep -A 20 "search:" data/generate/splunk_*.yml | less
   ```

3. **Query Execution Test** - Copy a generated query into Splunk/MDE and run it

## Advanced: Adding New Log Sources

To add support for a new log source (e.g., AWS CloudTrail, Azure AD):

1. **Add to dataSources.json** (maps techniques to log sources)
2. **Add to schemaSplunk.json** or **schemaMDE.json** (defines field mappings)
3. **Update queries.py or queries_enhanced.py** (if custom logic needed)

Example - Adding AWS CloudTrail support:

**dataSources.json:**
```json
{
    "T1078": {
        "platforms": ["AWS"],
        "splunk": ["aws_cloudtrail"]
    }
}
```

**schemaSplunk.json:**
```json
{
    "cmd": {
        "aws_cloudtrail": "\n| fields _time eventTime recipientAccountId userIdentity.userName eventName requestParameters responseElements\n| fillnull value=\"-\"\n| eval Time=strftime(_time, \"%F %T\")\n| stats min(Time) AS first_seen max(Time) AS last_seen BY recipientAccountId userIdentity.userName eventName\n| table first_seen last_seen recipientAccountId userIdentity.userName eventName"
    }
}
```

## Getting Help

If you need assistance customizing schemas for your environment:

1. **Check existing examples** in `archer/mappings/schemaSplunk.json`
2. **Review Query Learning System docs**: `docs/QUERY_LEARNING_SYSTEM.md`
3. **Test incrementally** - Start with one log source, verify, then expand
4. **Review generated queries** - The YAML files show exactly what queries were generated

## Related Documentation

- [GETTING_STARTED.md](GETTING_STARTED.md) - Initial setup and configuration
- [QUERY_LEARNING_SYSTEM.md](QUERY_LEARNING_SYSTEM.md) - Enhanced AI query generation
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture overview
- [CORRELATION_GUIDE.md](CORRELATION_GUIDE.md) - Multi-query correlation system

## Schema File Reference

### Required Fields by Platform

**Splunk - Windows Process Creation (EventCode 4688):**
- Time: `_time`
- Computer: `ComputerName`, `Computer`, `dest`, `host`
- User: `user`, `User`, `Account_Name`, `SubjectUserName`
- Process: `process_name`, `Process_Name`, `NewProcessName`, `Image`
- Command Line: `CommandLine`, `ProcessCommandLine`, `process`
- Parent Process: `parent_process_name`, `ParentProcessName`, `ParentImage`

**MDE - DeviceProcessEvents:**
- Timestamp
- DeviceName
- AccountName, AccountUpn
- FileName (process name)
- ProcessCommandLine
- InitiatingProcessFileName, InitiatingProcessCommandLine
- InitiatingProcessParentFileName
- SHA256, SHA1

**MDE - DeviceRegistryEvents:**
- Timestamp
- DeviceName
- RegistryKey, RegistryValueName, RegistryValueData
- PreviousRegistryKey, PreviousRegistryValueName, PreviousRegistryValueData
- InitiatingProcessFileName, InitiatingProcessCommandLine

## Conclusion

Schema customization is **critical** for Archer to generate detection queries that work in your environment. By providing accurate field mappings in `archer/mappings/`, you enable Archer to:

- Generate deployment-ready queries without manual modification
- Leverage AI query learning with your organization's field names
- Support multiple log sources (Windows, Linux, cloud, etc.)
- Scale detection engineering across your security team

Take time to configure your schemas correctly - it's a one-time investment that pays dividends every time you generate detections.
