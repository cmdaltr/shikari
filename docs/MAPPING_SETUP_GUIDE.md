# Mapping Files Setup Guide

## Overview

Archer ships with **generic, example mapping files** that work with common index names. However, **you MUST customize these mappings** to match your environment's actual log sources and index names.

## Why Mapping Files Matter

Mapping files tell Archer:
1. **Which indices/sources** to query in your environment
2. **How to normalize field names** across different log formats
3. **What fields to extract** for each indicator type (cmd, file, registry, network, etc.)

Without proper mappings, generated detections will:
- ❌ Query non-existent indices
- ❌ Use wrong field names
- ❌ Return no results or false positives

## Mapping File Types

### 1. Schema Mappings (`schemaSplunk.json`, `schemaMDE.json`)

These define **field normalization** and **index selection** for each platform.

**Structure:**
```json
{
  "cmd": {
    "your_index_name_here": "| fields _time command process ...\n| rename ...",
    "another_index": "..."
  },
  "file": { ... },
  "reg": { ... }
}
```

**Key Points:**
- **Top-level keys** = indicator types (`cmd`, `file`, `reg`, `network`, `cve`, `api`)
- **Second-level keys** = YOUR actual index/source names
- **Values** = Splunk/KQL snippets to normalize fields

### 2. Example: Splunk Schema

```json
{
  "cmd": {
    "edr_events": "| rename \"properties.DeviceName\" AS device ...",
    "windows_events": "| rename EventCode AS event_code ..."
  }
}
```

**What This Means:**
- When Archer generates a detection for **command-line indicators**
- It will query `index=edr_events` OR `index=windows_events`
- Field names will be normalized (e.g., `properties.DeviceName` → `device`)

### 3. Example: MDE Schema

```json
{
  "DeviceProcessEvents": "\n| summarize by Timestamp, DeviceName, ProcessCommandLine, ...",
  "DeviceFileEvents": "\n| summarize by Timestamp, DeviceName, FileName, ..."
}
```

**What This Means:**
- MDE queries will use table names like `DeviceProcessEvents`
- Fields are already normalized (MDE has consistent schema)

## Setup Process

### Step 1: Identify Your Log Sources

Answer these questions:

1. **What SIEM platform do you use?**
   - Splunk
   - Microsoft Sentinel / Defender
   - Elastic
   - Multiple platforms

2. **What are your index/source names?**

   For Splunk:
   ```
   Example: index=windows_events
   Example: index=edr_events
   Example: index=av_console
   ```

   For Microsoft Defender/Sentinel:
   ```
   Example: DeviceProcessEvents
   Example: DeviceFileEvents
   Example: DeviceNetworkEvents
   ```

3. **What log types do you have?**
   - ✅ Process/Command execution logs (cmd)
   - ✅ File activity logs (file)
   - ✅ Registry activity logs (reg)
   - ✅ Network activity logs (network)
   - ✅ Software/vulnerability logs (sw, cve)
   - ✅ API/cloud logs (api)

### Step 2: Map Your Field Names

For each log source, identify how fields are named:

| Standard Field | Your Field Name | Example |
|---------------|-----------------|---------|
| Device/Hostname | ? | `DeviceName`, `host`, `ComputerName` |
| Command Line | ? | `ProcessCommandLine`, `CommandLine`, `process_command_line` |
| File Name | ? | `FileName`, `file_name`, `fname` |
| User | ? | `AccountName`, `user`, `User` |
| Source IP | ? | `src_ip`, `SourceIP`, `RemoteIP` |

### Step 3: Update Mapping Files

#### Option A: Use the Setup Script (Recommended)

```bash
python scripts/setup_mappings.py
```

This interactive script will:
1. Ask about your environment
2. Generate custom mapping files
3. Validate your configuration

#### Option B: Manual Editing

1. Copy example mapping files:
   ```bash
   cp archer/mappings/schemaSplunk.json archer/mappings/schemaSplunk_custom.json
   cp archer/mappings/schemaMDE.json archer/mappings/schemaMDE_custom.json
   ```

2. Edit `schemaSplunk_custom.json`:
   ```json
   {
     "cmd": {
       "YOUR_INDEX_NAME": "| rename YOUR_FIELD AS standard_field\n| fields ...",
       "ANOTHER_INDEX": "..."
     }
   }
   ```

3. Replace example index names with YOUR actual names:
   - `edr_events` → `index=edr_events`
   - `windows_events` → `index=windows_events`
   - `av_console` → `index=av_console`

### Step 4: Test Your Mappings

Run the validation script:

```bash
python scripts/validate_mappings.py
```

This will:
- ✅ Check for syntax errors
- ✅ Verify all indicator types are covered
- ✅ Ensure field names are consistent
- ✅ Warn about missing index definitions

### Step 5: Generate Test Detections

Generate a small test set to verify:

```bash
# Generate detections for a single technique
python -c "from archer.build.detections import compile_query; compile_query('T1003.001', 'Test Group', vendor='splunk')"
```

Check the generated query:
- Does it reference your actual indices?
- Are field names correct?
- Can you run it in your SIEM?

## Common Mapping Patterns

### Splunk: Multiple Indices

```json
{
  "cmd": {
    "windows_security": "index=windows_events EventCode=4688\n| rename ...",
    "sysmon": "index=windows_events EventCode=1\n| rename ...",
    "defender": "index=edr_events\n| rename ..."
  }
}
```

**Result:** Archer will generate queries like:
```spl
(index=windows_events EventCode=4688 ...) OR
(index=windows_events EventCode=1 ...) OR
(index=edr_events ...)
```

### MDE: Standard Tables

```json
{
  "DeviceProcessEvents": "\n| summarize by Timestamp, DeviceName, ...",
  "DeviceFileEvents": "\n| summarize by Timestamp, DeviceName, ..."
}
```

**Result:** Archer will generate queries like:
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine contains "mimikatz"
| summarize by Timestamp, DeviceName, ...
```

### Hybrid: Multiple Platforms

If you use both Splunk and MDE:
1. Configure both `schemaSplunk.json` and `schemaMDE.json`
2. Generate detections for both platforms
3. Each will use its appropriate schema

## Troubleshooting

### Problem: Generated queries don't work

**Cause:** Incorrect index names or field mappings

**Solution:**
1. Check your index names: `| metadata type=sources`
2. Check your field names: `index=your_index | head 1 | fieldsummary`
3. Update mapping files with actual names

### Problem: No indicators extracted

**Cause:** Missing indicator type mappings

**Solution:**
1. Check which indicator types your logs support
2. Add mappings for those types in your schema file
3. Some indicators (CVE, API) may not apply to all log sources

### Problem: Field name conflicts

**Cause:** Different log sources use same field name for different purposes

**Solution:**
Use source-specific normalization:
```json
{
  "cmd": {
    "source_a": "| rename field1 AS command ...",
    "source_b": "| rename different_field AS command ..."
  }
}
```

## Best Practices

1. **Start Small**
   - Configure one log source at a time
   - Test thoroughly before adding more

2. **Use Consistent Naming**
   - Standardize on field names across your mappings
   - Follow CIM (Common Information Model) when possible

3. **Document Your Mappings**
   - Add comments explaining custom choices
   - Keep a mapping inventory spreadsheet

4. **Version Control**
   - Commit mapping files to git
   - Track changes over time
   - Share with your team

5. **Regular Updates**
   - Review when log sources change
   - Update when new data connectors added
   - Test after SIEM upgrades

## Example: Complete Splunk Setup

**Environment:**
- Splunk Enterprise
- Microsoft Defender for Endpoint (forwarded to Splunk)
- Windows Security Event Logs
- Sysmon

**Mapping File** (`schemaSplunk.json`):

```json
{
  "cmd": {
    "mde_splunk": "index=mde_logs sourcetype=defender:atp:deviceprocessevents\n| rename properties.DeviceName AS device properties.ProcessCommandLine AS process_command_line\n| fields _time device process_command_line",

    "windows_security": "index=windows sourcetype=WinEventLog:Security EventCode=4688\n| rename ComputerName AS device Process_Command_Line AS process_command_line\n| fields _time device process_command_line",

    "sysmon": "index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1\n| rename Computer AS device CommandLine AS process_command_line\n| fields _time device process_command_line"
  },

  "file": {
    "mde_splunk": "index=mde_logs sourcetype=defender:atp:devicefileevents\n| rename properties.DeviceName AS device properties.FileName AS file_name properties.FolderPath AS file_path\n| fields _time device file_name file_path",

    "sysmon": "index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=11\n| rename Computer AS device TargetFilename AS file_path\n| fields _time device file_path"
  }
}
```

**Result:** Detections will query all three sources and normalize fields consistently!

## Getting Help

1. **Check Examples**
   - Review `archer/mappings/schemaSplunk.json`
   - Look at existing index patterns

2. **Run Validation**
   - `python scripts/validate_mappings.py`
   - Check for errors and warnings

3. **Test Queries**
   - Copy generated query to SIEM
   - Verify it returns expected results
   - Adjust mappings as needed

4. **Community Support**
   - GitHub Issues: Report problems
   - Documentation: Check for updates
   - Examples: Share your mappings (anonymized)

## Next Steps

1. ✅ Identify your log sources and index names
2. ✅ Create/update mapping files for your environment
3. ✅ Validate mappings
4. ✅ Generate test detections
5. ✅ Deploy to production

**Remember:** Mapping files are the foundation of Archer's detection generation. Take time to configure them correctly!
