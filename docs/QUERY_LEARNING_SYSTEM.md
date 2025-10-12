# Query Learning System

## Overview

The Query Learning System enhances Archer's detection query generation by learning from high-quality, real-world query examples from open source security repositories. This system implements **few-shot learning**, where relevant examples are injected into LLM prompts to guide query generation.

## Key Features

- **Automated Repository Management**: Clones and indexes query examples from leading security repositories
- **Technique-Based Search**: Find examples by MITRE ATT&CK technique ID
- **SIEM-Specific Learning**: Separate examples for Splunk, Microsoft Defender (KQL), Elastic, and Sigma
- **Schema-Aware Generation**: Respects your organization's field naming conventions
- **Graceful Fallback**: Falls back to template-based generation if enhanced mode fails
- **Progressive Enhancement**: Can be enabled/disabled without code changes

## Supported Query Repositories

The system integrates with these authoritative sources:

1. **[Splunk Security Content](https://github.com/splunk/security_content)**
   - 1000+ production-ready Splunk detection queries
   - Mapped to MITRE ATT&CK techniques
   - Used by Splunk ESCU (Enterprise Security Content Update)

2. **[SigmaHQ Sigma Rules](https://github.com/SigmaHQ/sigma)**
   - 3000+ vendor-agnostic detection rules
   - Universal format convertible to any SIEM
   - Community-maintained, battle-tested patterns

3. **[Microsoft Defender Hunting Queries](https://github.com/francoisfried/Defender-Advanced-Hunting-Queries)**
   - Advanced KQL hunting queries for Microsoft 365 Defender
   - Real-world threat hunting patterns
   - Platform-specific best practices

4. **Additional Resources** (documentation only):
   - [Elastic Detection Rules Blog](https://www.elastic.co/blog/elastic-security-building-effective-threat-hunting-detection-rules)
   - [50 Threat Hunting Queries (Splunk/KQL)](https://systemweakness.com/50-threat-hunting-queries-splunk-kql-every-analyst-should-know-ca82c1e5abe0)
   - [KQL Query - From Threat Report to Hunting Query](https://kqlquery.com/posts/from-threat-report-to-hunting-query/)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Query Generation Flow                    │
└─────────────────────────────────────────────────────────────┘

1. Technique Identified
   ↓
2. Query Example Repository
   - Search by technique ID (e.g., T1003)
   - Filter by vendor (Splunk/MDE)
   - Retrieve top N examples
   ↓
3. Prompt Enhancer
   - Inject relevant examples
   - Add organizational schema (schemaSplunk.json)
   - Include best practices
   ↓
4. LLM Generation
   - Local LLM (llama-cpp) or OpenAI
   - Few-shot learning from examples
   - Schema-guided field selection
   ↓
5. Query Validation
   - Syntax check
   - Structure validation
   - Fallback to template if invalid
   ↓
6. YAML Detection Rule Created
```

## Directory Structure

```
archer/
├── data/
│   └── query_examples/          # Downloaded repositories
│       ├── splunk_security_content/
│       ├── sigma/
│       ├── defender_hunting/
│       └── index.json           # Search index
├── genai/
│   ├── query_examples.py        # Repository manager
│   ├── query_prompt_enhancer.py # Prompt enhancement
│   └── models.py                # LLM interface
├── build/
│   ├── queries.py               # Template-based generation
│   └── queries_enhanced.py      # Enhanced generation
└── mappings/
    ├── schemaSplunk.json        # Org-specific Splunk fields
    └── schemaMDE.json           # Org-specific MDE fields
```

## Setup

### 1. Install Dependencies

The query learning system requires Git for cloning repositories:

```bash
# Verify git is installed
git --version

# Install Python dependencies (already in requirements.txt)
pip install pyyaml requests beautifulsoup4
```

### 2. Download Query Examples

```bash
# Clone all supported repositories
python scripts/manage_query_examples.py update

# This downloads:
# - Splunk Security Content (~200MB)
# - SigmaHQ Sigma Rules (~100MB)
# - Defender Hunting Queries (~10MB)
```

### 3. Build the Index

```bash
# Parse repositories and build search index
python scripts/manage_query_examples.py rebuild

# This creates:
# - Technique-to-example mappings
# - Vendor-specific indices
# - Platform categorization
# - Statistics
```

### 4. Enable Enhanced Generation

```bash
# Enable enhanced query generation
export ARCHER_ENHANCED_QUERIES=true

# Or add to .env file
echo "ARCHER_ENHANCED_QUERIES=true" >> .env

# Verify
python scripts/manage_query_examples.py test
```

## Usage

### CLI Management

```bash
# Update repositories (git pull)
python scripts/manage_query_examples.py update

# Rebuild index after updates
python scripts/manage_query_examples.py rebuild

# View statistics
python scripts/manage_query_examples.py stats

# Search for technique examples
python scripts/manage_query_examples.py search T1003
python scripts/manage_query_examples.py search T1003 splunk  # Filter by vendor

# Test the system
python scripts/manage_query_examples.py test
```

### Programmatic Usage

```python
from archer.genai.query_examples import get_repository

# Get repository instance
repo = get_repository()

# Search for examples
examples = repo.get_examples_for_technique(
    technique_id="T1003",
    vendor="splunk",  # Optional: splunk, mde, sigma
    limit=5
)

# Each example contains:
# - name: Detection name
# - description: What it detects
# - query: The actual query
# - techniques: MITRE ATT&CK technique IDs
# - tactics: MITRE ATT&CK tactics
# - platforms: Target platforms (Windows, Linux, etc.)
# - vendor: SIEM vendor
# - severity: Detection severity
# - data_sources: Required data sources

for example in examples:
    print(f"{example['name']} ({example['vendor']})")
    print(f"Query: {example['query'][:100]}...")
```

### Enhanced Query Generation

Once enabled, enhanced generation happens automatically during detection generation:

```bash
# Generate detections for a threat group
python cli.py build-correlations "Scattered Spider"

# Enhanced queries will be used automatically if:
# 1. ARCHER_ENHANCED_QUERIES=true
# 2. Repository is indexed
# 3. Relevant examples exist
# 4. LLM is available

# Output will show:
#   "Using GenAI to generate KQL query for T1003 (cmd)"
#   "✓ Generated enhanced KQL query"
```

### How It Works

When generating a detection for technique T1003 (OS Credential Dumping):

**1. Search for Examples**
```python
# System searches index for T1003
examples = [
    {
        "name": "Detect Credential Dumping with LSASS Access",
        "query": "index=windows sourcetype=WinEventLog:Security EventCode=4656 Object_Name=*lsass.exe*...",
        "techniques": ["T1003"],
        ...
    },
    {
        "name": "LSASS Memory Dump via ProcDump",
        "query": "DeviceProcessEvents | where FileName =~ 'procdump.exe' | where ProcessCommandLine has_any ('lsass', '-ma')...",
        "techniques": ["T1003"],
        ...
    }
]
```

**2. Build Enhanced Prompt**
```
# Task: Generate SPLUNK Detection Query

You are generating a detection query for the following MITRE ATT&CK technique:

**Technique**: T1003 - OS Credential Dumping
**Tactic**: Credential Access
**Description**: Adversaries may attempt to dump credentials...

**Indicators to Detect**:
  - lsass
  - procdump
  - mimikatz

## Field Schema for SPLUNK

Use these specific field names in your query (organizational schema):
  **index=windows_events**: EventCode, ComputerName, user, process_name, new_process_name, parent_process_name, process_command_line_arguments

## High-Quality Example Queries

Here are 2 professionally-written detection queries for similar techniques to guide your approach:

### Example 1: Detect Credential Dumping with LSASS Access
**Technique**: T1003
**Description**: Detects attempts to access LSASS process memory which may indicate credential dumping

**Query**:
```splunk
index=windows sourcetype=WinEventLog:Security EventCode=4656
Object_Name=*lsass.exe* Access_Mask=0x1010
| stats count by _time, ComputerName, SubjectUserName, ProcessName
| where count > 1
```

**Key Patterns**:
- Uses index: windows
- Filters on fields: EventCode, Object_Name, Access_Mask
- Uses stats for aggregation and grouping
...

## Best Practices for SPLUNK Queries

1. **Index Selection**: Always specify the correct index
2. **Time Window**: Use earliest=-1d for recent events
...

## Your Task

Generate a SPLUNK query that:
1. Detects the indicators listed above for technique T1003
2. Uses the organizational field schema provided
...

Generate the query now:
```

**3. LLM Generation**

The LLM sees:
- Real examples of how professionals write this detection
- Your organization's field names
- Best practices for the SIEM platform
- The specific indicators to detect

Result: Much higher quality, more accurate queries that follow best practices and use correct field names.

## Schema Integration

### Splunk Schema (schemaSplunk.json)

The system uses your organizational Splunk field mappings to ensure generated queries use the correct field names:

```json
{
  "cmd": {
    "windows_events": "| fields EventCode, process_name, process_command_line_arguments, parent_process_name...",
    "edr_events": "| fields DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName..."
  },
  "reg": {
    "edr_events": "| fields RegistryKey, RegistryValueData, PreviousRegistryKey..."
  }
}
```

These field templates are injected into prompts so the LLM generates queries using YOUR field names, not generic ones.

### Microsoft Defender Schema (schemaMDE.json)

Similar mapping for MDE/KQL queries:

```json
{
  "cmd": {
    "DeviceProcessEvents": ["ProcessCommandLine", "FileName", "AccountName"],
    "DeviceEvents": ["AdditionalFields"]
  },
  "reg": {
    "DeviceRegistryEvents": ["RegistryKey", "RegistryValueData"]
  }
}
```

## Benefits

### 1. Higher Quality Queries

**Before** (Template-based):
```splunk
index=windows_events earliest=-1d
("process_command_line_arguments"="*lsass*" OR "process_command_line_arguments"="*procdump*")
| stats count BY user ComputerName process_name
```

**After** (Enhanced with Examples):
```splunk
index=windows_events sourcetype=WinEventLog:Security earliest=-1d
(
  (EventCode=4688 AND (process_command_line_arguments="*lsass*" OR process_command_line_arguments="*procdump*" OR process_command_line_arguments="*mimikatz*"))
  OR
  (EventCode=4656 AND Object_Name="*lsass.exe*" AND Access_Mask IN ("0x1010", "0x1438"))
)
| eval suspicious_flags=if(match(process_command_line_arguments, "(?i)(dump|lsass|memory)"), 1, 0)
| stats count, values(process_command_line_arguments) as commands, max(suspicious_flags) as has_suspicious_flags BY _time, ComputerName, user, process_name, parent_process_name
| where count > 0 AND has_suspicious_flags=1
| table _time, ComputerName, user, process_name, parent_process_name, commands, count
```

### 2. Best Practice Patterns

Examples teach the system:
- Proper EventCode usage (4688 for process creation, 4656 for handle access)
- Multiple detection angles (process command line + object access)
- Appropriate aggregation and filtering
- Field selection for analyst triage
- Performance optimization (early filtering)

### 3. Reduced False Positives

By learning from production queries that have been refined over time, the system generates more precise detections that balance coverage with noise reduction.

### 4. Platform-Specific Idioms

**Splunk**:
- `sourcetype` for data source specification
- `stats values()` for multi-value fields
- `eval` for calculated fields
- Proper pipe command ordering

**KQL/MDE**:
- `has_any` / `has_all` for efficient string matching
- `summarize` for aggregation
- `extend` for calculated columns
- `ago()` for time filtering
- Case-insensitive operators (`=~`)

### 5. Organizational Consistency

All queries use YOUR field names from YOUR schema, ensuring:
- Queries work in your environment immediately
- No need to manually map fields
- Consistent naming across all generated detections

## Troubleshooting

### No Examples Found

```bash
# Check if index is built
python scripts/manage_query_examples.py stats

# If "Total Examples: 0", rebuild:
python scripts/manage_query_examples.py rebuild

# Check for specific technique
python scripts/manage_query_examples.py search T1003
```

### Git Clone Fails

```bash
# Manual clone as fallback
cd archer/data/query_examples
git clone --depth 1 https://github.com/splunk/security_content.git splunk_security_content
git clone --depth 1 https://github.com/SigmaHQ/sigma.git sigma
git clone --depth 1 https://github.com/francoisfried/Defender-Advanced-Hunting-Queries.git defender_hunting

# Then rebuild
python scripts/manage_query_examples.py rebuild
```

### Enhanced Generation Not Working

```bash
# Run diagnostic
python scripts/manage_query_examples.py test

# Check environment variable
echo $ARCHER_ENHANCED_QUERIES

# Enable if not set
export ARCHER_ENHANCED_QUERIES=true

# Check if LLM is available
python -c "from archer.genai.models import get_generator; print(get_generator('local'))"
```

### Queries Still Using Templates

This is normal and expected:
- System falls back to templates if no examples found for a technique
- Some techniques are rare and may not have examples
- Fallback ensures generation always succeeds
- Check logs for "⚠" warning messages

## Performance

- **Initial Setup**: ~5-10 minutes (clone + index ~300MB of repos)
- **Index Size**: ~50MB JSON index
- **Search Speed**: <100ms per technique lookup
- **Memory**: +100-200MB for loaded index
- **Query Generation**: Adds ~2-5s per query (LLM inference)

For large-scale generation (100+ techniques), the time increase is acceptable given the quality improvement.

## Maintenance

### Update Repositories

```bash
# Update repositories monthly for latest detections
python scripts/manage_query_examples.py update
python scripts/manage_query_examples.py rebuild

# Or force re-clone
python scripts/manage_query_examples.py update --force
python scripts/manage_query_examples.py rebuild
```

### Monitor Statistics

```bash
# Track coverage growth
python scripts/manage_query_examples.py stats

# Example output:
# Total Examples: 4,523
# Examples by Vendor:
#   splunk: 1,234
#   mde: 856
#   sigma: 2,433
# MITRE ATT&CK Techniques Covered: 187
```

## Future Enhancements

Potential improvements:

1. **Vector Database Integration**: Use embeddings for semantic search instead of exact technique ID matching
2. **Example Ranking**: Score examples by quality, recency, complexity
3. **Cross-Platform Translation**: Learn patterns from one SIEM and apply to another
4. **Technique Clustering**: Find examples from similar techniques when exact match not found
5. **User Feedback Loop**: Track which generated queries are deployed and learn from them
6. **Custom Repository Support**: Allow users to add their own internal query repositories

## Related Documentation

- [DIRECTORY_STRUCTURE.md](../DIRECTORY_STRUCTURE.md) - Archer directory organization
- [genai/README.md](../archer/genai/README.md) - GenAI engine documentation
- [Query Generation Flow](../archer/build/README.md) - Detection generation pipeline

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Splunk Security Content](https://github.com/splunk/security_content)
- [SigmaHQ](https://github.com/SigmaHQ/sigma)
- [Microsoft Defender Queries](https://github.com/francoisfried/Defender-Advanced-Hunting-Queries)
- [Few-Shot Learning](https://en.wikipedia.org/wiki/Few-shot_learning)
