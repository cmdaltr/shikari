# How Query Learning Works - Technical Deep Dive

## Table of Contents

1. [Overview](#overview)
2. [The Problem We're Solving](#the-problem-were-solving)
3. [Few-Shot Learning Explained](#few-shot-learning-explained)
4. [System Architecture](#system-architecture)
5. [Step-by-Step Process Flow](#step-by-step-process-flow)
6. [Example Walkthrough](#example-walkthrough)
7. [Why This Approach Works](#why-this-approach-works)
8. [Enhancing the System](#enhancing-the-system)
9. [Performance Considerations](#performance-considerations)
10. [Advanced Topics](#advanced-topics)

---

## Overview

The Query Learning System uses **few-shot learning** to improve detection query generation. Instead of relying purely on templates or hoping an LLM "knows" how to write good security queries, we show the LLM examples of professionally-written queries and ask it to follow those patterns.

**Core Concept**: If you show an AI 2-3 examples of how experts solve a problem, it can solve similar problems much better than if you just describe the problem.

---

## The Problem We're Solving

### Traditional Template-Based Generation

**Before** this system, Archer generated queries using templates:

```python
# Template approach (simplified)
def generate_splunk_query(indicators, index):
    conditions = " OR ".join([f'field="*{ind}*"' for ind in indicators])
    return f"""index={index} earliest=-1d
({conditions})
| stats count BY user ComputerName"""
```

**Problems**:
- ❌ Generic, one-size-fits-all approach
- ❌ Doesn't know which EventCodes are relevant
- ❌ Misses detection opportunities (e.g., object access events)
- ❌ Poor filtering → high false positives
- ❌ Doesn't follow platform-specific best practices

### LLM Without Examples

Even with an LLM, if you just ask "generate a Splunk query to detect lsass access", results are inconsistent:
- ❌ May use wrong field names (your org uses custom fields)
- ❌ May miss platform idioms (stats vs table, has_any vs contains)
- ❌ May generate syntactically correct but operationally poor queries
- ❌ No consistency across generated queries

### Few-Shot Learning Solution

**With examples**, the LLM sees:
- ✅ Real queries from Splunk Security Content team
- ✅ YOUR organization's field names from schemaSplunk.json
- ✅ Multiple detection angles (process + object access)
- ✅ Proper aggregation and filtering patterns
- ✅ Platform-specific functions and operators

Result: **Professional-quality queries that work in your environment**

---

## Few-Shot Learning Explained

### What is Few-Shot Learning?

Few-shot learning is when a model learns to perform a task from just a few examples, rather than thousands of training samples.

**Analogy**: Teaching someone to write detection rules
- **Zero-shot**: "Write a query to detect credential dumping" (no examples)
- **Few-shot**: "Here are 3 queries that detect credential dumping. Now write one for this new indicator."

### Why It Works for LLMs

Modern LLMs (like GPT, Claude, Llama) have:
1. **Broad pre-training**: Seen lots of code, including security queries
2. **Pattern recognition**: Can identify common structures and idioms
3. **In-context learning**: Can adapt their output based on examples in the prompt

When you show an LLM examples, it:
1. Identifies the pattern (structure, syntax, field names)
2. Extracts the "style" (verbosity, operators, functions used)
3. Applies that pattern to the new task
4. Generates output that matches the examples

### Few-Shot vs Fine-Tuning

| Approach | Training Required | Examples Needed | Flexibility | Best For |
|----------|------------------|-----------------|-------------|----------|
| **Fine-tuning** | Yes (GPU, hours/days) | 1000s | Low (model locked) | Specialized, static use cases |
| **Few-shot** | No | 2-5 per task | High (change examples anytime) | Dynamic, varied use cases |

**Why we chose few-shot**:
- ✅ No training infrastructure needed
- ✅ Can add new examples instantly
- ✅ Examples update as repositories update
- ✅ Different examples for each technique
- ✅ Works with any LLM (local or API)

---

## System Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Query Learning System                         │
└─────────────────────────────────────────────────────────────────┘

1. REPOSITORY LAYER
   ┌────────────────────┐
   │ GitHub Repos       │
   │ - Splunk Security  │
   │ - SigmaHQ          │
   │ - Defender Hunting │
   └────────┬───────────┘
            │ git clone
            ↓
   ┌────────────────────┐
   │ Local Storage      │
   │ archer/data/       │
   │ query_examples/    │
   └────────┬───────────┘
            │

2. INDEXING LAYER
            │ parse & extract
            ↓
   ┌────────────────────┐
   │ Query Parser       │
   │ - Extract metadata │
   │ - Find techniques  │
   │ - Detect platform  │
   └────────┬───────────┘
            │ build index
            ↓
   ┌────────────────────┐
   │ Search Index       │
   │ {                  │
   │   "T1003": [       │
   │     {example1},    │
   │     {example2}     │
   │   ]                │
   │ }                  │
   └────────┬───────────┘
            │

3. RETRIEVAL LAYER
            │ query by technique
            ↓
   ┌────────────────────┐
   │ Example Selector   │
   │ - Match technique  │
   │ - Filter by vendor │
   │ - Rank by quality  │
   └────────┬───────────┘
            │ relevant examples
            ↓

4. PROMPT ENGINEERING LAYER
   ┌────────────────────┐
   │ Prompt Builder     │
   │ - Inject examples  │
   │ - Add schema       │
   │ - Add best practices│
   └────────┬───────────┘
            │ enhanced prompt
            ↓

5. GENERATION LAYER
   ┌────────────────────┐
   │ LLM                │
   │ - Llama-cpp        │
   │ - OpenAI           │
   │ - Local model      │
   └────────┬───────────┘
            │ generated query
            ↓

6. VALIDATION LAYER
   ┌────────────────────┐
   │ Query Validator    │
   │ - Syntax check     │
   │ - Structure check  │
   │ - Fallback if fail │
   └────────┬───────────┘
            │ validated query
            ↓
   ┌────────────────────┐
   │ YAML Detection     │
   │ Rule Created       │
   └────────────────────┘
```

### Key Files and Their Roles

| File | Purpose | Key Functions |
|------|---------|---------------|
| **query_examples.py** | Repository management | `update_repositories()`, `rebuild_index()`, `get_examples_for_technique()` |
| **query_prompt_enhancer.py** | Prompt engineering | `enhance_query_generation_prompt()`, `_get_schema_info()`, `_extract_key_patterns()` |
| **queries_enhanced.py** | Enhanced generation | `compile_mde_queries_enhanced()`, `compile_splunk_queries_enhanced()`, validation |
| **schemaSplunk.json** | Org field mappings | Field name templates for each index |
| **schemaMDE.json** | MDE field mappings | Field name templates for each table |
| **manage_query_examples.py** | CLI interface | Commands for setup and maintenance |

---

## Step-by-Step Process Flow

### Detailed Flow with Code References

#### Step 1: User Triggers Detection Generation

```bash
python cli.py build-correlations "Scattered Spider"
```

**What happens**:
- CLI calls `archer/build/orchestrator.py::process_group()`
- Orchestrator retrieves procedures for the group from MITRE ATT&CK
- For each technique, calls `compile_query()` in `detections.py`

#### Step 2: Query Generation Initiated

In `archer/build/detections.py`:

```python
def compile_query(retrieved_data):
    name = retrieved_data.get("technique")  # "OS Credential Dumping"
    tid = retrieved_data.get("technique_id")  # "T1003"
    identifiers = {**op_guidance, **red_tool}  # {"cmd": ["lsass", "procdump"]}

    # Calls enhanced query builders if enabled
    mde_queries = compile_mde_queries(
        indicator_mapping, indicators, indicator_type, mde_queries,
        technique_id=tid,  # T1003
        technique_name=name,
        technique_description=tdesc,
        tactic=tactic
    )
```

#### Step 3: Check if Enhancement is Enabled

In `archer/build/queries_enhanced.py`:

```python
def compile_splunk_queries_enhanced(...):
    # Check environment variable
    if not ENHANCED_QUERIES_ENABLED:
        return _compile_splunk_queries_basic(...)  # Fallback to template

    # Check if we have context (technique info)
    if not technique_id or not technique_name:
        return _compile_splunk_queries_basic(...)  # Need context for examples

    # Try to get enhancer and LLM
    enhancer = _get_enhancer()
    llm_generator = _get_llm_generator()

    if not enhancer or not llm_generator:
        return _compile_splunk_queries_basic(...)  # Fallback
```

#### Step 4: Search for Relevant Examples

In `archer/genai/query_examples.py`:

```python
def get_examples_for_technique(self, technique_id: str, vendor: str = None, limit: int = 5):
    # Normalize technique ID
    technique_id = technique_id.upper()  # "T1003"

    # Lookup in index
    examples = self.index.get("techniques", {}).get(technique_id, [])
    # Returns: [
    #   {
    #     "name": "Detect Credential Dumping via LSASS Access",
    #     "query": "index=windows EventCode=4656 Object_Name=*lsass*...",
    #     "techniques": ["T1003"],
    #     "vendor": "splunk",
    #     ...
    #   },
    #   ...
    # ]

    # Filter by vendor if specified
    if vendor:
        examples = [e for e in examples if e.get("vendor") == vendor.lower()]

    return examples[:limit]  # Return top N
```

**Index Structure**:
```json
{
  "techniques": {
    "T1003": [
      {
        "id": "abc123",
        "source": "splunk_security_content",
        "name": "Detect Credential Dumping via LSASS Access",
        "query": "index=windows sourcetype=WinEventLog:Security EventCode=4656...",
        "techniques": ["T1003"],
        "tactics": ["Credential Access"],
        "vendor": "splunk",
        "platforms": ["Windows"],
        "severity": "high",
        "description": "Detects access to LSASS process memory..."
      },
      ...
    ],
    "T1059": [...],
    ...
  },
  "tactics": {
    "Credential Access": [...],
    ...
  },
  "vendors": {
    "splunk": [...],
    "mde": [...],
    ...
  }
}
```

#### Step 5: Load Organizational Schema

In `archer/genai/query_prompt_enhancer.py`:

```python
def _load_schemas(self):
    # Load schemaSplunk.json
    schema_path = self.schema_dir / "schemaSplunk.json"
    with open(schema_path, "r") as f:
        self.schemas["splunk"] = json.load(f)

    # Schema structure:
    # {
    #   "cmd": {
    #     "windows_events": "| fields EventCode, process_name, process_command_line_arguments...",
    #     "edr_events": "| fields DeviceName, FileName, ProcessCommandLine..."
    #   },
    #   "reg": {...}
    # }

def _get_schema_info(self, vendor: str, indicator_type: str):
    schema = self.schemas.get(vendor, {})
    indicator_schema = schema.get(indicator_type, {})

    # Extract field names from templates
    for index, fields in indicator_schema.items():
        field_names = self._extract_field_names_from_spl(fields)
        # Returns: ["EventCode", "process_name", "process_command_line_arguments", ...]

    return formatted_schema_info
```

#### Step 6: Build Enhanced Prompt

In `archer/genai/query_prompt_enhancer.py`:

```python
def enhance_query_generation_prompt(
    self,
    technique_id: str,        # "T1003"
    technique_name: str,      # "OS Credential Dumping"
    technique_description: str,
    vendor: str,              # "splunk"
    indicator_type: str,      # "cmd"
    indicators: List[str],    # ["lsass", "procdump", "mimikatz"]
    tactic: str = None,
    num_examples: int = 3
):
    # 1. Get relevant examples
    examples = self.repository.get_examples_for_technique(
        technique_id, vendor=vendor, limit=num_examples
    )

    # 2. Get organizational schema
    schema_info = self._get_schema_info(vendor, indicator_type)

    # 3. Build prompt with sections:
    prompt = f"""
# Task: Generate {vendor.upper()} Detection Query

**Technique**: {technique_id} - {technique_name}
**Tactic**: {tactic}
**Description**: {technique_description}

**Indicators to Detect**:
{format_indicators(indicators)}

## Field Schema for {vendor.upper()}
{schema_info}

## High-Quality Example Queries

### Example 1: {examples[0]['name']}
**Query**:
```{vendor}
{examples[0]['query']}
```
**Key Patterns**:
{self._extract_key_patterns(examples[0]['query'], vendor)}

### Example 2: {examples[1]['name']}
...

## Best Practices for {vendor.upper()} Queries
1. Index Selection: Always specify correct index
2. Time Window: Use earliest=-1d
3. Wildcard Matching: Use "*term*" for substring matching
...

## Your Task
Generate a {vendor.upper()} query that:
1. Detects the indicators listed above
2. Uses the organizational field schema
3. Follows the patterns shown in examples
...

Generate the query now:
"""

    return prompt
```

#### Step 7: LLM Generates Query

The complete prompt (now ~15,000 characters with examples) is sent to the LLM:

```python
# In queries_enhanced.py
result = llm_generator.generate_query(prompt, vendor="splunk")

# LLM sees:
# - Task description with technique T1003
# - Indicators to detect: lsass, procdump, mimikatz
# - YOUR field names: EventCode, process_command_line_arguments, etc.
# - 2-3 real examples of how experts detect this
# - Best practices for Splunk SPL
# - Instruction to follow the patterns

# LLM generates:
generated_query = """
index=windows_events sourcetype=WinEventLog:Security earliest=-1d
(
  (EventCode=4688 AND (process_command_line_arguments="*lsass*" OR process_command_line_arguments="*procdump*" OR process_command_line_arguments="*mimikatz*"))
  OR
  (EventCode=4656 AND Object_Name="*lsass.exe*" AND Access_Mask IN ("0x1010", "0x1438"))
)
| eval suspicious_flags=if(match(process_command_line_arguments, "(?i)(dump|lsass|memory)"), 1, 0)
| stats count, values(process_command_line_arguments) as commands BY _time, ComputerName, user, process_name
| where count > 0 AND suspicious_flags=1
| table _time, ComputerName, user, process_name, commands
"""
```

**What the LLM learned from examples**:
1. ✅ Use EventCode 4688 (process creation) AND 4656 (object access)
2. ✅ Multiple detection angles for better coverage
3. ✅ Use `eval` for calculated fields
4. ✅ `stats values()` to aggregate multi-value fields
5. ✅ Filter with `where` after aggregation
6. ✅ Select useful fields for analyst triage
7. ✅ Use exact field names from YOUR schema

#### Step 8: Validate Generated Query

In `archer/build/queries_enhanced.py`:

```python
def _validate_splunk_query(query: str) -> bool:
    # Check structure
    if not query.startswith("index="):
        return False  # Invalid

    # Check time window
    if "earliest=" not in query:
        return False  # Missing time filter

    # Check has search terms
    if "=" not in query[20:]:  # Skip index= part
        return False  # No conditions

    return True  # Valid

if _validate_splunk_query(generated_query):
    splunk_queries.append(generated_query)
    print("✓ Generated enhanced Splunk query")
else:
    print("⚠ Validation failed, using template")
    return _compile_splunk_queries_basic(...)  # Fallback
```

#### Step 9: Create YAML Detection Rule

Back in `archer/build/yaml.py`:

```python
def construct_yaml(name, tid, tdesc, tactic, tag, identifiers, ...):
    # Query is now in appended_splunk_queries
    for query in appended_splunk_queries:
        yamlfile = os.path.join("data", "generate", f"{name}_{index}.yaml")
        write_yaml(
            yamlfile,
            name,          # "OSCredentialDumping"
            tid,           # "T1003"
            tdesc,
            "Splunk",      # connectorId
            all_tactics,
            tag,           # "Scattered Spider (Group)"
            query          # Our enhanced query
        )
```

**Final YAML** (`data/generate/OSCredentialDumping_windows_events.yaml`):
```yaml
id: 12345-abcde-67890
name: OSCredentialDumping
description: |
  Adversaries may attempt to dump credentials to obtain account login...
severity: High
requiredDataConnectors:
  - connectorId: Splunk
    dataTypes:
      - microsoft_windows
tactics:
  - Credential Access
tags:
  - Scattered Spider (Group)
query: |
  index=windows_events sourcetype=WinEventLog:Security earliest=-1d
  (
    (EventCode=4688 AND (process_command_line_arguments="*lsass*" OR ...))
    OR
    (EventCode=4656 AND Object_Name="*lsass.exe*" AND Access_Mask IN ("0x1010", "0x1438"))
  )
  | eval suspicious_flags=if(match(process_command_line_arguments, "(?i)(dump|lsass)"), 1, 0)
  | stats count, values(process_command_line_arguments) as commands BY _time, ComputerName, user
  | where count > 0 AND suspicious_flags=1
version: 1.0
```

---

## Example Walkthrough

Let's trace a complete example from start to finish.

### Scenario: Detect T1003 - OS Credential Dumping for "Scattered Spider"

#### Input
- **Threat Group**: Scattered Spider
- **Technique**: T1003 - OS Credential Dumping
- **Indicators**: `["lsass", "procdump", "mimikatz"]`
- **Target SIEM**: Splunk
- **Indicator Type**: `cmd` (command-line)

#### Process

**1. Repository Search**

```python
# System searches index
examples = repo.get_examples_for_technique("T1003", vendor="splunk", limit=2)

# Returns 2 examples from Splunk Security Content:
[
  {
    "name": "Detect Credential Dumping via LSASS Access",
    "query": """index=windows sourcetype=WinEventLog:Security EventCode=4656
                Object_Name=*lsass.exe* Access_Mask=0x1010
                | stats count by ComputerName, SubjectUserName, ProcessName
                | where count > 1""",
    "description": "Detects attempts to access LSASS process memory",
    "techniques": ["T1003"],
    "vendor": "splunk"
  },
  {
    "name": "Credential Dumping via Procdump",
    "query": """index=windows sourcetype=WinEventLog:Security EventCode=4688
                NewProcessName=*procdump* CommandLine=*lsass*
                | eval suspicious=if(match(CommandLine, "(?i)(-ma|dump)"), 1, 0)
                | stats values(CommandLine) as cmds by ComputerName, User
                | where suspicious=1""",
    "description": "Detects use of procdump to dump lsass",
    "techniques": ["T1003"],
    "vendor": "splunk"
  }
]
```

**2. Schema Loading**

```python
# From schemaSplunk.json
schema = {
  "cmd": {
    "windows_events": """
      | fields EventCode, ComputerName, user, process_name,
        new_process_name, parent_process_name, process_command_line_arguments
    """
  }
}

# Extract field names
fields = ["EventCode", "ComputerName", "user", "process_name",
          "new_process_name", "parent_process_name",
          "process_command_line_arguments"]
```

**3. Prompt Construction**

```text
# Task: Generate SPLUNK Detection Query

You are generating a detection query for the following MITRE ATT&CK technique:

**Technique**: T1003 - OS Credential Dumping
**Tactic**: Credential Access
**Description**: Adversaries may attempt to dump credentials to obtain
account login and credential material, normally in the form of a hash or
a clear text password, from the operating system and software.

**Indicators to Detect**:
  - lsass
  - procdump
  - mimikatz

## Field Schema for SPLUNK

Use these specific field names in your query (organizational schema):
  **index=windows_events**: EventCode, ComputerName, user,
    process_name, new_process_name, parent_process_name,
    process_command_line_arguments

## High-Quality Example Queries

Here are 2 professionally-written detection queries for similar techniques
to guide your approach:

### Example 1: Detect Credential Dumping via LSASS Access
**Technique**: T1003
**Description**: Detects attempts to access LSASS process memory which may
indicate credential dumping

**Query**:
```splunk
index=windows sourcetype=WinEventLog:Security EventCode=4656
Object_Name=*lsass.exe* Access_Mask=0x1010
| stats count by ComputerName, SubjectUserName, ProcessName
| where count > 1
```

**Key Patterns**:
- Uses index: windows
- Filters on fields: EventCode, Object_Name, Access_Mask
- Uses stats for aggregation and grouping
- Filters results with where clause

### Example 2: Credential Dumping via Procdump
**Technique**: T1003
**Description**: Detects use of procdump to dump lsass memory

**Query**:
```splunk
index=windows sourcetype=WinEventLog:Security EventCode=4688
NewProcessName=*procdump* CommandLine=*lsass*
| eval suspicious=if(match(CommandLine, "(?i)(-ma|dump)"), 1, 0)
| stats values(CommandLine) as cmds by ComputerName, User
| where suspicious=1
```

**Key Patterns**:
- Uses EventCode 4688 for process creation events
- Uses eval for calculated fields
- Uses regex matching with match()
- Aggregates with stats values()

## Best Practices for SPLUNK Queries

1. **Index Selection**: Always specify the correct index
   (e.g., index=windows_events)
2. **Time Window**: Use earliest=-1d for recent events
3. **Wildcard Matching**: Use "*term*" for substring matching in field values
4. **Field Extraction**: Use | fields to select relevant fields early
5. **Aggregation**: Use | stats to group and count matching events
6. **Multi-word Indicators**: For phrases, combine with AND:
   (field="*word1*" AND field="*word2*")
7. **Performance**: Filter by index and time first, then apply complex logic
8. **Field Names**: Use exact field names from the organizational schema above

**Common Splunk Fields (from schema)**:
- Process execution: process_name, new_process_name,
  process_command_line_arguments, parent_process_name
- User context: user
- System: ComputerName
- Event IDs: EventCode

## Your Task

Generate a SPLUNK query that:
1. Detects the indicators listed above for technique T1003
2. Uses the organizational field schema provided
3. Follows the best practices and patterns shown in the examples
4. Combines multiple indicators with appropriate logic
   (OR for alternatives, AND for required combinations)
5. Filters by relevant time windows and system fields
6. Returns useful fields for security analyst triage

**Important**:
- Use ONLY the field names from the organizational schema
- Follow the query structure patterns from the examples
- Ensure the query is syntactically correct and performant
- Include comments explaining the detection logic

Generate the query now:
```

**(Prompt is ~15,000 characters total)**

**4. LLM Processing**

The LLM (e.g., Llama 3 8B, GPT-4, Claude) processes this prompt and generates:

```splunk
index=windows_events sourcetype=WinEventLog:Security earliest=-1d
(
  (EventCode=4688 AND (process_command_line_arguments="*lsass*" OR process_command_line_arguments="*procdump*" OR process_command_line_arguments="*mimikatz*"))
  OR
  (EventCode=4656 AND Object_Name="*lsass.exe*" AND Access_Mask IN ("0x1010", "0x1438"))
)
| eval suspicious_flags=if(match(process_command_line_arguments, "(?i)(dump|lsass|memory|mimikatz|procdump)"), 1, 0)
| stats count, values(process_command_line_arguments) as commands, max(suspicious_flags) as has_suspicious_flags BY _time, ComputerName, user, process_name, parent_process_name
| where count > 0 AND has_suspicious_flags=1
| table _time, ComputerName, user, process_name, parent_process_name, commands, count
```

**What the LLM learned**:
1. From Example 1: Use EventCode 4656 for object access to lsass.exe
2. From Example 2: Use EventCode 4688 for process creation events
3. From Example 2: Use `eval` with `match()` for pattern detection
4. From both: Use `stats` with `values()` to aggregate
5. From schema: Use exact field names (process_command_line_arguments, not CommandLine)
6. From best practices: Include multiple indicators with OR
7. From best practices: Filter early, aggregate, then filter again

**5. Validation**

```python
valid = _validate_splunk_query(query)
# Checks:
# ✓ Starts with "index="
# ✓ Contains "earliest="
# ✓ Has search conditions
# → Returns True
```

**6. YAML Creation**

```yaml
id: abc-123-def-456
name: OSCredentialDumping
description: Adversaries may attempt to dump credentials...
severity: High
requiredDataConnectors:
  - connectorId: Splunk
    dataTypes:
      - microsoft_windows
tactics:
  - Credential Access
tags:
  - Scattered Spider (Group)
query: |
  index=windows_events sourcetype=WinEventLog:Security earliest=-1d
  (
    (EventCode=4688 AND (process_command_line_arguments="*lsass*" OR ...))
    OR
    (EventCode=4656 AND Object_Name="*lsass.exe*" AND Access_Mask IN ("0x1010", "0x1438"))
  )
  | eval suspicious_flags=if(match(process_command_line_arguments, "(?i)(dump|lsass|memory)"), 1, 0)
  | stats count, values(process_command_line_arguments) as commands BY _time, ComputerName, user, process_name
  | where count > 0 AND suspicious_flags=1
  | table _time, ComputerName, user, process_name, commands
version: 1.0
kind: Scheduled
source: Archer
author: ben
```

**Result**: Professional-quality detection rule ready for deployment!

---

## Why This Approach Works

### 1. Pattern Recognition

LLMs excel at recognizing and replicating patterns. When shown:
- Structure: `index=X | filter | stats | where`
- Syntax: `stats values(field) as alias BY groupfield`
- Idioms: `eval suspicious=if(match(...), 1, 0)`

They can apply these patterns to new scenarios consistently.

### 2. Field Name Learning

**Problem**: Your organization uses custom field names:
- You: `process_command_line_arguments`
- Generic: `CommandLine` or `ProcessCommandLine`

**Solution**: Schema in prompt ensures LLM uses YOUR names:
```text
## Field Schema for SPLUNK
  **index=windows_events**: EventCode, ComputerName, user,
    process_name, process_command_line_arguments
```

LLM sees this and uses `process_command_line_arguments` in all generated queries.

### 3. Best Practice Transfer

Examples encode years of security expertise:
- Which EventCodes are relevant (4688, 4656 for credential access)
- Multiple detection angles (process + object access)
- Proper aggregation (stats before where)
- Scoring mechanisms (eval with match)
- Field selection for triage (user, computer, process, command)

### 4. Quality Consistency

Every generated query follows professional patterns because:
- Examples are from production security teams
- LLM mimics the structure and style
- Schema ensures correct field names
- Validation catches errors

### 5. Reduced False Positives

Examples show how to filter properly:
```splunk
| where count > 1  # Only alert on repeated attempts
| where suspicious_flags=1  # Only suspicious patterns
```

This knowledge transfers to new queries, reducing noise.

---

## Enhancing the System

The Query Learning System can be significantly improved by adding more data sources and capabilities. Here's how to enhance it:

### 1. Adding New Repository Sources

#### Currently Integrated:
- ✅ Splunk Security Content
- ✅ SigmaHQ Sigma Rules
- ✅ Microsoft Defender Hunting Queries

#### High-Value Additions:

**Elastic Detection Rules**
```python
# In archer/genai/query_examples.py, add to self.repositories:
"elastic_detection_rules": {
    "url": "https://github.com/elastic/detection-rules.git",
    "path": self.base_dir / "elastic_detection_rules",
    "type": "git",
    "parser": self._parse_elastic_detection_rules,
}

def _parse_elastic_detection_rules(self, repo_path: Path) -> List[Dict]:
    """Parse Elastic Detection Rules repository."""
    examples = []
    rules_dir = repo_path / "rules"

    for toml_file in rules_dir.rglob("*.toml"):
        # Parse TOML format rules
        # Extract EQL queries and metadata
        # Map to MITRE ATT&CK
        ...

    return examples
```

**Why**: Elastic has 1000+ production detection rules with EQL and KQL queries

**SOC Prime Threat Detection Marketplace**
```python
"soc_prime": {
    "url": "https://github.com/socprime/SigmaRules.git",
    "path": self.base_dir / "soc_prime",
    "type": "git",
    "parser": self._parse_soc_prime_rules,
}
```

**Why**: Additional high-quality Sigma rules from commercial vendor

**Palantir Alerting Detection Strategy**
```python
"palantir_ads": {
    "url": "https://github.com/palantir/alerting-detection-strategy-framework.git",
    "path": self.base_dir / "palantir_ads",
    "type": "git",
    "parser": self._parse_palantir_ads,
}
```

**Why**: Palantir's methodology for building detections

**Chronicle Detection Rules**
```python
"chronicle_rules": {
    "url": "https://github.com/chronicle/detection-rules.git",
    "path": self.base_dir / "chronicle_rules",
    "type": "git",
    "parser": self._parse_chronicle_rules,
}
```

**Why**: Google Chronicle (YARA-L) detection rules

**Panther Analysis**
```python
"panther_analysis": {
    "url": "https://github.com/panther-labs/panther-analysis.git",
    "path": self.base_dir / "panther_analysis",
    "type": "git",
    "parser": self._parse_panther_analysis,
}
```

**Why**: Python-based detections from Panther SIEM

#### How to Add a New Repository:

1. **Add to repository definitions** (`archer/genai/query_examples.py`):
```python
self.repositories["new_repo_name"] = {
    "url": "https://github.com/org/repo.git",
    "path": self.base_dir / "new_repo_name",
    "type": "git",
    "parser": self._parse_new_repo,
}
```

2. **Implement parser method**:
```python
def _parse_new_repo(self, repo_path: Path) -> List[Dict]:
    examples = []

    # Find query files
    query_files = list(repo_path.rglob("*.ext"))

    for query_file in query_files:
        # Parse file format (JSON, YAML, TOML, etc.)
        data = parse_file(query_file)

        # Extract required fields
        example = {
            "id": generate_id(query_file),
            "source": "new_repo_name",
            "file": str(query_file.relative_to(repo_path)),
            "name": data.get("name", "Unknown"),
            "description": data.get("description", ""),
            "vendor": detect_vendor(data),  # splunk, mde, elastic, etc.
            "query": extract_query(data),
            "techniques": extract_techniques(data),  # ["T1003", "T1059"]
            "tactics": extract_tactics(data),  # ["Credential Access"]
            "platforms": detect_platforms(data),  # ["Windows", "Linux"]
            "data_sources": data.get("data_sources", []),
            "severity": data.get("severity", "medium"),
            "metadata": extract_metadata(data),
        }

        examples.append(example)

    return examples
```

3. **Run update and rebuild**:
```bash
python scripts/manage_query_examples.py update
python scripts/manage_query_examples.py rebuild
```

### 2. Adding Documentation-Based Learning

For resources that are documentation rather than code repositories:

**Elastic Blog Posts**
- Source: https://www.elastic.co/blog/elastic-security-building-effective-threat-hunting-detection-rules
- Implementation: Web scraping with pattern extraction

```python
def _scrape_elastic_blog_examples(self) -> List[Dict]:
    """Scrape query examples from Elastic blog posts."""

    blog_urls = [
        "https://www.elastic.co/blog/elastic-security-building-effective-threat-hunting-detection-rules",
        # Add more blog post URLs
    ]

    examples = []
    for url in blog_urls:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find code blocks with EQL/KQL
        code_blocks = soup.find_all('code', class_='language-eql')
        code_blocks += soup.find_all('code', class_='language-kql')

        for block in code_blocks:
            query = block.get_text()

            # Extract context from surrounding text
            context = extract_context_from_blog(block)

            example = {
                "source": "elastic_blog",
                "name": context.get("title", "Elastic Blog Example"),
                "query": query,
                "vendor": "elastic",
                "techniques": extract_techniques_from_text(context.get("text", "")),
                ...
            }
            examples.append(example)

    return examples
```

**KQL Query Articles**
- Source: https://kqlquery.com/posts/from-threat-report-to-hunting-query/
- Source: https://systemweakness.com/50-threat-hunting-queries-splunk-kql-every-analyst-should-know-ca82c1e5abe0

```python
def _scrape_kql_articles(self) -> List[Dict]:
    """Scrape hunting queries from KQL articles."""

    article_urls = {
        "https://kqlquery.com/posts/from-threat-report-to-hunting-query/": "kqlquery.com",
        "https://systemweakness.com/50-threat-hunting-queries-splunk-kql-every-analyst-should-know-ca82c1e5abe0": "systemweakness"
    }

    examples = []
    for url, source in article_urls.items():
        # Scrape and parse
        # Extract both Splunk and KQL examples
        # Map to techniques based on article content
        ...

    return examples
```

### 3. Custom Internal Repository Support

Allow users to add their own organization's queries:

```python
# In query_examples.py
def add_custom_repository(self, name: str, path: Path, parser_func):
    """Add a custom repository from local directory."""

    self.repositories[name] = {
        "url": None,  # Local only
        "path": path,
        "type": "local",
        "parser": parser_func,
    }

    # Re-index with new repository
    self.rebuild_index()

# Usage:
repo = get_repository()

def parse_my_org_queries(repo_path: Path) -> List[Dict]:
    # Parse your organization's query format
    ...

repo.add_custom_repository(
    name="my_org_queries",
    path=Path("/path/to/internal/queries"),
    parser_func=parse_my_org_queries
)
```

**Configuration file approach**:

Create `archer/mappings/custom_repositories.json`:
```json
{
  "repositories": [
    {
      "name": "internal_splunk_queries",
      "path": "/secure/shared/splunk_detections",
      "type": "local",
      "vendor": "splunk",
      "format": "yaml"
    },
    {
      "name": "internal_kql_queries",
      "path": "/secure/shared/mde_hunting",
      "type": "local",
      "vendor": "mde",
      "format": "kql"
    }
  ]
}
```

Then load automatically:
```python
def _load_custom_repositories(self):
    config_file = self.schema_dir / "custom_repositories.json"
    if config_file.exists():
        with open(config_file) as f:
            config = json.load(f)

        for repo_config in config["repositories"]:
            self.add_custom_repository(
                name=repo_config["name"],
                path=Path(repo_config["path"]),
                parser_func=self._get_parser_for_format(repo_config["format"])
            )
```

### 4. Example Quality Ranking

Not all examples are equal. Add ranking system:

```python
def _rank_examples(self, examples: List[Dict]) -> List[Dict]:
    """Rank examples by quality metrics."""

    for example in examples:
        score = 0

        # Factor 1: Source reputation
        source_scores = {
            "splunk_security_content": 10,
            "elastic_detection_rules": 10,
            "sigma": 8,
            "defender_hunting": 7,
            "custom": 5,
        }
        score += source_scores.get(example["source"], 5)

        # Factor 2: Completeness
        if example.get("description"):
            score += 2
        if len(example.get("techniques", [])) > 0:
            score += 2
        if example.get("metadata", {}).get("author"):
            score += 1

        # Factor 3: Query complexity (sweet spot)
        query_lines = len(example["query"].split("\n"))
        if 5 <= query_lines <= 20:  # Not too simple, not too complex
            score += 3

        # Factor 4: Recency
        date_str = example.get("metadata", {}).get("date", "")
        if date_str:
            try:
                from datetime import datetime
                date = datetime.fromisoformat(date_str)
                age_years = (datetime.now() - date).days / 365
                if age_years < 1:
                    score += 3
                elif age_years < 2:
                    score += 2
                elif age_years < 3:
                    score += 1
            except:
                pass

        # Factor 5: Specificity
        if len(example.get("techniques", [])) == 1:  # Very specific
            score += 2

        example["quality_score"] = score

    # Sort by score
    return sorted(examples, key=lambda x: x.get("quality_score", 0), reverse=True)

# Update retrieval to use ranking
def get_examples_for_technique(self, technique_id, vendor=None, limit=5):
    examples = self.index.get("techniques", {}).get(technique_id, [])

    if vendor:
        examples = [e for e in examples if e.get("vendor") == vendor.lower()]

    # Rank before returning
    ranked_examples = self._rank_examples(examples)

    return ranked_examples[:limit]
```

### 5. Semantic Search with Embeddings

Move beyond exact technique matching to semantic similarity:

```python
# Add vector database support
import chromadb  # or faiss, pinecone, etc.

class QueryExampleRepository:
    def __init__(self, base_dir: str = None):
        ...
        # Initialize vector database
        self.chroma_client = chromadb.Client()
        self.collection = self.chroma_client.create_collection(
            name="query_examples",
            metadata={"hnsw:space": "cosine"}
        )

    def _embed_examples(self, examples: List[Dict]):
        """Generate embeddings for semantic search."""
        from sentence_transformers import SentenceTransformer

        model = SentenceTransformer('all-MiniLM-L6-v2')

        for example in examples:
            # Create text representation
            text = f"{example['name']} {example['description']} {example['query']}"

            # Generate embedding
            embedding = model.encode(text)

            # Store in vector DB
            self.collection.add(
                ids=[example['id']],
                embeddings=[embedding.tolist()],
                documents=[text],
                metadatas=[{
                    "technique": ",".join(example.get("techniques", [])),
                    "vendor": example["vendor"],
                    "source": example["source"]
                }]
            )

    def search_similar_examples(
        self,
        technique_description: str,
        vendor: str = None,
        limit: int = 5
    ) -> List[Dict]:
        """Find examples similar to technique description using semantic search."""

        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer('all-MiniLM-L6-v2')

        # Embed the query
        query_embedding = model.encode(technique_description)

        # Search vector DB
        results = self.collection.query(
            query_embeddings=[query_embedding.tolist()],
            n_results=limit * 2,  # Get more, then filter
            where={"vendor": vendor} if vendor else None
        )

        # Return matching examples
        return self._lookup_examples_by_ids(results['ids'][0])[:limit]
```

**Benefits**:
- Find examples even if technique ID not exact match
- "Credential dumping" → finds lsass, mimikatz, hashdump examples
- Cross-technique learning (similar TTPs)

### 6. Technique Clustering

Group similar techniques for broader matching:

```python
TECHNIQUE_CLUSTERS = {
    "credential_access": ["T1003", "T1552", "T1555", "T1558"],
    "lateral_movement": ["T1021", "T1091", "T1570"],
    "defense_evasion": ["T1070", "T1112", "T1562", "T1027"],
    ...
}

def get_examples_with_clustering(self, technique_id: str, vendor: str = None, limit: int = 5):
    """Get examples from technique and similar techniques in cluster."""

    # First try exact match
    examples = self.get_examples_for_technique(technique_id, vendor, limit)

    # If insufficient examples, expand to cluster
    if len(examples) < limit:
        cluster = self._find_cluster_for_technique(technique_id)
        if cluster:
            for related_technique in cluster:
                if related_technique != technique_id:
                    more_examples = self.get_examples_for_technique(
                        related_technique, vendor, limit - len(examples)
                    )
                    examples.extend(more_examples)
                    if len(examples) >= limit:
                        break

    return examples[:limit]
```

### 7. Cross-Platform Query Translation

Learn patterns from one SIEM and apply to another:

```python
def translate_query_pattern(self, source_vendor: str, target_vendor: str, technique_id: str):
    """Learn from one platform's queries to generate for another."""

    # Get examples from source vendor
    source_examples = self.get_examples_for_technique(technique_id, source_vendor, limit=3)

    # Extract patterns (fields, operators, logic)
    patterns = self._extract_cross_platform_patterns(source_examples)

    # Build prompt showing translation pattern
    prompt = f"""
Examples of how to detect {technique_id} in {source_vendor}:
{format_examples(source_examples)}

Now translate this pattern to {target_vendor}, using equivalent:
- Tables/indexes: {get_mapping(source_vendor, target_vendor)}
- Fields: {get_field_mapping(source_vendor, target_vendor)}
- Operators: {get_operator_mapping(source_vendor, target_vendor)}

Generate a {target_vendor} query following the same detection logic:
"""

    return prompt
```

### 8. User Feedback Loop

Track which generated queries are deployed and learn from them:

```python
def record_query_deployment(self, query_id: str, feedback: Dict):
    """Record when a generated query is deployed."""

    feedback_db = self.base_dir / "feedback.json"

    feedback_data = {
        "query_id": query_id,
        "deployed": True,
        "deployment_date": datetime.utcnow().isoformat(),
        "modified": feedback.get("was_modified", False),
        "modifications": feedback.get("modifications", ""),
        "effectiveness": feedback.get("effectiveness_score", None),  # 1-5
        "false_positive_rate": feedback.get("fp_rate", None),
    }

    # Save to feedback database
    save_feedback(feedback_db, feedback_data)

    # Use for future ranking
    self._update_example_scores_from_feedback()

def _update_example_scores_from_feedback(self):
    """Adjust example quality scores based on deployment feedback."""

    feedback_data = load_feedback(self.base_dir / "feedback.json")

    for feedback in feedback_data:
        # If queries generated from specific examples were successful,
        # boost those examples' quality scores
        if feedback["effectiveness"] and feedback["effectiveness"] >= 4:
            source_examples = self._find_examples_used_for_query(feedback["query_id"])
            for example_id in source_examples:
                self._boost_example_score(example_id, amount=2)
```

### 9. Multi-Modal Learning

Incorporate threat intelligence reports:

```python
def learn_from_threat_report(self, report_url: str) -> List[Dict]:
    """Extract detection patterns from threat intelligence reports."""

    # Fetch report
    report_text = fetch_and_parse_report(report_url)

    # Extract IOCs and TTPs
    iocs = extract_iocs(report_text)  # IPs, domains, hashes, etc.
    ttps = extract_techniques(report_text)  # MITRE ATT&CK references

    # Generate example queries for each TTP+IOC combination
    examples = []
    for ttp in ttps:
        for ioc in iocs:
            # Use existing examples as templates
            template_examples = self.get_examples_for_technique(ttp)

            # Adapt to specific IOCs from report
            adapted_query = adapt_query_to_iocs(template_examples[0], ioc)

            example = {
                "source": "threat_report",
                "name": f"Detect {ttp} with IOCs from {report_url}",
                "query": adapted_query,
                "techniques": [ttp],
                "iocs": [ioc],
                ...
            }
            examples.append(example)

    return examples
```

### 10. Performance Optimization

As the repository grows, optimize search:

```python
# Add caching
from functools import lru_cache

@lru_cache(maxsize=1000)
def get_examples_for_technique_cached(self, technique_id: str, vendor: str = None):
    """Cached version of example retrieval."""
    return self.get_examples_for_technique(technique_id, vendor)

# Add lazy loading
class LazyIndex:
    """Load index sections on-demand rather than all at once."""

    def __init__(self, index_file: Path):
        self.index_file = index_file
        self._techniques = None
        self._tactics = None

    @property
    def techniques(self):
        if self._techniques is None:
            # Load only techniques section
            with open(self.index_file) as f:
                full_index = json.load(f)
                self._techniques = full_index.get("techniques", {})
        return self._techniques

# Add compression
def save_index_compressed(self):
    """Save index with compression to reduce disk usage."""
    import gzip

    with gzip.open(f"{self.index_file}.gz", 'wt', encoding='utf-8') as f:
        json.dump(self.index, f, indent=2)
```

### Summary: Enhancement Roadmap

**Short-term (Easy Wins)**:
1. ✅ Add Elastic Detection Rules repository
2. ✅ Add SOC Prime Sigma rules
3. ✅ Implement example quality ranking
4. ✅ Add custom repository support

**Medium-term (Moderate Effort)**:
5. ⏳ Web scraping for blog/article examples
6. ⏳ Technique clustering for broader matches
7. ⏳ Cross-platform query translation
8. ⏳ User feedback loop

**Long-term (Advanced)**:
9. 🔮 Semantic search with embeddings
10. 🔮 Multi-modal learning from threat reports
11. 🔮 Automated pattern extraction from deployed queries
12. 🔮 Active learning (system suggests which techniques need more examples)

---

## Performance Considerations

### Resource Usage

| Component | Storage | Memory | CPU |
|-----------|---------|--------|-----|
| **Repositories** | ~300MB | - | - |
| **Index (JSON)** | ~50MB | ~200MB (loaded) | - |
| **Example Retrieval** | - | - | <100ms per lookup |
| **Prompt Building** | - | - | ~500ms |
| **LLM Generation** | - | 4-16GB (model) | 2-5s per query |
| **Total per Query** | - | ~5GB | ~3-6s |

### Optimization Strategies

**1. Index Optimization**
- Use compression (gzip) for on-disk storage
- Lazy-load index sections as needed
- Cache frequent technique lookups

**2. Prompt Optimization**
- Limit example length (first 1000 chars of query)
- Pre-compute key patterns during indexing
- Cache formatted schema strings

**3. LLM Optimization**
- Use smaller models for query generation (Llama 3 8B vs 70B)
- Quantization (4-bit or 8-bit) to reduce memory
- Batch processing for multiple techniques

**4. Parallel Processing**
- Generate queries for multiple techniques in parallel
- Pre-fetch examples while LLM is generating previous query
- Async I/O for repository updates

### Scaling Considerations

**For 100 Techniques**:
- Index lookup: ~10s total (parallel)
- Query generation: 5 min (sequential), 1 min (parallel with 5 workers)
- Total: ~1-5 minutes depending on parallelization

**For 1000 Techniques** (full ATT&CK):
- Would require distributed processing
- Consider pre-generating queries for common techniques
- Cache results for frequently-used threat groups

---

## Advanced Topics

### A. Prompt Engineering Techniques

The quality of generated queries heavily depends on prompt design:

**1. Structured Prompts**
```
# Task: [Clear objective]
[Context: Technique, indicators, etc.]

## Examples:
[2-3 relevant examples with annotations]

## Schema:
[Organizational field names]

## Best Practices:
[Platform-specific guidance]

## Task:
[Specific generation instructions]
```

**2. Chain-of-Thought**
Add reasoning step:
```
Before generating the query, explain:
1. Which examples are most relevant and why
2. Which field names from the schema you'll use
3. What detection logic you'll implement

Then generate the query.
```

**3. Self-Critique**
Ask LLM to validate its output:
```
After generating the query, review it for:
- Correct field names from schema
- Appropriate time window
- Proper aggregation
- Missing detection opportunities

If any issues found, regenerate.
```

### B. Multi-Turn Refinement

Instead of one-shot generation, iterate:

```python
def generate_query_with_refinement(self, technique_id, indicators, vendor):
    # Turn 1: Initial generation
    prompt1 = self.build_initial_prompt(technique_id, indicators, vendor)
    query_v1 = self.llm.generate(prompt1)

    # Turn 2: Critique
    prompt2 = f"""
Review this query:
{query_v1}

Issues:
- Field names correct? Check against schema
- Detection logic sound? Check against examples
- Performance optimized? Check filter ordering

Provide critique:
"""
    critique = self.llm.generate(prompt2)

    # Turn 3: Refinement
    prompt3 = f"""
Original query:
{query_v1}

Critique:
{critique}

Generate improved version:
"""
    query_v2 = self.llm.generate(prompt3)

    return query_v2
```

### C. Ensemble Methods

Use multiple models and combine:

```python
def generate_query_ensemble(self, technique_id, indicators, vendor):
    prompt = self.build_prompt(technique_id, indicators, vendor)

    # Generate with multiple models
    query_gpt4 = openai_generate(prompt)
    query_claude = anthropic_generate(prompt)
    query_llama = llama_generate(prompt)

    # Combine best parts
    # - Use GPT-4's structure
    # - Use Claude's field selection
    # - Use Llama's filtering logic

    combined = combine_queries([query_gpt4, query_claude, query_llama])
    return combined
```

### D. Active Learning

System identifies which techniques need better examples:

```python
def identify_low_coverage_techniques(self):
    """Find techniques with few or poor-quality examples."""

    low_coverage = []

    for technique_id in ALL_ATTACK_TECHNIQUES:
        examples = self.get_examples_for_technique(technique_id)

        if len(examples) == 0:
            low_coverage.append({
                "technique": technique_id,
                "reason": "no_examples",
                "priority": "high"
            })
        elif len(examples) < 3:
            low_coverage.append({
                "technique": technique_id,
                "reason": "few_examples",
                "priority": "medium"
            })
        elif avg_quality_score(examples) < 5:
            low_coverage.append({
                "technique": technique_id,
                "reason": "low_quality",
                "priority": "medium"
            })

    # Generate report
    report = f"""
Techniques Needing Better Examples:

HIGH PRIORITY (No Examples):
{format_techniques([t for t in low_coverage if t['priority'] == 'high'])}

MEDIUM PRIORITY (Few/Low Quality):
{format_techniques([t for t in low_coverage if t['priority'] == 'medium'])}

Recommendation: Prioritize creating or finding examples for high-priority techniques.
"""

    return report
```

### E. Continuous Improvement Pipeline

Automated system for keeping examples current:

```bash
#!/bin/bash
# scripts/update_query_learning.sh

# Run weekly via cron

echo "=== Weekly Query Learning Update ==="

# 1. Update repositories
python scripts/manage_query_examples.py update

# 2. Rebuild index
python scripts/manage_query_examples.py rebuild

# 3. Generate coverage report
python scripts/manage_query_examples.py coverage > reports/coverage_$(date +%Y%m%d).txt

# 4. Test quality on sample techniques
python scripts/test_query_quality.py > reports/quality_$(date +%Y%m%d).txt

# 5. Send report
mail -s "Query Learning Weekly Update" security-team@example.com < reports/quality_$(date +%Y%m%d).txt

echo "=== Update Complete ==="
```

---

## Conclusion

The Query Learning System transforms detection generation from template-based to intelligence-driven. By learning from thousands of professional security queries and respecting your organizational schema, it generates high-quality detections that:

- **Work immediately** in your environment (correct field names)
- **Follow best practices** (learned from experts)
- **Reduce false positives** (better filtering and aggregation)
- **Cover multiple angles** (process + object + network)
- **Scale efficiently** (few-shot learning, no training required)

The system is designed to be **extensible** - you can add new repositories, implement semantic search, incorporate threat intelligence, and build feedback loops to continuously improve quality.

**Next Steps**:
1. Set up the system: [QUICK_START_QUERY_LEARNING.md](QUICK_START_QUERY_LEARNING.md)
2. Add new repositories following the patterns in Section "Enhancing the System"
3. Customize for your organization's needs
4. Monitor and iterate based on deployment feedback

The more you invest in curating high-quality examples and tuning the system, the better your detection generation becomes. It's a virtuous cycle: better examples → better queries → better detections → learn from deployed queries → even better examples.
