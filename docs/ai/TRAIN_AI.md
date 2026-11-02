# Shikari Training Data Collection Scripts

> **Status (2026-10-16):** some of what this document names was never built: none of its scripts, but the dataset files it shows are examples of output, not files in the repository. What exists: `scripts/config/` (`setup_knowledge_base.py`, `import_community_rules.py`, `build_embeddings.py`, `search_similar_detections.py`, `validate_detections.py`, `quickstart_rag.py`), `scripts/ai/` (`setup_local_llm.py`, `train_ai.py`), `scripts/data/` and `scripts/validation/`: see [SCRIPTS.md](../SCRIPTS.md).

## Table of Contents

- [train_ai.py](#train_aipy)
  - [Commands](#commands)
    - [1. CVE Enrichment (`cve`)](#1-cve-enrichment-cve)
    - [2. Threat Report Conversion (`reports`)](#2-threat-report-conversion-reports)
    - [3. OSINT Extraction (`osint`)](#3-osint-extraction-osint)
    - [4. Custom High-Fidelity Queries (`custom`)](#4-custom-high-fidelity-queries-custom)
- [Quick Examples](#quick-examples)
  - [Collect High-Impact CVEs](#collect-high-impact-cves)
  - [Convert Threat Reports](#convert-threat-reports)
  - [Extract OSINT Data](#extract-osint-data)
  - [Add Custom High-Fidelity Queries](#add-custom-high-fidelity-queries)
  - [Complete Workflow](#complete-workflow)
  - [Custom Queries Only Workflow](#custom-queries-only-workflow)
  - [Complete End-to-End Example](#complete-end-to-end-example)
- [Directory Structure](#directory-structure)
- [Training Data Format Specification](#training-data-format-specification)
  - [Custom Query Training Format (JSONL)](#custom-query-training-format-jsonl)
  - [Multi-Platform Custom Query Example](#multi-platform-custom-query-example)
  - [Correlation Training Format](#correlation-training-format)
  - [Field Descriptions](#field-descriptions)
- [Manual JSONL Creation](#manual-jsonl-creation)
- [Training Configuration Options](#training-configuration-options)
  - [Basic Training (LoRA Fine-Tuning)](#basic-training-lora-fine-tuning)
  - [Memory-Efficient Training (4-bit Quantization)](#memory-efficient-training-4-bit-quantization)
  - [Multi-Task Training](#multi-task-training)
  - [Platform-Specific Training](#platform-specific-training)
- [Few-Shot Learning (No Fine-Tuning)](#few-shot-learning-no-fine-tuning)
- [Validation and Testing](#validation-and-testing)
- [Troubleshooting](#troubleshooting)
  - [CVE Enrichment](#cve-enrichment)
  - [Report Conversion](#report-conversion)
  - [OSINT Extraction](#osint-extraction)
  - [Custom Query Import](#custom-query-import)
- [Best Practices](#best-practices)
- [Additional Resources](#additional-resources)

---

## train_ai.py

Unified script for collecting training data from multiple sources for LLM fine-tuning.

### Commands

#### 1. CVE Enrichment (`cve`)

Enrich CVE data with blog posts, exploits, and technical analysis.

```bash
# Enrich specific CVEs
python scripts/ai/train_ai.py cve --cves CVE-2024-1234 CVE-2024-5678

# Enrich CVEs from a specific year
python scripts/ai/train_ai.py cve --year 2024 --min-cvss 7.0 --limit 50

# Enrich only CVEs with in-the-wild exploitation
python scripts/ai/train_ai.py cve --year 2024 --itw-only --min-cvss 8.0

# Enrich from file (one CVE per line)
python scripts/ai/train_ai.py cve --file priority_cves.txt

# Specify output directory
python scripts/ai/train_ai.py cve --cves CVE-2024-1234 --output custom_output/
```

**Options**:
- `--cves`: Specific CVE IDs to enrich
- `--year`: Fetch CVEs from specific year
- `--file`: File with CVE IDs (one per line)
- `--min-cvss`: Minimum CVSS score (default: 0.0)
- `--limit`: Maximum CVEs to process
- `--itw-only`: Only CVEs with ITW exploitation
- `--output`: Output directory

**Output**:
- `cache/`: Raw CVE data from NVD
- `enriched/`: Enriched CVEs with blog posts and analysis
- `training_examples/`: Training examples in JSONL format

#### 2. Threat Report Conversion (`reports`)

Convert PDF threat reports to JSON format.

```bash
# Convert single PDF
python scripts/ai/train_ai.py reports --pdf threat_report.pdf

# Batch convert directory of PDFs
python scripts/ai/train_ai.py reports --dir reports/

# Specify output directory
python scripts/ai/train_ai.py reports --dir reports/ --output custom_output/
```

**Requirements**: `pip install pdfplumber`

**Options**:
- `--pdf`: Single PDF file to convert
- `--dir`: Directory with PDF files (batch mode)
- `--output`: Output directory

**Output**: JSON files with extracted text, CVEs, threat groups, and techniques

#### 3. OSINT Extraction (`osint`)

Extract detection rules from OSINT repositories.

```bash
# Extract Elastic detection rules
python scripts/ai/train_ai.py osint --source elastic

# Extract Splunk security content
python scripts/ai/train_ai.py osint --source splunk

# Extract from all sources
python scripts/ai/train_ai.py osint --all

# Use custom repository
python scripts/ai/train_ai.py osint --source elastic --repo https://github.com/custom/detection-rules-fork

# Specify output directory
python scripts/ai/train_ai.py osint --all --output custom_output/
```

**Requirements**: `pip install pyyaml toml`

**Options**:
- `--source`: OSINT source (elastic, splunk)
- `--repo`: Custom repository URL
- `--all`: Extract from all sources
- `--output`: Output directory

**Output**: JSONL files with detection rules in training format

#### 4. Custom High-Fidelity Queries (`custom`)

Add your proprietary, battle-tested detection queries for AI training. Unlike OSINT queries, these are your organization's custom-built, high-fidelity detections.

```bash
# Create custom training data from interactive prompts
python scripts/ai/train_ai.py custom --interactive

# Import from existing query file (JSON/YAML)
python scripts/ai/train_ai.py custom --import queries.json

# Import from directory of query files
python scripts/ai/train_ai.py custom --import-dir custom_queries/

# Validate custom training data format
python scripts/ai/train_ai.py custom --validate hunting_queries/

# Specify output directory
python scripts/ai/train_ai.py custom --interactive --output custom_output/
```

**Options**:
- `--interactive`: Interactive mode to add queries one-by-one
- `--import`: Import from single JSON/YAML file
- `--import-dir`: Batch import from directory
- `--validate`: Validate existing training data format
- `--output`: Output directory (default: shikari/ai/training/datasets/hunting_queries/)

**Input Format** (JSON/YAML):
```json
{
  "queries": [
    {
      "name": "Suspicious PowerShell Web Download",
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "platforms": ["Windows"],
      "platform": "MDE",
      "query": "DeviceProcessEvents\n| where FileName =~ \"powershell.exe\"\n| where ProcessCommandLine has_any (\"DownloadFile\", \"IEX\", \"Invoke-WebRequest\")",
      "description": "Detects PowerShell downloading files from the internet",
      "false_positive_rate": "low",
      "severity": "high",
      "data_sources": ["Process: Process Creation", "Command: Command Execution"],
      "rationale": "This query has been tuned over 6 months with minimal FPs in production",
      "threat_context": "Commonly used by APT29 for initial payload delivery"
    }
  ]
}
```

**Template**: See [CUSTOM_QUERY_TEMPLATE.json](../examples/CUSTOM_QUERY_TEMPLATE.json) for a complete template with all available fields

**Output**: Training examples in JSONL format at `shikari/ai/training/datasets/hunting_queries/`

## Quick Examples

### Collect High-Impact CVEs

```bash
# Enrich Log4Shell and other critical CVEs
python scripts/ai/train_ai.py cve \
    --cves CVE-2021-44228 CVE-2021-26855 CVE-2021-34527 CVE-2020-1472

# Enrich top 100 critical CVEs from 2024
python scripts/ai/train_ai.py cve --year 2024 --min-cvss 9.0 --limit 100
```

### Convert Threat Reports

```bash
# Convert all PDFs in threat_reports directory
python scripts/ai/train_ai.py reports --dir shikari/ai/training/datasets/threat_reports/
```

### Extract OSINT Data

```bash
# Extract from all OSINT sources
python scripts/ai/train_ai.py osint --all
```

### Add Custom High-Fidelity Queries

```bash
# Add your proprietary detections interactively
python scripts/ai/train_ai.py custom --interactive

# Or import from existing files
python scripts/ai/train_ai.py custom --import-dir custom_queries/
```

### Complete Workflow

```bash
# 1. Enrich CVEs
python scripts/ai/train_ai.py cve --year 2024 --min-cvss 7.0 --limit 50

# 2. Convert threat reports
python scripts/ai/train_ai.py reports --dir reports/

# 3. Extract OSINT samples
python scripts/ai/train_ai.py osint --all

# 4. Add your custom high-fidelity queries
python scripts/ai/train_ai.py custom --import-dir custom_queries/

# 5. Train model with collected data (including your custom queries)
python -m shikari.ai.training.pipelines.training \
    --data shikari/ai/training/datasets/ \
    --model llama3.1:70b \
    --epochs 5
```

### Custom Queries Only Workflow

```bash
# Train exclusively on your proprietary detections (no OSINT data)
# 1. Add custom queries
python scripts/ai/train_ai.py custom --import-dir custom_queries/

# 2. Train only on custom data
python -m shikari.ai.training.pipelines.training \
    --data shikari/ai/training/datasets/hunting_queries/ \
    --model llama3.1:70b \
    --epochs 5 \
    --task detection_generation
```

### Complete End-to-End Example

```bash
# Step 1: Create custom query file
cat > /tmp/my_custom_queries.json << 'EOF'
{
  "queries": [
    {
      "name": "High-Fidelity Kerberoasting",
      "technique_id": "T1558.003",
      "technique_name": "Kerberoasting",
      "platforms": ["Windows"],
      "platform": "MDE",
      "query": "DeviceEvents\n| where ActionType == \"KerberosServiceTicketRequested\"\n| where ServiceName endswith \"$\" == false\n| summarize Services=make_set(ServiceName), Count=count() by AccountName, DeviceName, bin(Timestamp, 5m)\n| where Count > 5",
      "description": "Detects Kerberoasting by identifying accounts requesting multiple service tickets in short time",
      "false_positive_rate": "very_low",
      "severity": "high",
      "rationale": "Tuned threshold eliminates legitimate service account activity",
      "threat_context": "Used by APT29, FIN7, and ransomware operators for privilege escalation"
    },
    {
      "name": "Anomalous PowerShell Execution from Office",
      "technique_id": "T1566.001",
      "technique_name": "Spearphishing Attachment",
      "platforms": ["Windows"],
      "platform": "MDE",
      "query": "DeviceProcessEvents\n| where InitiatingProcessFileName in~ (\"winword.exe\", \"excel.exe\", \"powerpnt.exe\")\n| where FileName =~ \"powershell.exe\"\n| where ProcessCommandLine has_any (\"http\", \"downloadstring\", \"iex\")\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName",
      "description": "Detects Office applications spawning PowerShell with download/execution patterns",
      "false_positive_rate": "low",
      "severity": "critical",
      "rationale": "Legitimate Office macros rarely spawn PowerShell with web download patterns",
      "threat_context": "Primary initial access vector for Emotet, QBot, and IcedID"
    }
  ]
}
EOF

# Step 2: Import custom queries
python scripts/ai/train_ai.py custom --import /tmp/my_custom_queries.json

# Step 3: Validate the imported data
python scripts/ai/train_ai.py custom --validate shikari/ai/training/datasets/hunting_queries/

# Step 4: Train the model with LoRA
python -m shikari.ai.training.pipelines.training \
    --data shikari/ai/training/datasets/hunting_queries/ \
    --model llama3.1:70b \
    --epochs 5 \
    --lora \
    --lora-rank 16 \
    --learning-rate 2e-4 \
    --batch-size 4 \
    --task detection_generation

# Step 5: Test the trained model
python -m shikari.ai.training.pipelines.llm_inference \
    --model-path shikari/ai/training/models/llama3.1-70b-lora/ \
    --technique T1558.003 \
    --platform MDE

# Step 6: Evaluate model performance
python -m shikari.ai.training.pipelines.evaluate \
    --model-path shikari/ai/training/models/llama3.1-70b-lora/ \
    --test-data shikari/ai/training/datasets/test_set.jsonl
```

## Directory Structure

After running all commands, your data structure will look like:

```
shikari/ai/training/datasets/
├── cve_data/
│   ├── cache/              # Raw CVE data
│   ├── enriched/           # Enriched with blog posts
│   └── training_examples/  # Training JSONL
├── threat_reports/
│   ├── *.pdf              # Original PDFs
│   └── *.json             # Converted JSON
├── osint_samples/
│   ├── elastic_rules.jsonl
│   └── splunk_rules.jsonl
├── hunting_queries/        # Custom high-fidelity queries
│   ├── custom_detections.jsonl
│   ├── apt_detections.jsonl
│   └── platform_specific/
│       ├── mde_queries.jsonl
│       ├── splunk_queries.jsonl
│       └── sentinel_queries.jsonl
├── correlations/           # Multi-stage detection logic
│   └── custom_correlations.jsonl
└── blog_posts/
    └── *.json             # Manually added blog posts
```

## Troubleshooting

### CVE Enrichment

**Issue**: No blog posts found
- **Solution**: Add blog posts manually to `shikari/ai/training/datasets/blog_posts/`

**Issue**: NVD rate limit
- **Solution**: Add delays between requests or use cached data

### Report Conversion

**Issue**: pdfplumber import error
- **Solution**: `pip install pdfplumber`

**Issue**: PDF extraction quality poor
- **Solution**: Use OCR tools for scanned PDFs

### OSINT Extraction

**Issue**: git clone fails
- **Solution**: Check network connection and repository URL

**Issue**: Missing dependencies
- **Solution**: `pip install pyyaml toml`

**Issue**: Parse errors
- **Solution**: Update to latest repository version

### Custom Query Import

**Issue**: JSON validation error
- **Solution**: Validate JSON syntax using `jq . < your_file.json` or online validator

**Issue**: Missing required fields
- **Solution**: Ensure all required fields are present: `technique_id`, `technique_name`, `platforms`, `platform`, `query`

**Issue**: JSONL format error
- **Solution**: Each line must be a complete JSON object. Use `jq -c` to compact JSON to single lines

**Issue**: Training data not being used
- **Solution**: Verify file is in correct directory and has `.jsonl` extension

**Issue**: Model not improving with custom data
- **Solution**:
  - Ensure you have at least 20-50 high-quality examples
  - Increase epochs (try 10-15 for small datasets)
  - Check training logs for loss metrics
  - Validate examples are diverse across different techniques

## Best Practices

1. **Start with High-Impact CVEs**: Focus on critical CVEs with public exploits
2. **Validate Enriched Data**: Review enriched CVEs before adding to training
3. **Add Manual Detections**: Enrichment creates templates - add actual queries
4. **Organize by Priority**: Process ITW exploits first
5. **Track Metrics**: Monitor CVEs processed, blog posts per CVE, detection coverage
6. **Custom Queries Over OSINT**: Prioritize your battle-tested detections for training
7. **Document Rationale**: Include why each custom query has high fidelity
8. **Platform-Specific Training**: Organize custom queries by target SIEM/EDR platform
9. **Include Threat Context**: Add threat actor TTPs and real-world usage to custom queries
10. **Test Before Training**: Validate all custom queries in production before adding to training data

## Training Data Format Specification

### Custom Query Training Format (JSONL)

Each line in your training file should be a complete JSON object:

```json
{
  "task": "detection_generation",
  "input": {
    "technique_id": "T1003.001",
    "technique_name": "LSASS Memory",
    "description": "Adversaries may attempt to access credential material stored in LSASS memory",
    "platforms": ["Windows"],
    "threat_intel": "Used by FIN6, APT28, and Lazarus Group for credential dumping",
    "cve_data": null
  },
  "output": {
    "detections": [
      {
        "name": "High-Fidelity LSASS Memory Access",
        "description": "Detects non-system processes accessing LSASS memory with specific access rights indicating credential dumping",
        "platform": "MDE",
        "query": "DeviceEvents\n| where ActionType == \"OpenProcess\"\n| where AdditionalFields.TargetProcessName =~ \"lsass.exe\"\n| where AdditionalFields.DesiredAccess has_any (\"0x1010\", \"0x1410\", \"0x1438\")\n| where InitiatingProcessFileName !in~ (\"taskmgr.exe\", \"procexp64.exe\")\n| where InitiatingProcessFolderPath !startswith \"C:\\\\Windows\\\\System32\\\\\"",
        "false_positive_rate": "low",
        "severity": "critical",
        "data_sources": ["Process: OS API Execution"],
        "rationale": "Tuned over 12 months with specific access rights that minimize false positives. Excludes known admin tools and system processes.",
        "threat_context": "This pattern matches Mimikatz, ProcDump, and custom credential dumpers",
        "mitigations": ["Credential Access Protection", "LSA Protection", "PPL for LSASS"],
        "detection_requirements": ["MDE P2 or Defender for Endpoint"]
      }
    ]
  }
}
```

### Multi-Platform Custom Query Example

```json
{
  "task": "detection_generation",
  "input": {
    "technique_id": "T1053.005",
    "technique_name": "Scheduled Task",
    "description": "Adversaries may abuse task scheduling to execute programs",
    "platforms": ["Windows"],
    "threat_intel": "Common persistence mechanism used by ransomware operators"
  },
  "output": {
    "detections": [
      {
        "name": "Suspicious Scheduled Task Creation",
        "platform": "MDE",
        "query": "DeviceProcessEvents\n| where FileName =~ \"schtasks.exe\"\n| where ProcessCommandLine has \"/create\"\n| where ProcessCommandLine has_any (\"/ru system\", \"/ru administrator\")\n| where InitiatingProcessFileName !in~ (\"installer.exe\", \"setup.exe\")",
        "false_positive_rate": "low",
        "severity": "medium"
      },
      {
        "name": "Suspicious Scheduled Task Creation",
        "platform": "Splunk",
        "query": "index=windows sourcetype=WinEventLog:Security EventCode=4698\n| where TaskContent LIKE \"%SYSTEM%\" OR TaskContent LIKE \"%ADMINISTRATOR%\"\n| where NOT [| inputlookup legitimate_installers.csv | fields ProcessName]\n| stats count by Computer, TaskName, UserName, ProcessName",
        "false_positive_rate": "low",
        "severity": "medium"
      },
      {
        "name": "Suspicious Scheduled Task Creation",
        "platform": "Sentinel",
        "query": "SecurityEvent\n| where EventID == 4698\n| where EventData has \"SYSTEM\" or EventData has \"ADMINISTRATOR\"\n| where InitiatingProcessName !in~ (\"installer.exe\", \"setup.exe\")\n| project TimeGenerated, Computer, Account, TaskName, CommandLine",
        "false_positive_rate": "low",
        "severity": "medium"
      }
    ]
  }
}
```

### Correlation Training Format

For multi-stage detections:

```json
{
  "task": "correlation_generation",
  "input": {
    "technique_ids": ["T1078.004", "T1136.003", "T1087.003"],
    "attack_pattern": "Account Discovery followed by Account Creation",
    "description": "Detect adversary performing account enumeration before creating new accounts",
    "platforms": ["Windows", "Azure AD"]
  },
  "output": {
    "correlation": {
      "name": "Account Enumeration to Creation",
      "description": "Correlates account discovery activities with subsequent account creation from the same source",
      "stages": [
        {
          "stage": 1,
          "technique_id": "T1087.003",
          "query": "AADSignInEventsBeta\n| where ErrorCode == 50126\n| where ResultType == \"Failure\"\n| summarize FailedAttempts=count() by IPAddress, Timestamp=bin(TimeGenerated, 5m)",
          "threshold": "FailedAttempts > 10"
        },
        {
          "stage": 2,
          "technique_id": "T1136.003",
          "query": "AuditLogs\n| where OperationName == \"Add user\"\n| where ResultType == \"Success\"\n| extend IPAddress = tostring(parse_json(InitiatedBy).user.ipAddress)",
          "correlation_key": "IPAddress",
          "time_window": "30m"
        }
      ],
      "false_positive_rate": "very_low",
      "severity": "high"
    }
  }
}
```

### Field Descriptions

**Required Fields**:
- `task`: Type of training task (`detection_generation`, `correlation_generation`, `report_generation`)
- `input.technique_id`: MITRE ATT&CK technique ID
- `input.technique_name`: Human-readable technique name
- `input.platforms`: Target platforms (Windows, Linux, macOS, Azure AD, AWS, etc.)
- `output.detections[].name`: Detection rule name
- `output.detections[].platform`: SIEM/EDR platform (MDE, Splunk, Sentinel, Elastic, Google SecOps, etc.)
- `output.detections[].query`: The actual detection query

**Recommended Fields**:
- `false_positive_rate`: `very_low`, `low`, `medium`, `high`
- `severity`: `informational`, `low`, `medium`, `high`, `critical`
- `rationale`: Why this query has high fidelity
- `threat_context`: Real-world threat actor usage
- `data_sources`: MITRE ATT&CK data sources
- `detection_requirements`: Platform features or license requirements

**Optional Fields**:
- `mitigations`: Associated MITRE mitigations
- `threat_intel`: Threat intelligence context
- `cve_data`: Associated CVE information
- `tags`: Custom categorization tags
- `author`: Query author
- `version`: Query version
- `last_validated`: Date query was last tested

## Manual JSONL Creation

If you prefer to manually create JSONL files without using the `custom` command:

```bash
# Create directory structure
mkdir -p shikari/ai/training/datasets/hunting_queries/platform_specific

# Create JSONL file (each line is one complete JSON object)
cat > shikari/ai/training/datasets/hunting_queries/mde_custom.jsonl << 'EOF'
{"task":"detection_generation","input":{"technique_id":"T1059.001","technique_name":"PowerShell","platforms":["Windows"]},"output":{"detections":[{"name":"Encoded PowerShell Command","platform":"MDE","query":"DeviceProcessEvents\n| where FileName =~ \"powershell.exe\"\n| where ProcessCommandLine has_any (\"-enc\", \"-encodedcommand\")\n| where ProcessCommandLine !contains \"Microsoft.Graph\"","false_positive_rate":"low","severity":"high"}]}}
{"task":"detection_generation","input":{"technique_id":"T1003.001","technique_name":"LSASS Memory","platforms":["Windows"]},"output":{"detections":[{"name":"LSASS Memory Dump","platform":"MDE","query":"DeviceEvents\n| where ActionType == \"OpenProcess\"\n| where AdditionalFields.TargetProcessName =~ \"lsass.exe\"","false_positive_rate":"low","severity":"critical"}]}}
EOF
```

## Training Configuration Options

### Basic Training (LoRA Fine-Tuning)

```bash
python -m shikari.ai.training.pipelines.training \
    --data shikari/ai/training/datasets/hunting_queries/ \
    --model llama3.1:70b \
    --epochs 5 \
    --lora \
    --lora-rank 16 \
    --lora-alpha 32 \
    --learning-rate 2e-4 \
    --batch-size 4 \
    --task detection_generation
```

### Memory-Efficient Training (4-bit Quantization)

```bash
python -m shikari.ai.training.pipelines.training \
    --data shikari/ai/training/datasets/hunting_queries/ \
    --model llama3.1:70b \
    --epochs 3 \
    --lora \
    --quantization 4bit \
    --batch-size 2 \
    --gradient-accumulation-steps 8 \
    --task detection_generation
```

### Multi-Task Training

```bash
# Train on both detection generation and correlation
python -m shikari.ai.training.pipelines.training \
    --data shikari/ai/training/datasets/ \
    --model llama3.1:70b \
    --epochs 5 \
    --lora \
    --task detection_generation correlation_generation
```

### Platform-Specific Training

```bash
# Train only on MDE queries
python -m shikari.ai.training.pipelines.training \
    --data shikari/ai/training/datasets/hunting_queries/platform_specific/mde_queries.jsonl \
    --model llama3.1:70b \
    --epochs 5 \
    --task detection_generation \
    --platform MDE
```

## Few-Shot Learning (No Fine-Tuning)

If you want to use your custom queries without full model training:

```bash
# Add queries to database for few-shot learning
python -m shikari.ai.training.pipelines.ingest_examples \
    --data shikari/ai/training/datasets/hunting_queries/ \
    --rating high \
    --source custom
```

This adds your queries to the database where they'll be automatically used as examples in prompts.

## Validation and Testing

```bash
# Validate training data format
python scripts/ai/train_ai.py custom --validate shikari/ai/training/datasets/hunting_queries/

# Test trained model
python -m shikari.ai.training.pipelines.evaluate \
    --model-path shikari/ai/training/models/llama3.1-70b-lora/ \
    --test-data shikari/ai/training/datasets/test_set.jsonl

# Generate sample detections with trained model
python -m shikari.ai.training.pipelines.llm_inference \
    --model-path shikari/ai/training/models/llama3.1-70b-lora/ \
    --technique T1059.001 \
    --platform MDE
```

## Additional Resources

- [AI Model Configuration Guide](MODEL_CONFIGURATION.md) - **Start here to configure AI models**
- [CVE Enrichment Workflow](../features/CVE_ENRICHMENT.md)
- [LLM Detection Generation Guide](LLM_DETECTION_GENERATION.md)
- [CVE Data README](../../shikari/ai/training/datasets/cve_data/README.md)
- [AI Training Architecture](AI_TRAINING.md)
