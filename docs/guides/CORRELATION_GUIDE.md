# Correlation Query Builder

> **Quick Links**: [Usage](#usage) | [Configuration](#configuration) | [Examples](#examples) | [Module Reference](#module-reference)

## Overview

The Correlation Query Builder analyzes YAML detection files and automatically creates correlation searches by combining related queries. This helps identify sophisticated attack campaigns by requiring multiple detection patterns to fire, reducing false positives while improving detection confidence.

### Features

- **YAML Parsing**: Reads all YAML detection files and extracts queries with metadata
- **Relevance Assessment**: Calculates similarity scores based on:
  - Threat groups (40% weight) - queries targeting the same adversary groups
  - Platform compatibility (20% weight) - MDE vs Splunk
  - Attack tactics (30% weight) - overlapping MITRE ATT&CK tactics
  - Severity alignment (10% weight) - similar threat levels
- **Intelligent Grouping**: Automatically groups queries into logical correlation sets
- **Multi-Platform Support**: Generates correlation queries for both MDE (KQL) and Splunk
- **Query Summarization**: Creates human-readable summaries for each correlation
- **JSON Export**: Saves all correlations to a structured JSON file

### Module Structure

The correlation system is organized in the `archer/genai/` module:

```
archer/genai/
├── __init__.py    # Public API exports
├── engine.py      # Core correlation engine (1200+ lines)
└── models.py      # Optional AI providers (400+ lines)
```

- **engine.py**: Heuristic and advanced correlation generation
- **models.py**: AI-powered query combination (LocalLLMGenerator, RemoteAPIGenerator)

## Usage

### Via CLI (Recommended)

```bash
# Generate detections and run correlation together
python3 archer.py generate "APT29" --correlate

# Or build correlations separately
python3 archer.py correlate --verbose

# Specify custom paths
python3 archer.py correlate --yaml-dir ./my-detections --output ./results.json

# Require at least 3 queries per correlation
python3 archer.py correlate --min-queries 3
```

> **Note**: Correlation is now **opt-in**. Use `--correlate` flag with `generate` command or run `correlate` separately.

### Via Standalone Script

```bash
# Basic usage
python3 archer/parsers/correlations.py

# With options
python3 archer/parsers/correlations.py --yaml-dir ./detections --output ./correlations.json --min-queries 3 -v
```

### Programmatic Usage

```python
from archer.genai import build_correlation_queries

# Build correlations
result = build_correlation_queries(
    yaml_dir='data/queries',
    output_file='data/correlations/correlation_queries.json',
    min_queries=2
)

print(f"Generated {result['total_correlations']} correlations")
```

## Output Structure

The tool generates a JSON file with the following structure:

```json
{
  "generated_at": "2025-10-04 12:00:00",
  "total_queries_analyzed": 50,
  "total_correlations": 12,
  "min_queries_per_correlation": 2,
  "correlations": [
    {
      "correlation_id": "CORR-0001",
      "name": "Correlation: Query1 + Query2 + Query3",
      "summary": "Human-readable description...",
      "platform": "mde",
      "threat_groups": ["Scattered Spider", "APT29"],
      "tactics": ["Discovery", "Credential Access", "Lateral Movement"],
      "query_count": 3,
      "queries_included": [
        {
          "id": "uuid-1234",
          "name": "Suspicious PowerShell Activity",
          "file": "PowerShell_mde.yaml"
        }
      ],
      "combined_query": "// KQL or Splunk correlation query...",
      "relevance_scores": [
        {
          "query_pair": "Query1 <-> Query2",
          "score": 0.85
        }
      ]
    }
  ],
  "query_inventory": [
    {
      "id": "uuid-1234",
      "name": "Query Name",
      "platform": "mde",
      "tags": ["APT29"],
      "tactics": ["Discovery"],
      "severity": "High"
    }
  ]
}
```

## How It Works

### 1. YAML Parsing

The tool reads all `.yaml` and `.yml` files from the specified directory and extracts:
- Query ID and name
- Detection query (KQL or Splunk)
- Threat group tags
- MITRE ATT&CK tactics
- Platform/vendor (MDE or Splunk)
- Severity level

### 2. Relevance Scoring

For each pair of queries, the tool calculates a relevance score (0.0-1.0) based on:

```python
score = (tag_overlap * 0.4) +
        (platform_match * 0.2) +
        (tactic_overlap * 0.3) +
        (severity_alignment * 0.1)
```

### 3. Grouping

Queries are grouped by:
1. **Shared threat groups** (same adversary targets)
2. **Platform compatibility** (MDE or Splunk)
3. **Minimum query count** (configurable, default: 2)

### 4. Correlation Building

For each group, the tool generates a combined query:

**MDE/KQL Example:**
```kql
// Query 1
let query_1 = (
    DeviceProcessEvents
    | where ProcessCommandLine contains "powershell"
);

// Query 2
let query_2 = (
    DeviceNetworkEvents
    | where RemoteUrl contains "malicious.com"
);

// Correlation search combining 2 queries
union query_1, query_2
   | where Timestamp > ago(1d)
   | summarize CorrelationCount=count() by DeviceId, DeviceName, Timestamp, AccountName
   | where CorrelationCount >= 2  // At least 2 different detection patterns matched
```

**Splunk Example:**
```spl
index=edr_events earliest=-1d
  ((ProcessCommandLine="*powershell*") OR (RemoteUrl="*malicious.com*"))
  | stats count as CorrelationCount, values(*) as * by AccountName, DeviceName, _time
  | where CorrelationCount >= 2
  | table _time, AccountName, DeviceName, CorrelationCount, ActionType, FileName
```

## Configuration

### Default Paths

- **Input**: `data/queries/` (all `.yaml` and `.yml` files)
- **Output**: `data/correlations/correlation_queries.json`

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--yaml-dir` | `data/queries` | Directory containing YAML detection files |
| `--output` | `data/correlations/correlation_queries.json` | Output JSON file path |
| `--min-queries` | `2` | Minimum queries per correlation |
| `--verbose` | `False` | Enable detailed output |

## YAML File Requirements

Your YAML files should follow this structure:

```yaml
id: unique-id
name: Detection Name
description: |
  Description of the detection
severity: Medium
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection  # or Splunk
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Discovery
  - Credential Access
tags:
  - APT29
  - Scattered Spider
query: |
  DeviceProcessEvents
  | where ProcessCommandLine contains "suspicious"
```

## Examples

### Example 1: Basic Usage

```bash
python3 archer.py build-correlations
```

Output:
```
======================================================================
Correlation Query Builder
======================================================================

Scanning YAML files in data/queries...
Found 25 YAML files
Successfully parsed 25 queries
Assessing query relevance...
Building 8 correlation searches...

======================================================================
SUMMARY
======================================================================
Total queries analyzed: 25
Correlations built: 8
Minimum queries per correlation: 2

✓ Output saved to: data/correlations/correlation_queries.json
```

### Example 2: Custom Configuration

```bash
python3 archer.py build-correlations \
  --yaml-dir ./custom-detections \
  --output ./custom-correlations.json \
  --min-queries 3 \
  --verbose
```

### Example 3: Integration with Existing Workflow

```bash
# Option 1: Generate detections with correlation in one step
python3 archer.py generate "Scattered Spider" --correlate

# Option 2: Generate detections, then correlate separately
python3 archer.py generate "Scattered Spider"
python3 archer.py correlate --verbose
```

## Troubleshooting

### No Correlations Generated

**Issue**: `Correlations built: 0`

**Solutions**:
1. Ensure your YAML files have the `tags` field populated with threat groups
2. Check that you have at least 2 queries with matching tags and platforms
3. Lower `--min-queries` to 2 (the minimum supported value)

### FileNotFoundError

**Issue**: `ERROR: [Errno 2] No such file or directory: 'data/queries'`

**Solution**: Ensure the YAML directory exists and contains `.yaml` or `.yml` files

### Import Errors

**Issue**: `ModuleNotFoundError: No module named 'yaml'`

**Solution**: Install required dependencies:
```bash
pip install pyyaml
```

## Integration Points

### With Existing GenAI Module

The correlation builder extends the existing `genai.py` module:

```python
from archer.genai import build_correlation_queries, generate_correlations

# New correlation builder (relevance-based)
correlations = build_correlation_queries(yaml_dir='data/queries')

# Existing GenAI (heuristic-based)
results = generate_correlations(group_name='APT29', yaml_dir='data/queries')
```

### With Web Application

To integrate with your FastAPI app:

```python
from archer.genai import build_correlation_queries

@app.post("/api/build-correlations")
async def build_correlations_endpoint(group_name: str):
    result = build_correlation_queries(
        yaml_dir=f"data/queries/{group_name}",
        output_file=f"data/correlations/{group_name}_correlations.json"
    )
    return result
```

## Best Practices

1. **Tag Consistency**: Use consistent threat group names in YAML tags
2. **Tactic Alignment**: Ensure tactics follow MITRE ATT&CK naming conventions
3. **Platform Separation**: Don't mix MDE and Splunk queries in the same correlation
4. **Severity Levels**: Use standard levels (Low, Medium, High, Critical)
5. **Regular Updates**: Rebuild correlations when adding new detection queries

## Advanced Usage

### Filtering by Threat Group

```python
from archer.genai import build_correlation_queries
import json

# Build all correlations
result = build_correlation_queries()

# Filter for specific threat group
apt29_correlations = [
    c for c in result['correlations']
    if 'APT29' in c['threat_groups']
]

# Save filtered results
with open('apt29_correlations.json', 'w') as f:
    json.dump(apt29_correlations, f, indent=2)
```

### Custom Relevance Scoring

To adjust the relevance scoring weights, modify `_calculate_relevance_score()` in `archer/genai/engine.py`:

```python
def _calculate_relevance_score(query_a: Dict, query_b: Dict) -> float:
    # Adjust these weights based on your needs
    tag_weight = 0.4      # Threat group importance
    platform_weight = 0.2  # Platform compatibility
    tactic_weight = 0.3    # Attack path overlap
    severity_weight = 0.1  # Severity alignment

    # ... rest of function
```

## Module Reference

### Core Module: `archer.genai`

**Location**: `archer/genai/`

**Public API** (from `__init__.py`):
```python
from archer.genai import (
    generate_correlations,      # Main correlation generator
    build_correlation_queries,  # Advanced correlation builder
    process_genai,              # Process wrapper
    process,                    # Alias for process_genai
)
```

### Files

#### `engine.py` (1208 lines)
Core correlation generation engine with multiple modes:
- **Heuristic mode** (default): Fast, no external dependencies
- **Advanced parsing**: Uses query parsers from `archer.parsers`
- **Semantic analysis**: Analyzes query structure and overlap
- **AI integration**: Optional, lazy-loaded from `models.py`

**Key Functions**:
- `generate_correlations()` - Generate correlations for a group
- `build_correlation_queries()` - Build correlations from YAML files
- `_combine_queries()` - Combine two queries intelligently
- `_calculate_relevance_score()` - Score query similarity (0.0-1.0)

#### `models.py` (411 lines)
AI provider implementations for enhanced query generation:

**Classes**:
- `QueryGeneratorBase` - Abstract base with caching
- `LocalLLMGenerator` - Local LLM support (llama.cpp, transformers)
- `RemoteAPIGenerator` - Remote API support (OpenAI)
- `get_generator()` - Factory function

**Usage**: Only loaded when `GENAI_MODE=ai_generators` or `GENAI_MODE=local_llm`

### Related Documentation

- [Appendix A: Local AI Model Setup](#appendix-a-local-ai-model-setup) - Local AI model configuration
- [Appendix B: Semantic Overlap Algorithm](#appendix-b-semantic-overlap-algorithm) - Technical overlap details
- [archer.py](../archer.py) - Command-line interface implementation
- [correlations.py](../archer/parsers/correlations.py) - Standalone script

### Historical Documents

Archived documentation about past changes:
- [archive/CLEANUP_REPORT.md](archive/CLEANUP_REPORT.md) - Codebase cleanup (Oct 2025)
- [archive/GENAI_RESTRUCTURE.md](archive/GENAI_RESTRUCTURE.md) - Module restructure (Oct 2025)

---

## Appendix A: Local AI Model Setup

This appendix explains how to run a local, quantized ggml model with llama.cpp and the python binding `llama-cpp-python` on macOS (Apple Silicon / M1/M2).

### Overview

- **Recommended model**: quantized GGML 7B (q4_0 or q4_1) for Mac M2 (16GB)
- The repo contains a smoke test script `scripts/genai_smoke_test.py` that will call the local model when `LLAMA_MODEL_PATH` is set
- The script is safe: if the env var is not set, it will fall back to the repo's heuristic generator

### Prerequisites

- Homebrew installed
- Command-line tools (Xcode command line tools)

### Install System Dependencies

```bash
brew install cmake libomp
```

### Install Python Dependencies

```bash
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install llama-cpp-python
# Optional: install transformers if you plan to try transformers-based local models
# python3 -m pip install transformers
```

### Obtain a GGML Quantized Model

- Download a ggml quantized 7B model (for example: ggml-7b-q4_0.bin) from a trusted source (Hugging Face community repo or TheBloke conversions)
- Respect model licensing (Llama 2 models require agreeing to the model license)
- Place the model binary somewhere on disk, e.g. `~/models/ggml-7b-q4_0.bin`

### Set Environment Variables and Run the Smoke Test

```bash
export GENAI_MODE=local_llm
export LLAMA_MODEL_PATH=/Users/you/models/ggml-7b-q4_0.bin
python3 scripts/genai_smoke_test.py
```

### What the Smoke Test Does

- If `LLAMA_MODEL_PATH` is set and `llama-cpp-python` is available, the script will load the model, run a small prompt across `data/samples/` and produce `data/correlations/smoke_test.json`
- If the model or binding are not available, the script will run the heuristic fallback (no external deps) and write the same `data/correlations/smoke_test.json`

### Troubleshooting

- **Memory errors**: Try a smaller quantized model or close other apps
- **Installation fails**: Ensure you have cmake and libomp installed and try again. On macOS, you may need to set architecture flags

### Notes

- This approach keeps everything local and offline
- If you later want to experiment with external APIs, the repo genai module supports adding an OpenAI/Anthropic adapter

---

## Appendix B: Semantic Overlap Algorithm

This appendix provides technical details about the semantic overlap calculation used in KQL query combinations.

### What Is Semantic Overlap?

A quick heuristic that estimates how similar two KQL queries are, expressed as a percentage (0–100). It's not a count of matching fields but reflects shared meaningful tokens after removing common KQL noise.

### How It's Computed (Heuristic)

1. **Tokenize** each query into lowercase alphanumeric tokens with length ≥ 3
2. **Remove common KQL operators** and very common columns (e.g., `where`, `summarize`, `project`, `DeviceName`, `Timestamp`, `ActionType`, etc.)
3. **Compute Jaccard similarity** = `100 * |intersection(tokens)| / |union(tokens)|`, rounded to an integer and clamped to [0, 100]

### What Typically Counts Toward Overlap

- Uncommon columns and tables (e.g., `DeviceFileEvents`, `DeviceProcessEvents` when distinctive)
- Specific function/verb names
- Distinctive literals/strings (e.g., "Evilginx2", "gcloud", "NTDS.dit")
- Specific filter terms in command lines or URLs

### What's Ignored or Downweighted

- Common KQL keywords and operators (`where`, `summarize`, `join`, `project`, etc.)
- Very common schema/columns across detections (`DeviceName`, `DeviceId`, `Timestamp`, `ActionType`, `AccountName`, etc.)
- This prevents inflating overlap just because both queries project typical fields

### Displayed Headers

- In heuristic mode for MDE/Sentinel/KQL, combined queries include:
  ```kql
  // {QueryAName} followed by {QueryBName}; {X}% semantic overlap.
  ```
- In non-heuristic mode, if a deeper semantic analyzer is available, its score is preferred; otherwise the heuristic is used. An extra line may appear:
  ```kql
  // Semantic: {X}% overlap via {strategy}
  ```

### Scope

- Applied to KQL-family vendors: `mde`, `microsoft`, `sentinel`, `kql`
- Splunk output is unaffected by this heuristic

### Interpreting the Percentage (Rough Guide)

| Percentage | Interpretation |
|------------|----------------|
| 0–10% | Essentially unrelated |
| 10–30% | Low overlap |
| 30–60% | Moderate overlap |
| 60%+ | High overlap (likely similar concepts or shared indicators) |

### Why It's Not "Matching Fields"

- The heuristic doesn't count identical columns
- It focuses on distinctive tokens so that common columns don't dominate the score
- Two queries with the same projection list can still be low-overlap if their core filters and distinctive terms differ

### Limitations

- **Token-based and schema-agnostic**: No AST or operator semantics considered
- **Rare tokens** can disproportionately affect the score
- Use as a hint for conceptual proximity, not a measure of result-set equivalence or performance

### FAQ

**Q: Is it the number of fields that match?**
A: No. It's a Jaccard-like similarity over meaningful tokens after stripping common KQL noise.

**Q: Why do some pairs show high overlap?**
A: They likely share distinctive strings (e.g., same tool names) and uncommon columns/tables.
