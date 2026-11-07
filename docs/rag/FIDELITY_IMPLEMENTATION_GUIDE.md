# Detection Fidelity Improvement System - Implementation Guide

> **Status (2026-10-16):** some of what this document names was never built: the knowledge-base maintenance and benchmarking scripts (`add_to_kb.py`, `batch_enhance.py`, `benchmark_fidelity.py`, `ab_test.py` and the rest under `scripts/`) and the test-sample files. What exists: `scripts/config/` (`setup_knowledge_base.py`, `import_community_rules.py`, `build_embeddings.py`, `search_similar_detections.py`, `validate_detections.py`, `quickstart_rag.py`), `scripts/ai/` (`setup_local_llm.py`, `train_ai.py`), `scripts/data/` and `scripts/validation/`: see [SCRIPTS.md](../SCRIPTS.md). `shikari offline generate` has none of the flags shown here (`--use-rag`, `--no-rag`, `--min-fidelity`, `--validate`, `--parallel`, `--workers`); its options are `--correlate`, `--llm`/`--no-llm` and `--hypothesis`.

**Version:** 1.0
**Date:** 2024-11-28
**Status:** 🚧 In Development

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Phase 1: Knowledge Base Setup](#phase-1-knowledge-base-setup)
4. [Phase 2: RAG Retrieval System](#phase-2-rag-retrieval-system)
5. [Phase 3: Validation Module](#phase-3-validation-module)
6. [Phase 4: Integration](#phase-4-integration)
7. [Phase 5: Testing & Validation](#phase-5-testing--validation)
8. [Configuration](#configuration)
9. [Usage Examples](#usage-examples)
10. [Performance Optimization](#performance-optimization)
11. [Troubleshooting](#troubleshooting)
12. [Maintenance](#maintenance)

---

## Overview

### Problem Statement

Current detection generation uses heuristic-based extraction from MITRE ATT&CK procedures, which can result in:
- Generic, low-fidelity queries
- Missing platform-specific optimizations
- High false positive rates
- Inconsistent query quality across techniques

### Solution: RAG-Based Fidelity Enhancement

This system improves detection quality through:

1. **Knowledge Base**: Curated collection of high-quality detection examples
2. **RAG (Retrieval-Augmented Generation)**: Find similar examples to guide query generation
3. **Validation Module**: Automated testing against known good/bad samples
4. **Community Integration**: Import proven detections from open-source projects

### Key Benefits

✅ **No model training required** - Works with any LLM (OpenAI, Ollama, Claude)
✅ **Easy to update** - Add new examples as YAML/JSON files
✅ **Explainable** - See which examples influenced each query
✅ **Measurable** - Track fidelity scores over time
✅ **Community-powered** - Leverage thousands of Splunk and Elastic community rules

---

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                   Fidelity Enhancement System                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────┐      ┌──────────────────┐                │
│  │  Knowledge Base  │      │   RAG Retrieval  │                │
│  │  - Examples      │  →   │   - Embeddings   │                │
│  │  - Mappings      │      │   - Similarity    │                │
│  │  - FP Patterns   │      │   - Ranking      │                │
│  └──────────────────┘      └──────────────────┘                │
│           ↓                          ↓                           │
│  ┌────────────────────────────────────────────┐                │
│  │        Query Enhancement Engine            │                │
│  │  - Example-guided generation               │                │
│  │  - LLM integration (any provider)          │                │
│  └────────────────────────────────────────────┘                │
│           ↓                                                      │
│  ┌────────────────────────────────────────────┐                │
│  │        Validation Module                │                │
│  │  - Syntax validation                       │                │
│  │  - Field existence checks                  │                │
│  │  - Test data validation                    │                │
│  │  - Fidelity scoring                        │                │
│  └────────────────────────────────────────────┘                │
│           ↓                                                      │
│  ┌────────────────────────────────────────────┐                │
│  │        Enhanced Detection Output            │                │
│  │  - High-fidelity queries                   │                │
│  │  - Confidence scores                       │                │
│  │  - Validation results                      │                │
│  └────────────────────────────────────────────┘                │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
shikari/
├── data/
│   ├── external/                     # All external/community content
│   │   ├── repos/                    # Cloned community repositories
│   │   │   ├── splunk/
│   │   │   └── elastic/
│   │   └── detections/               # Processed detection examples
│   │       ├── detection_examples/   # High-quality detection YAMLs
│   │       │   ├── credential_access/
│   │       │   │   ├── T1003.001_lsass_dump_splunk_001.yaml
│   │       │   │   └── ...
│   │       │   ├── execution/
│   │       │   ├── persistence/
│   │       │   └── ... (14 tactics)
│   │       ├── field_mappings/       # Platform-specific field catalogs
│   │       ├── false_positive_patterns/  # Known FP patterns
│   │       └── embeddings/           # Vector store for RAG
│   │           ├── vector_store.faiss
│   │           └── metadata.json
│   ├── bespoke/                      # Organization-specific content (gitignored)
│   │   ├── sample_searches/          # Custom search examples
│   │   ├── exclusions.yaml           # Global exclusions for all queries
│   │   └── config.yaml               # Org-specific settings
│   ├── validation/                   # Validation module
│   │   ├── test_samples/
│   │   └── validation_results/
│   └── ml_training/                  # ML training data
├── shikari/
│   ├── rag/                          # RAG system
│   │   ├── __init__.py
│   │   ├── knowledge_base.py         # KB management
│   │   ├── retrieval.py              # Vector search
│   │   ├── embeddings.py             # Embedding generation
│   │   └── enhancer.py               # Query enhancement with LLM
│   ├── validation/                   # Validation module
│   │   ├── field_validator.py        # Field existence checks
│   │   ├── query_validator.py        # Syntax & logic validation
│   │   ├── test_runner.py            # Automated testing
│   │   └── scoring.py                # Fidelity scoring
│   └── importers/                    # Community rule importers
│       ├── splunk_importer.py
│       └── elastic_importer.py
└── scripts/
    ├── setup_knowledge_base.py       # Initialize structure
    ├── import_community_rules.py     # Import from repos
    ├── build_embeddings.py           # Build vector store
    └── validate_detection.py         # Validate detections
```

---

## Phase 1: Knowledge Base Setup

### Step 1.1: Create Directory Structure

```bash
# Run the setup script
python scripts/config/setup_knowledge_base.py

# Or manually:
mkdir -p data/external/detections/{detection_examples,field_mappings,false_positive_patterns,embeddings}
mkdir -p data/external/detections/detection_examples/{credential_access,execution,persistence,privilege_escalation,defense_evasion,discovery,lateral_movement,collection,exfiltration,command_and_control}
mkdir -p data/validation/test_samples
mkdir -p data/external
```

### Step 1.2: Clone Community Detection Repositories

```bash
# Clone Splunk Security Content (900+ detections)
cd data/external/repos
git clone https://github.com/splunk/security_content.git splunk

# Clone Elastic Detection Rules (800+ rules)
git clone https://github.com/elastic/detection-rules.git elastic

# Optional: Clone Sentinel rules
git clone https://github.com/Azure/Azure-Sentinel.git azure_sentinel

cd ../../..
```

### Step 1.3: Import Community Rules

```bash
# Import Splunk rules
python scripts/config/import_community_rules.py \
  --source splunk \
  --input data/external/repos/splunk/detections \
  --output data/external/detections/detection_examples/

# Import all at once
python scripts/config/import_community_rules.py --all
```

**Expected Output:**
```
Importing Splunk Security Content...
  ✓ Processed 923 Splunk detections
  ✓ Mapped 876 detections to MITRE ATT&CK
  ✓ Imported 876 high-quality examples

Importing Elastic Detection Rules...
  ✓ Processed 812 Elastic rules
  ✓ Mapped 650 rules to MITRE ATT&CK
  ✓ Imported 650 high-quality examples

Total Knowledge Base: 1526 detection examples
```

### Step 1.4: Create Field Mapping Catalogs

```bash
# Generate field catalogs from your actual data sources
python scripts/generate_field_catalogs.py \
  --splunk-host https://your-splunk:8089 \
  --mde-tenant your-tenant \
  --output data/external/detections/field_mappings/
```

**Manual Alternative:** Create field catalogs manually:

```json
// data/external/detections/field_mappings/splunk_windows_security.json
{
  "platform": "Splunk",
  "index": "windows_security",
  "sourcetype": "WinEventLog:Security",
  "fields": [
    {
      "name": "EventCode",
      "type": "integer",
      "common_values": [4688, 4689, 4624, 4625, 4672, 5140],
      "population": 1.0,
      "description": "Windows Event ID"
    },
    {
      "name": "CommandLine",
      "type": "string",
      "population": 0.95,
      "aliases": ["Process_CommandLine", "properties.CommandLine"],
      "description": "Process command line"
    },
    {
      "name": "SourceImage",
      "type": "string",
      "population": 0.98,
      "aliases": ["ParentProcessName", "ProcessName"],
      "description": "Process executable path"
    }
  ],
  "validation_date": "2024-11-28",
  "sample_count": 1000000
}
```

---

## Phase 2: RAG Retrieval System

### Step 2.1: Install Dependencies

```bash
# Add to requirements.txt
pip install sentence-transformers==2.2.2
pip install faiss-cpu==1.7.4  # Use faiss-gpu if you have CUDA
pip install numpy==1.24.3
pip install pyyaml==6.0.1

# Or install all at once
pip install -r requirements.txt
```

### Step 2.2: Build Vector Embeddings

```bash
# Build embeddings for all detection examples
python scripts/config/build_embeddings.py \
  --knowledge-base data/external/detections/detection_examples/ \
  --output data/external/detections/embeddings/vector_store.faiss \
  --model sentence-transformers/all-MiniLM-L6-v2

# Expected time: 5-10 minutes for 2000+ examples
```

**Output:**
```
Loading detection examples from knowledge base...
  ✓ Loaded 1526 detection examples

Generating embeddings...
  Model: sentence-transformers/all-MiniLM-L6-v2
  Progress: 100% |████████████████| 1526/1526
  ✓ Generated 1526 embeddings

Building FAISS index...
  ✓ Built index with 1526 vectors
  ✓ Index dimension: 384

Saving index...
  ✓ Saved to: data/external/detections/embeddings/vector_store.faiss
  ✓ Saved metadata: data/external/detections/embeddings/metadata.json

Total time: 7m 23s
```

### Step 2.3: Test Retrieval System

```bash
# Test retrieval for a specific technique
python scripts/config/search_similar_detections.py \
  --technique T1003.001 \
  --platform splunk \
  --top-k 5
```

**Expected Output:**
```
Querying: T1003.001 (LSASS Memory) on platform Splunk

Top 5 Similar Detections:
1. Score: 0.89 | T1003.001_credential_dump_splunk_sc.yaml
   Source: Splunk Security Content
   Fidelity: 0.91

2. Score: 0.87 | T1003.001_lsass_access_elastic.yaml
   Source: Elastic Detection Rules
   Fidelity: 0.88

3. Score: 0.86 | T1003_credential_access_splunk_custom.yaml
   Source: Community Contribution
   Fidelity: 0.85

[Preview of top result]
Query: |
  index=windows sourcetype=WinEventLog:Security EventCode=10
  TargetImage="*\\lsass.exe"
  (GrantedAccess=0x1010 OR GrantedAccess=0x1410 OR GrantedAccess=0x1438)
  | where NOT match(SourceImage, "(?i)(wininit|services|csrss)")
```

---

## Phase 3: Validation Module

### Step 3.1: Create Test Data Samples

```bash
# Generate test samples for a technique
python scripts/create_test_samples.py \
  --technique T1003.001 \
  --output data/validation/test_samples/T1003.001/
```

**Manual Alternative:** Create test samples manually:

```json
// data/validation/test_samples/T1003.001/malicious/mimikatz_lsass_dump.json
{
  "event_type": "process_access",
  "timestamp": "2024-11-15T10:30:00Z",
  "event_id": 10,
  "source_process": "powershell.exe",
  "source_process_id": 4532,
  "source_image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "target_process": "lsass.exe",
  "target_process_id": 684,
  "target_image": "C:\\Windows\\System32\\lsass.exe",
  "granted_access": "0x1410",
  "call_trace": "C:\\Windows\\System32\\ntdll.dll+a1234|C:\\Windows\\System32\\kernelbase.dll+1c2a3",
  "is_malicious": true,
  "attack_tool": "mimikatz",
  "attack_technique": "T1003.001",
  "description": "Mimikatz attempting to read LSASS memory for credential dumping"
}
```

```json
// data/validation/test_samples/T1003.001/benign/windows_defender_scan.json
{
  "event_type": "process_access",
  "timestamp": "2024-11-15T10:31:00Z",
  "event_id": 10,
  "source_process": "MsMpEng.exe",
  "source_process_id": 2344,
  "source_image": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2110.6-0\\MsMpEng.exe",
  "target_process": "lsass.exe",
  "target_process_id": 684,
  "target_image": "C:\\Windows\\System32\\lsass.exe",
  "granted_access": "0x1410",
  "call_trace": "C:\\Windows\\System32\\ntdll.dll+a1234",
  "is_malicious": false,
  "description": "Windows Defender legitimately scanning LSASS"
}
```

### Step 3.2: Implement Validation Tests

Run validation on a generated query:

```bash
# Validate a specific detection
python scripts/validate_detection.py \
  --technique T1003.001 \
  --platform splunk \
  --query-file data/groups/APT29_T1003.001_splunk.yaml \
  --verbose
```

**Expected Output:**
```
Validating: APT29_T1003.001_splunk.yaml

✓ Syntax Validation: PASS
  - Valid Splunk SPL syntax
  - No syntax errors detected

✓ Field Validation: PASS
  - All fields exist in target index
  - Fields checked: EventCode, TargetImage, GrantedAccess, SourceImage

✓ Logic Validation: PASS
  - Query logic is sound
  - Appropriate filters applied
  - No obvious logic errors

✓ Test Data Validation:
  Testing against 15 samples (10 malicious, 5 benign)

  True Positives:  9/10 (90%)
  False Positives: 1/5  (20%)
  False Negatives: 1/10 (10%)

  Precision: 0.90
  Recall: 0.90
  F1 Score: 0.90
  Fidelity Score: 0.85

Overall Score: 0.91 (Excellent)

Recommendations:
  - Consider adding exclusion for source process: MsMpEng.exe
  - Query performs well, minimal adjustments needed
```

---

## Phase 4: Integration

### Step 4.1: Integrate RAG with Detection Generation

The RAG system is automatically integrated into the detection generation pipeline:

```python
# In shikari/build/detections.py
# RAG enhancement is now enabled by default

# Generate detections with RAG enhancement
shikari offline generate APT29 --use-rag
```

**CLI Options:**
```bash
# Generate with RAG enhancement (default)
shikari offline generate APT29

# Generate without RAG (use original heuristics only)
shikari offline generate APT29 --no-rag

# Generate with specific confidence threshold
shikari offline generate APT29 --min-fidelity 0.8

# Generate with validation
shikari offline generate APT29 --validate
```

### Step 4.2: Use RAG in Web Interface

The web interface automatically uses RAG when generating queries:

1. Navigate to `http://localhost:32453`
2. Go to "Generate Detection" tab
3. Enter threat group name
4. Enable "Use RAG Enhancement" (enabled by default)
5. Set "Minimum Fidelity Score" slider (default: 0.7)
6. Click "Generate"

The system will:
- Retrieve similar high-quality examples
- Generate enhanced queries using LLM
- Validate against test data
- Display confidence scores

### Step 4.3: API Integration

```python
from shikari.ai.rag import DetectionKnowledgeBase
from shikari.validation import DetectionTestRunner

# Initialize systems
kb = DetectionKnowledgeBase()
validator = DetectionTestRunner()

# Generate enhanced detection
technique_id = "T1003.001"
platform = "splunk"

# 1. Retrieve similar examples
examples = kb.find_similar_detections(
    technique_id=technique_id,
    platform=platform,
    top_k=5
)

# 2. Generate enhanced query
enhanced_query = kb.enhance_query_with_examples(
    original_query=original_query,
    examples=examples,
    llm_provider="openai"  # or "ollama", "anthropic"
)

# 3. Validate enhanced query
validation_results = validator.run_validation_suite(
    query=enhanced_query,
    technique_id=technique_id,
    platform=platform
)

print(f"Fidelity Score: {validation_results['overall_score']}")
```

---

## Phase 5: Testing & Validation

### Step 5.1: Benchmark Improvements

```bash
# Run benchmark to measure fidelity improvements
python scripts/benchmark_fidelity.py \
  --techniques T1003.001,T1059.001,T1543.003,T1055 \
  --platforms splunk,mde \
  --iterations 10 \
  --output benchmarks/baseline_vs_rag.json
```

**Expected Output:**
```
Benchmarking Fidelity Improvements
===================================

Baseline (Heuristic Only):
  Average Fidelity: 0.67
  Average Precision: 0.71
  Average Recall: 0.79
  Average F1: 0.75

With RAG Enhancement:
  Average Fidelity: 0.88  (+31%)
  Average Precision: 0.91 (+28%)
  Average Recall: 0.87    (+10%)
  Average F1: 0.89        (+19%)

Improvement Summary:
  ✓ Fidelity improved by 31%
  ✓ False positives reduced by 28%
  ✓ Detection coverage improved by 10%

Saved detailed results to: benchmarks/baseline_vs_rag.json
```

### Step 5.2: A/B Testing

```bash
# Generate detections both ways and compare
python scripts/ab_test.py \
  --group "APT29" \
  --output comparison/apt29_baseline_vs_rag.html
```

This generates an HTML report showing side-by-side comparisons.

---

## Configuration

### Knowledge Base Configuration

```yaml
# config/knowledge_base.yaml

knowledge_base:
  path: "data/external/detections"

  detection_examples:
    min_fidelity_score: 0.7      # Only use examples with score >= 0.7
    max_age_days: 365            # Ignore examples older than 1 year
    prefer_validated: true        # Prefer examples with validation data

  embeddings:
    model: "sentence-transformers/all-MiniLM-L6-v2"
    dimension: 384
    similarity_threshold: 0.75    # Minimum similarity to use example
    top_k: 5                      # Number of examples to retrieve

  field_mappings:
    auto_update: true             # Auto-update from live sources
    update_interval_days: 30      # Update every 30 days

  false_positive_patterns:
    enabled: true
    auto_apply: true              # Automatically exclude FP patterns
```

### RAG Configuration

```yaml
# config/rag.yaml

rag:
  enabled: true

  retrieval:
    algorithm: "faiss"            # or "annoy", "chromadb"
    distance_metric: "cosine"     # or "euclidean", "dot_product"
    cache_results: true
    cache_ttl_seconds: 3600

  enhancement:
    llm_provider: "openai"        # or "ollama", "anthropic", "local"
    llm_model: "gpt-4"            # or "gpt-3.5-turbo", "llama2", "claude-3"
    temperature: 0.2              # Lower = more deterministic
    max_tokens: 1000

    prompt_template: "default"    # or path to custom template

    fallback_to_heuristic: true   # Use heuristics if RAG fails
    retry_attempts: 3
    timeout_seconds: 30
```

### Validation Configuration

```yaml
# config/validation.yaml

validation:
  enabled: true

  test_data:
    path: "data/validation/test_samples"
    min_samples_required: 5       # Require at least 5 test samples

  thresholds:
    min_fidelity_score: 0.7       # Minimum acceptable fidelity
    min_precision: 0.8            # Minimum precision
    min_recall: 0.7               # Minimum recall
    max_false_positive_rate: 0.3  # Maximum FP rate

  auto_reject:
    enabled: true                 # Reject queries below thresholds
    save_rejected: true           # Save rejected queries for review

  reporting:
    save_results: true
    output_dir: "data/validation/validation_results"
    format: "json"                # or "yaml", "html"
```

---

## Usage Examples

### Example 1: Generate Detection with RAG

```bash
# Generate detection for APT29 with RAG enhancement
shikari offline generate APT29 --use-rag --validate

# Output: data/groups/APT29_*.yaml files with confidence scores
```

### Example 2: Validate Existing Detection

```bash
# Validate an existing detection
python scripts/validate_detection.py \
  --file data/groups/APT29_T1003.001_splunk.yaml \
  --verbose

# Returns fidelity score and recommendations
```

### Example 3: Compare Detection Quality

```bash
# Generate and compare baseline vs RAG-enhanced
python scripts/compare_detections.py \
  --technique T1003.001 \
  --platform splunk \
  --output comparison_report.html
```

### Example 4: Batch Processing

```bash
# Process all detections for a threat group
python scripts/batch_enhance.py \
  --group APT29 \
  --input data/groups/ \
  --output data/groups_enhanced/ \
  --validate
```

### Example 5: Add Custom Example to KB

```bash
# Add your own high-quality detection to knowledge base
python scripts/add_to_kb.py \
  --technique T1003.001 \
  --platform splunk \
  --query-file my_custom_detection.yaml \
  --fidelity-score 0.95
```

---

## Performance Optimization

### Embedding Generation

```bash
# Use GPU acceleration for faster embedding generation
pip install faiss-gpu
export CUDA_VISIBLE_DEVICES=0

# Or use quantized model for faster inference
python scripts/config/build_embeddings.py \
  --model sentence-transformers/all-MiniLM-L6-v2 \
  --quantize int8
```

### Caching

```python
# Enable caching in config/rag.yaml
rag:
  retrieval:
    cache_results: true
    cache_ttl_seconds: 3600  # Cache for 1 hour
```

### Batch Processing

```bash
# Process multiple techniques in parallel
shikari offline generate APT29 --parallel --workers 4
```

---

## Troubleshooting

### Issue: "No similar examples found"

**Cause:** Knowledge base is empty or embeddings not built

**Solution:**
```bash
# Check KB status
python scripts/check_kb_status.py

# Import community rules
python scripts/config/import_community_rules.py --all

# Build embeddings
python scripts/config/build_embeddings.py
```

### Issue: "Field validation failed"

**Cause:** Field mappings are outdated or incorrect

**Solution:**
```bash
# Regenerate field catalogs
python scripts/generate_field_catalogs.py --update

# Or manually update:
# Edit data/external/detections/field_mappings/[platform]_[index].json
```

### Issue: "Low fidelity scores"

**Cause:** Not enough high-quality examples in KB

**Solution:**
```bash
# Import more community rules
python scripts/config/import_community_rules.py --all

# Add custom examples
python scripts/add_to_kb.py --from-directory my_detections/

# Lower minimum fidelity threshold temporarily
shikari offline generate APT29 --min-fidelity 0.6
```

### Issue: "LLM timeout or errors"

**Cause:** LLM provider unavailable or rate limited

**Solution:**
```bash
# Enable fallback to heuristics in config/rag.yaml
rag:
  enhancement:
    fallback_to_heuristic: true
    retry_attempts: 3

# Or use local LLM
rag:
  enhancement:
    llm_provider: "ollama"
    llm_model: "llama2"
```

---

## Maintenance

### Regular Updates

```bash
# Update community rule repositories (monthly)
cd data/external/repos/splunk && git pull
cd ../elastic && git pull

# Re-import updated rules
python scripts/config/import_community_rules.py --all --update

# Rebuild embeddings
python scripts/config/build_embeddings.py --incremental
```

### Monitoring

```bash
# Check knowledge base statistics
python scripts/kb_stats.py

# Monitor validation results
python scripts/monitor_validation.py --last-30-days

# Generate quality report
python scripts/generate_quality_report.py --output reports/quality_$(date +%Y%m%d).html
```

### Cleanup

```bash
# Remove low-quality examples
python scripts/cleanup_kb.py --min-fidelity 0.7

# Remove duplicates
python scripts/deduplicate_kb.py

# Archive old examples
python scripts/archive_kb.py --older-than-days 365
```

---

## Next Steps

1. ✅ Complete Phase 1: Knowledge Base Setup
2. ✅ Complete Phase 2: RAG System Implementation
3. ✅ Complete Phase 3: Validation Module
4. ✅ Complete Phase 4: Integration
5. → Test with real threat groups
6. → Collect user feedback
7. → Iterate and improve

---

## Support & Feedback

- **Documentation:** See docs/
- **Issues:** [GitHub Issues](https://github.com/cmdaltr/shikari/issues)
- **Feature Requests:** [GitHub Discussions](https://github.com/cmdaltr/shikari/discussions)

---

**Last Updated:** 2024-11-28
**Version:** 1.0
**Status:** 🚧 Implementation in progress
