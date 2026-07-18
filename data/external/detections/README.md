# External Detections

This directory contains **community-sourced** detection examples for RAG-based query enhancement.

These are external/public detections imported from community repositories (Splunk, Elastic, etc.).

## Structure

### detection_examples/
High-quality detection examples organized by MITRE ATT&CK tactic.

Each example is a YAML file with:
- Technique ID and name
- Platform (Splunk, MDE, Elastic, etc.)
- Detection query
- Fidelity score
- Validation data
- False positive patterns
- Data source requirements

### field_mappings/
Platform-specific field catalogs that define available fields in each data source.

Format: JSON files with field names, types, aliases, and population statistics.

### false_positive_patterns/
Known false positive patterns to exclude from detections.

Includes:
- Legitimate administrative tools
- Vendor processes
- Common noise sources

### embeddings/
Vector embeddings for similarity search in RAG system.

Files:
- vector_store.faiss: FAISS index with embeddings
- metadata.json: Mapping of vector indices to detection files

## Adding Examples

To add a new detection example:

```bash
python scripts/add_to_kb.py \
  --technique T1003.001 \
  --platform splunk \
  --query-file my_detection.yaml \
  --fidelity-score 0.90
```

Or manually create a YAML file in the appropriate tactic directory:

```yaml
technique_id: T1003.001
technique_name: "LSASS Memory Dump"
platform: Splunk
fidelity_score: 0.95
validated: true

query: |
  index=windows EventCode=10
  TargetImage="*\\lsass.exe"
  | stats count by SourceImage, GrantedAccess

explanation: |
  Detects access to LSASS memory

data_sources:
  - Windows Security Event Log (Event ID 10)
```

## Importing Community Rules

```bash
# Import Splunk Security Content
python scripts/config/import_community_rules.py --source splunk

# Import Elastic Detection Rules
python scripts/config/import_community_rules.py --source elastic

# Import all sources
python scripts/config/import_community_rules.py --all
```

## Maintenance

### Update Community Repositories

```bash
cd data/external/splunk && git pull
python scripts/config/import_community_rules.py --source splunk --update
```

### Rebuild Embeddings

```bash
python scripts/config/build_embeddings.py --incremental
```

### Check Statistics

```bash
python scripts/kb_stats.py
```

---

For more information, see [FIDELITY_IMPLEMENTATION_GUIDE.md](../../FIDELITY_IMPLEMENTATION_GUIDE.md)
