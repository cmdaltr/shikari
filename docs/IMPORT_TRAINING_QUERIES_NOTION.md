# 📝 Training Examples Import Script

Import high-quality detection queries as training examples for AI-powered query generation.


---

## ⚡ Quick Start

```bash
# Extract queries from directory to JSON
python3 scripts/import_training_queries.py -file /path/to/queries

# Import queries directly to database
python3 scripts/import_training_queries.py -db /path/to/queries

# Dry run (see what would be imported)
python3 scripts/import_training_queries.py -db /path/to/queries --dry-run
```bash


---

## 💻 Usage

### 📌 Step 1: Extract Queries to JSON File

```bash
python3 scripts/import_training_queries.py -file data/sample_queries

# Custom output location
python3 scripts/import_training_queries.py -file data/sample_queries -o my_queries.json
```bash

This scans a directory for YAML/JSON files and extracts high-quality queries into a JSON file.

### 🗄️ Step 2: Import to Database

```bash
# From JSON file
python3 scripts/import_training_queries.py -db data/query_examples.json

# Directly from directory (combines both steps)
python3 scripts/import_training_queries.py -db data/sample_queries

# Dry run first (recommended)
python3 scripts/import_training_queries.py -db data/sample_queries --dry-run
```bash


---

## 🆘 Supported File Formats

### 📌 YAML Format

```yaml
title: LSASS Memory Access Detection
technique_id: T1003.001
technique_name: LSASS Memory Dumping
platform: splunk
quality: high
rating: 5.0
tags:
  - credential-access
  - windows
detection:
|  |
    index=windows EventCode=10 TargetImage="*\\lsass.exe"
|  |
notes: High-fidelity detection with minimal false positives
```bash

### 📌 JSON Format

```json
{
  "technique_id": "T1053.005",
  "technique_name": "Scheduled Task",
  "platform": "mde",
  "quality": "high",
  "rating": 4.5,
|  |
  "tags": ["persistence", "windows"],
  "notes": "Detects privileged scheduled task creation"
}
```bash

### 📌 Flexible Field Names

The script automatically detects queries from various formats:

**Query fields** (in order of precedence):
- `query`
- `search`
- `detection.search`
- `detection.query`
- `detection_query`
- `spl`

**Technique ID sources**:
- `technique_id` field
- `mitre_attack.technique_id` field
- Filename (e.g., `T1003.001_splunk.yaml`)

**Platform detection**:
- `platform` field
- Filename (`splunk`, `mde`, `sentinel`, `chronicle`)
- Query content (index=, DeviceProcessEvents, etc.)


---

## 📌 Options

```bash
-file DIR, --extract-to-file DIR
    Extract queries from directory to JSON file

-db PATH, --import-to-database PATH
    Import queries from directory or JSON to database

-o FILE, --output FILE
    Output JSON file (default: data/query_examples.json)

--dry-run
    Show what would be imported without making changes

-q, --quiet
    Suppress verbose output
```bash


---

## 📝 Examples

### 📌 Example 1: Import from Existing Detection Library

```bash
# If you have a directory of Sigma rules or custom detections
python3 scripts/import_training_queries.py -file data/detections -o training_data.json
python3 scripts/import_training_queries.py -db training_data.json
```bash

### 📌 Example 2: Quick Import from Directory

```bash
# Combine extraction and import in one command
python3 scripts/import_training_queries.py -db /path/to/detection/library
```bash

### 📌 Example 3: Verify Before Import

```bash
# Always use dry-run first
python3 scripts/import_training_queries.py -db my_queries/ --dry-run

# If looks good, run actual import
python3 scripts/import_training_queries.py -db my_queries/
```bash

### 📌 Example 4: Quiet Mode for Automation

```bash
# Suppress output (for cron jobs, scripts)
python3 scripts/import_training_queries.py -db queries/ --quiet
```bash


---

## 📌 Output

### 📌 Extraction Output
```bash
🔍 Scanning directory: data/sample_queries
Found 10 YAML and 5 JSON files

  ✓ T1003.001_splunk.yaml: T1003.001 (splunk)
  ✓ T1053.005_mde.json: T1053.005 (mde)
  ...

✓ Extracted 15 queries from 15 files

💾 Saved to: data/query_examples.json
   Total queries: 15
```bash

### 📌 Import Output
```bash
📊 Importing to database...

  ✓ T1003.001 (splunk): Imported
  ✓ T1053.005 (mde): Imported
  ⊘ T1078 (splunk): Already exists
  ...

============================================================
Import Summary:
  ✓ Imported: 12
  ⊘ Skipped (duplicates): 3
============================================================
```bash


---

## 🗄️ Database Schema

Queries are stored in the `query_training_examples` table:

```sql
CREATE TABLE query_training_examples (
    id INTEGER PRIMARY KEY,
    technique_id VARCHAR(20),
    platform VARCHAR(20),  -- splunk, mde, sentinel, chronicle
    query TEXT,
    technique_description TEXT,
    attack_scenario TEXT,
    avg_rating FLOAT,
    usage_count INTEGER,
    source VARCHAR(50),
    tags TEXT,  -- JSON array
    created_at TIMESTAMP
);
```bash


---

## 📝 Using Training Examples

After importing, queries can be used for:

1. **Few-Shot Learning** - Provide examples to AI models
2. **Query Templates** - Base new queries on high-quality examples
3. **Quality Comparison** - Benchmark generated queries
4. **Pattern Analysis** - Extract common patterns from good queries

See [docs/AI_TRAINING_IMPLEMENTATION.md](../docs/AI_TRAINING_IMPLEMENTATION.md) for details on using these examples with AI.


---

## 🔧 Troubleshooting

### "No queries extracted"
- Check file format matches expected structure
- Verify files have `query` or `search` fields
- Ensure queries are >10 characters
- Use `-file` mode to see what's being extracted

### "ModuleNotFoundError: yaml"
- Install dependencies: `pip install -r requirements.txt`
- Or activate venv: `source .venv/bin/activate`

### "Already exists" for all queries
- This is normal on re-import (duplicate detection working)
- To update, delete existing entries first or modify queries

### 📌 Platform not detected correctly
- Add explicit `platform: splunk` field to file
- Or include platform in filename: `T1003.001_splunk.yaml`


---

## 💻 Advanced Usage

### 📌 Custom Extraction Logic

Modify `QueryExtractor._parse_query_data()` to handle your specific format:

```python
# In scripts/import_training_queries.py
def _parse_query_data(self, data: Dict, source_file: Path) -> Optional[Dict]:
    # Add custom parsing logic
    if 'my_custom_field' in data:
        query = data['my_custom_field']['custom_query']
    ...
```bash

### 📌 Batch Processing

```bash
# Process multiple directories
for dir in detections/*; do
    python3 scripts/import_training_queries.py -db "$dir" --quiet
done
```bash

### 📌 Export Training Data

```python
from archer.database.db import get_db
from scripts.import_training_examples import QueryTrainingExample

db = next(get_db())
examples = db.query(QueryTrainingExample).filter(
    QueryTrainingExample.avg_rating >= 4.5
).all()

print(f"Found {len(examples)} high-quality examples")
```bash


---

## 📌 See Also

- [AI Training Implementation Guide](../docs/AI_TRAINING_IMPLEMENTATION.md)
- [Dependency Analysis](../docs/DEPENDENCY_ANALYSIS.md)
- [Migration Guide](../docs/MIGRATION_GUIDE.md)
