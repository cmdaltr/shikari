# Schema Normalization Scripts

> **Status (2026-10-16):** some of what this document names was never built: `scripts/normalize_schema.sh`, `normalize_splunk_schema.py`, `verify_schema_duplicates.py` and the example script; schema checks are now `scripts/validation/verify_schema.py` and `analyze_schema_fields.py`, and the schemas live in `bespoke/mappings/schemas/`. What exists: `scripts/config/` (`setup_knowledge_base.py`, `import_community_rules.py`, `build_embeddings.py`, `search_similar_detections.py`, `validate_detections.py`, `quickstart_rag.py`), `scripts/ai/` (`setup_local_llm.py`, `train_ai.py`), `scripts/data/` and `scripts/validation/`: see [SCRIPTS.md](../SCRIPTS.md).

This directory contains scripts for managing Splunk schema normalization in Shikari.

## Quick Reference

### Normalize Schema (Recommended)

```bash
# Auto-detect and normalize new indexes only
./scripts/normalize_schema.sh

# Or use Python directly
python3 shikari/mappings/normalize_manual.py
```

### Verify Schema

```bash
# Check for duplicate field mappings
python3 scripts/verify_schema_duplicates.py
```

### Force Re-normalization

```bash
# Re-normalize ALL indexes (use with caution)
./scripts/normalize_schema.sh --force
```

## Available Scripts

### 1. `normalize_schema.sh` (Shell Wrapper)

Convenient shell script wrapper for schema normalization.

**Usage:**
```bash
./scripts/normalize_schema.sh [OPTIONS]

Options:
  --force         Force re-normalization of all indexes
  --silent        Suppress output
  --schema PATH   Path to custom schema file
  --help, -h      Show help message
```

**Examples:**
```bash
# Normalize new indexes (production workflow)
./scripts/normalize_schema.sh

# Silent mode for automation
./scripts/normalize_schema.sh --silent

# Test with custom schema
./scripts/normalize_schema.sh --schema /tmp/test.json

# Force re-normalize all (after updating field mappings)
./scripts/normalize_schema.sh --force
```

### 2. `verify_schema_duplicates.py`

Verifies that all data sources are free of duplicate field mappings.

**Usage:**
```bash
python3 scripts/verify_schema_duplicates.py
```

**Output:**
```
✅ aws_guardduty: OK (9 unique mappings)
✅ azure_signin: OK (6 unique mappings)
...
✅ SUCCESS: All data sources are free of duplicate field mappings!
```

### 3. `normalize_splunk_schema.py` (Legacy)

Original one-time normalization script. **Replaced by** `shikari/mappings/normalize_manual.py`.

This script was used for the initial normalization. The new schema normalizer is integrated
into Shikari and provides automatic detection of unnormalized indexes.

**Migration:**
```bash
# Old way (manual, one-time)
python3 scripts/normalize_splunk_schema.py

# New way (automatic, repeatable)
python3 shikari/mappings/normalize_manual.py
```

## Workflow Integration

### On Schema Update

When adding new indexes to `schemaSplunk.json`:

```bash
# 1. Add your new index to the JSON file
vim bespoke/mappings/schemas/schemaSplunk.json

# 2. Run normalization
./scripts/normalize_schema.sh

# 3. Verify no duplicate mappings
python3 scripts/verify_schema_duplicates.py

# 4. Commit changes
git add bespoke/mappings/schemas/schemaSplunk.json
git commit -m "Add and normalize new index"
```

### In Python Code

```python
from shikari.mappings import normalize_auto_schema

# Normalize when schema is updated
def update_schema(new_data):
    save_schema(new_data)
    stats = normalize_auto_schema()
    if stats['new_indexes'] > 0:
        print(f"Normalized {stats['new_indexes']} indexes")
```

### In CI/CD Pipeline

```yaml
# .github/workflows/schema-validation.yml
name: Validate Schema
on: [push]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Validate schema
        run: python3 scripts/verify_schema_duplicates.py
      - name: Auto-normalize if needed
        run: ./scripts/normalize_schema.sh
```

## File Locations

```
shikari/
├── mappings/
│   ├── normalize_manual.py      # Main normalization engine
│   ├── normalize_auto.py         # Integration helpers
│   ├── schemaSplunk.json         # Production schema
│   ├── README.md                 # Full documentation
│   └── INTEGRATION_GUIDE.md      # Quick start guide
│
├── scripts/
│   ├── normalize_schema.sh       # Shell wrapper (this directory)
│   ├── verify_schema_duplicates.py  # Verification tool
│   └── normalize_splunk_schema.py   # Legacy script
│
└── examples/
    └── schema_normalization_example.py  # Integration examples
```

## Common Tasks

### Task 1: Add New Data Source

```bash
# 1. Add to schemaSplunk.json (unnormalized query is OK)
{
  "cmd": {
    "new_firewall": "index=firewall src=10.0.0.1 dest=192.168.1.1 ..."
  }
}

# 2. Auto-normalize
./scripts/normalize_schema.sh

# 3. Verify
python3 scripts/verify_schema_duplicates.py
```

### Task 2: Update Field Mappings

```bash
# 1. Edit field mappings in normalize_manual.py
vim shikari/mappings/normalize_manual.py

# 2. Force re-normalization of all indexes
./scripts/normalize_schema.sh --force

# 3. Verify results
python3 scripts/verify_schema_duplicates.py
```

### Task 3: Validate Before Deployment

```bash
# Pre-deployment checklist
echo "1. Verifying schema normalization..."
python3 scripts/verify_schema_duplicates.py || exit 1

echo "2. Checking for unnormalized indexes..."
python3 -c "from shikari.mappings import validate_schema; exit(0 if validate_schema() else 1)"

echo "✅ Schema validation passed!"
```

### Task 4: Scheduled Maintenance

```bash
# Add to crontab for daily maintenance
0 2 * * * cd /path/to/shikari && ./scripts/normalize_schema.sh --silent
```

## Troubleshooting

### Problem: "No module named 'requests'"

**Solution:** Activate virtual environment first
```bash
source .venv/bin/activate
./scripts/normalize_schema.sh
```

### Problem: "Permission denied"

**Solution:** Make script executable
```bash
chmod +x scripts/normalize_schema.sh
./scripts/normalize_schema.sh
```

### Problem: Field conflicts detected

**Example:**
```
WARNING: Multiple fields map to 'dest_host': ['dest', 'dest_name']
```

**Solution:** Check the normalization output - conflicts are automatically resolved by:
1. Keeping the field that matches the target name
2. Excluding conflicting fields

To change behavior, edit `FIELD_NORMALIZATION` in `shikari/mappings/normalize_manual.py`.

### Problem: Important field excluded

**Solution:** Check if field is in exclusion list
```python
# In shikari/mappings/normalize_manual.py
FIELDS_TO_EXCLUDE = {
    'employee_id',  # Remove this if you need it
    # ...
}
```

Or add to security keywords:
```python
security_keywords = [
    # ... existing keywords ...
    'your_field_pattern',
]
```

## Best Practices

1. **Run normalization immediately after adding indexes**
   ```bash
   vim bespoke/mappings/schemas/schemaSplunk.json
   ./scripts/normalize_schema.sh
   ```

2. **Verify after normalization**
   ```bash
   python3 scripts/verify_schema_duplicates.py
   ```

3. **Commit normalized changes**
   ```bash
   git add bespoke/mappings/schemas/schemaSplunk.json
   git commit -m "Add and normalize new index"
   ```

4. **Test in development first**
   ```bash
   # Test with copy first
   cp bespoke/mappings/schemas/schemaSplunk.json /tmp/test.json
   ./scripts/normalize_schema.sh --schema /tmp/test.json
   # Review changes, then run on production schema
   ```

5. **Use silent mode in automation**
   ```bash
   # In automated scripts
   if ./scripts/normalize_schema.sh --silent; then
       echo "Normalization successful"
   else
       echo "Normalization failed"
       exit 1
   fi
   ```

## Related Documentation

- Mappings README - Full documentation
- Integration Guide - Quick start
- Examples - Code examples

## Support

For issues:
1. Check the full documentation
2. Review integration guide
3. Run verification: `python3 scripts/verify_schema_duplicates.py`
4. Check script output for specific errors
