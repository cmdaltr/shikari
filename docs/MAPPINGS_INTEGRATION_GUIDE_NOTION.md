# 🔗 Archer Schema Normalization - Integration Guide


---

## ⚡ Quick Start

### 💻 Command Line Usage

```bash
# Normalize only new/unnormalized indexes (recommended)
python3 archer/mappings/normalize_manual.py

# Force re-normalization of all indexes
python3 archer/mappings/normalize_manual.py --force

# Normalize a different schema file
python3 archer/mappings/normalize_manual.py --schema /path/to/schema.json
```bash

### 💻 Python API Usage

```python
from archer.mappings import normalize_auto_schema

# Simple one-liner to normalize new indexes
stats = normalize_auto_schema()

# Check results
if stats['new_indexes'] > 0:
    print(f"✅ Normalized {stats['new_indexes']} new indexes")
```bash


---

## 📌 How It Works

### 📌 1. Detection

The normalizer automatically identifies unnormalized indexes by checking for:

```bash
|  |
|  |
```bash

**If both are present** → Index is normalized (skipped)
**If either is missing** → Index needs normalization

### 📌 2. Normalization Process

For each unnormalized index:

1. **Extract Fields** - Parse the SPL query to find all field references
2. **Filter Security Fields** - Keep only security-relevant fields (remove HR, asset management, UI data)
3. **Normalize Names** - Map variant field names to standard names (e.g., `src` → `src_ip`)
4. **Detect Conflicts** - Identify multiple fields mapping to same target
| rename ... | fields ... |

### 📌 3. Example Transformation

**Before:**
```splunk
index=firewall src=10.0.0.1 dest=192.168.1.1 dvc=firewall01 proto=tcp
action=blocked employee_id=12345 department=IT
```bash

**After:**
```bash
|  |
|  |
|  |
```bash

**Excluded:**
- `dvc` - Conflicting field
- `proto` - Already have protocol field
- `employee_id` - HR data
- `department` - Organizational data


---

## 🔗 Integration Patterns

### 📌 Pattern 1: Schema Update Hook

Automatically normalize when schema file is updated:

```python
from archer.mappings import on_schema_update_hook

def update_schema(new_data):
    # Save schema updates
    save_to_file(new_data)

    # Auto-normalize new indexes
    on_schema_update_hook()
```bash

### 📌 Pattern 2: Application Startup

Ensure schema is normalized on app startup:

```python
from archer.mappings import validate_schema, normalize_auto_schema

def app_startup():
    if not validate_schema():
        print("Normalizing schema on startup...")
        normalize_auto_schema()
```bash

### 📌 Pattern 3: Pre-Query Validation

Validate before executing queries:

```python
from archer.mappings import pre_query_validation_hook

def execute_query(index_name, query):
    # Validate and auto-normalize if needed
    if not pre_query_validation_hook(index_name, query):
        # Reload normalized query
        query = reload_from_schema(index_name)

    # Execute
    return splunk_client.execute(query)
```bash

### 📌 Pattern 4: Scheduled Maintenance

Run periodic normalization checks:

```python
from archer.mappings import normalize_auto_schema
import schedule

def schema_maintenance():
    stats = normalize_auto_schema()
    if stats['new_indexes'] > 0:
        notify(f"Normalized {stats['new_indexes']} indexes")

schedule.every().day.at("02:00").do(schema_maintenance)
```bash

### 📌 Pattern 5: CI/CD Pipeline

Validate in continuous integration:

```python
from archer.mappings import validate_schema, normalize_auto_schema

def test_schema():
    """Run in CI/CD pipeline"""
    assert validate_schema(), "Unnormalized indexes found"

def auto_fix_schema():
    """Auto-fix and commit"""
    if not validate_schema():
        stats = normalize_auto_schema()
        commit_changes(f"Auto-normalize {stats['new_indexes']} indexes")
```bash


---

## 🔌 API Reference

### `normalize_auto_schema(schema_path=None, force=False, silent=False)`

Main entry point for normalization.

**Parameters:**
- `schema_path` (Path, optional) - Path to schema file (default: archer/mappings/schemaSplunk.json)
- `force` (bool) - Force re-normalization of all indexes (default: False)
- `silent` (bool) - Suppress output (default: False)

**Returns:**
```python
{
    'total_indexes': 29,
    'normalized_indexes': 26,
    'new_indexes': 3,
    'updated_indexes': 0,
    'errors': []
}
```bash

### `is_schema_normalized(query)`

Check if a single query is normalized.

**Parameters:**
- `query` (str) - SPL query string

**Returns:** `bool` - True if normalized

### `validate_schema()`

Validate entire schema for normalization.

**Returns:** `bool` - True if all indexes normalized

### `get_schema_stats()`

Get schema normalization statistics.

**Returns:**
```python
{
    'total_indexes': 29,
    'normalized_count': 26,
    'unnormalized_count': 3,
    'unnormalized_indexes': ['cmd.new_index', 'cve.test_waf']
}
```bash

### `on_schema_update_hook()`

Hook for schema update events.

**Returns:** Normalization stats dict

### `pre_query_validation_hook(index_name, query)`

Hook for pre-query validation.

**Parameters:**
- `index_name` (str) - Index name
- `query` (str) - SPL query

**Returns:** `bool` - True if normalized


---

## 📚 Field Normalization Reference

### 📌 Standard Mappings

| Original | Normalized | Category |
| ---------- | ----------- | ---------- |
| `src`, `source_ip`, `sourceIP`, `ClientIP` | `src_ip` | Source IP |
| `dvc`, `DeviceName` | `device` | Device |
| `suser` | `src_user` | Source User |
| `duser` | `dest_user` | Dest User |
| `proto`, `transport` | `protocol` | Protocol |
| `fname`, `FileName` | `file_name` | File Name |
| `Sha1`, `Sha256` | `file_hash_sha1`, `file_hash_sha256` | File Hash |
| `userAgent`, `UserAgent` | `http_user_agent` | User Agent |
| `lat`, `lon` | `latitude`, `longitude` | Geography |
| `EventCode` | `event_code` | Windows Event |
| `ComputerName` | `computer_name` | Windows Host |

### 📌 Excluded Field Categories

**HR and Organizational:**
- employee_id, manager, department, cost_center, business_unit
- phone_number, personal_email, hire_date, job_title

**Asset Management:**
- asset_tag, serial_number, purchase_date, warranty_expiration
- vendor, model, cost, depreciation

**UI and Display:**
- display_name, friendly_name, label, description, notes
- color, icon, theme, dashboard

**Compliance (low security value):**
- audit_id, certification, attestation, approval_date


---

## 🧪 Testing

### 📌 Unit Test Example

```python
import unittest
from archer.mappings import normalize_auto_schema, is_schema_normalized

class TestSchemaNormalization(unittest.TestCase):
    def test_normalized_query_detection(self):
        """Test normalized query detection"""
| fields _time user\\n |
        self.assertTrue(is_schema_normalized(normalized))

        unnormalized = "index=test src=10.0.0.1"
        self.assertFalse(is_schema_normalized(unnormalized))

    def test_auto_normalization(self):
        """Test auto-normalization"""
        stats = normalize_auto_schema(schema_path='/tmp/test.json')
        self.assertEqual(stats['errors'], [])
```bash

### 🔗 Integration Test Example

```python
def test_full_workflow():
    """Test complete normalization workflow"""
    # Create test schema with unnormalized index
    create_test_schema('/tmp/test.json')

    # Run normalization
    stats = normalize_auto_schema(schema_path='/tmp/test.json')

    # Verify results
    assert stats['new_indexes'] > 0
    assert stats['errors'] == []

    # Verify schema is now normalized
    assert validate_schema()
```bash


---

## 🔧 Troubleshooting

### 📌 Issue: Fields Being Excluded

**Problem:** Important security fields are being excluded.

**Solution:**
1. Check if field is in `FIELDS_TO_EXCLUDE` set in `normalize_manual.py`
2. Check if field matches `security_keywords` patterns
3. Add field to security keywords if needed:

```python
security_keywords = [
    # ... existing keywords ...
    'your_field_pattern',
]
```bash

### 📌 Issue: Field Name Conflicts

**Problem:** Multiple fields map to same target causing data loss.

**Example:**
```bash
WARNING: Multiple fields map to 'dest_host': ['dest', 'dest_name']
```bash

**Solution:**
The normalizer automatically resolves by:
1. Keeping field that matches target name (no rename needed)
2. Otherwise, keeping first field
3. Excluding conflicting fields

To change behavior, update `FIELD_NORMALIZATION` mappings:

```python
FIELD_NORMALIZATION = {
    'dest': 'dest_host',
    'dest_name': 'dest_hostname',  # Map to different target
}
```bash

### 📌 Issue: Query Not Detected as Normalized

**Problem:** Query appears normalized but normalizer doesn't recognize it.

**Check:**
|  |
|  |
|  |

### ⚡ Issue: Performance with Large Schemas

**Problem:** Normalization takes too long.

**Solutions:**
1. Use `silent=True` to suppress output
2. Run during off-peak hours
3. Use `force=False` (default) to only process new indexes


---

## ⭐ Best Practices

### 📌 1. Run Normalization Early and Often

- Run on schema file creation/update
- Run on application startup
- Run in CI/CD pipeline

### 📌 2. Monitor Normalization Results

```python
stats = normalize_auto_schema()

if stats['new_indexes'] > 0:
    logger.info(f"Normalized {stats['new_indexes']} indexes")

if stats['errors']:
    logger.error(f"Normalization errors: {stats['errors']}")
    alert_team(stats['errors'])
```bash

### 📌 3. Version Control Schema Changes

```bash
# Before normalization
git add archer/mappings/schemaSplunk.json
git commit -m "Add new firewall index"

# After normalization
python3 archer/mappings/normalize_manual.py
git add archer/mappings/schemaSplunk.json
git commit -m "Auto-normalize new firewall index"
```bash

### 👨‍💻 4. Test in Development First

```python
# Development
stats = normalize_auto_schema(schema_path='/path/to/dev/schema.json')

# Review results
review_normalized_queries(stats)

# Production (only after validation)
stats = normalize_auto_schema()  # Uses production schema
```bash

### 💾 5. Backup Before Normalization

The normalizer automatically creates backups:
```bash
schemaSplunk.json      # Updated file
schemaSplunk.json.bak  # Backup of original
```bash

To manually backup:
```bash
cp archer/mappings/schemaSplunk.json archer/mappings/schemaSplunk.json.backup
python3 archer/mappings/normalize_manual.py
```bash


---

## 📌 Files

- `normalize_manual.py` - Main normalizer class
- `normalize_auto.py` - Convenience functions for integration
- `__init__.py` - Module exports
- `README.md` - Detailed documentation
- `INTEGRATION_GUIDE.md` - This file
- `schemaSplunk.json` - Production schema


---

## 📝 Examples

See `examples/schema_normalization_example.py` for comprehensive integration examples.


---

## 🆘 Support

For issues or questions:
1. Check [README.md](README.md) for detailed documentation
2. Review `normalize_manual.py` source code
3. Run verification: `python3 scripts/verify_schema_duplicates.py`
4. Check logs for specific error messages
