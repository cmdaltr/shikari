# Archer Schema Normalizer

Automatic normalization for Splunk data source schemas in `schemaSplunk.json`.

## Overview

The Schema Normalizer automatically detects and processes new/unnormalized indexes added to `schemaSplunk.json`. It applies:

1. **Field Name Normalization** - Standardizes variant field names across data sources
   - Example: `src`, `source_ip`, `sourceIP`, `ClientIP` → `src_ip`
   - Example: `dvc`, `DeviceName` → `device`

2. **Security Field Filtering** - Keeps only security-relevant fields
   - Excludes: HR data, asset management, UI fields, organizational data
   - Includes: Threat indicators, network data, authentication, endpoints, etc.

3. **Conflict Resolution** - Handles multiple fields mapping to the same target
   - Prioritizes keeping original field names (no rename needed)
   - Excludes conflicting fields to prevent data loss

4. **Consistent Formatting** - Applies standard SPL query structure
   ```
   | rename <field_mappings>
   \n| fields <security_fields>
   \n| eval Time=strftime(_time, "%F %T")
   ```

## Detection Strategy

The normalizer identifies unnormalized indexes by checking for the required pattern:

**Normalized indexes have:**
- `| fields ...` command (field filtering)
- `| eval Time=strftime(_time, "%F %T")` (time formatting)

**Unnormalized indexes** are missing one or both of these, and will be automatically processed.

## Usage

### Command Line

```bash
# Normalize only new/unnormalized indexes (default)
python3 archer/mappings/normalize_manual.py

# Force re-normalization of ALL indexes
python3 archer/mappings/normalize_manual.py --force

# Normalize a different schema file
python3 archer/mappings/normalize_manual.py --schema /path/to/schema.json
```

### Python API

```python
from archer.mappings import SplunkSchemaNormalizer

# Initialize normalizer
normalizer = SplunkSchemaNormalizer()

# Normalize only new indexes
stats = normalizer.normalize_all()

# Force re-normalization of all indexes
stats = normalizer.normalize_all(force=True)

# Check results
print(f"Newly normalized: {stats['new_indexes']}")
print(f"Already normalized: {stats['normalized_indexes']}")
print(f"Errors: {len(stats['errors'])}")
```

### Integration into Archer Workflow

The normalizer can be integrated into various Archer workflows:

#### 1. On Schema File Update (Recommended)

Add to your schema update workflow to automatically normalize new indexes:

```python
from archer.mappings import SplunkSchemaNormalizer

def update_schema():
    # Load new schema data
    # ... your schema update logic ...

    # Auto-normalize any new indexes
    normalizer = SplunkSchemaNormalizer()
    stats = normalizer.normalize_all()

    if stats['new_indexes'] > 0:
        print(f"✅ Normalized {stats['new_indexes']} new indexes")

    return stats
```

#### 2. Pre-Query Validation

Ensure schemas are normalized before running queries:

```python
from archer.mappings import SplunkSchemaNormalizer
from archer.query.splunk import SplunkClient

def execute_detection_query(index_name, query):
    # Ensure schema is normalized
    normalizer = SplunkSchemaNormalizer()
    if not normalizer.is_normalized(query):
        print(f"⚠️  Index '{index_name}' not normalized, running auto-normalization...")
        normalizer.normalize_all()

    # Execute query
    client = SplunkClient()
    return client.execute_query(query)
```

#### 3. Scheduled Maintenance

Run as a scheduled task to keep schemas up-to-date:

```python
from archer.mappings import SplunkSchemaNormalizer
import schedule
import time

def schema_maintenance():
    normalizer = SplunkSchemaNormalizer()
    stats = normalizer.normalize_all()

    if stats['new_indexes'] > 0:
        # Send notification, log event, etc.
        print(f"🔧 Schema maintenance: normalized {stats['new_indexes']} indexes")

# Run daily at 2 AM
schedule.every().day.at("02:00").do(schema_maintenance)

while True:
    schedule.run_pending()
    time.sleep(3600)  # Check every hour
```

## Field Normalization Mappings

The normalizer uses a comprehensive mapping of field name variants to standard names:

| Category | Variants | Standard Name |
|----------|----------|---------------|
| Source IP | `src`, `source_ip`, `sourceIP`, `ClientIP`, `callerIpAddress` | `src_ip` |
| Destination IP | `dest_ip_internal`, `destination_ip` | `dest_ip` |
| Device | `dvc`, `DeviceName` | `device` |
| User | `suser` → `src_user`, `duser` → `dest_user` | Context-specific |
| Protocol | `proto`, `transport` | `protocol` |
| File Name | `fname`, `FileName`, `SourceFileName` | `file_name` |
| Hashes | `Sha1`, `Sha256` | `file_hash_sha1`, `file_hash_sha256` |
| Severity | `deviceSeverity` | `severity` |
| User Agent | `userAgent`, `UserAgent` | `http_user_agent` |
| Geography | `lat`, `lon` | `latitude`, `longitude` |

## Security Field Categories

Fields are kept if they match security-relevant patterns:

### Included Categories:
- **Threat Intelligence**: threat, attack, malware, virus, exploit, vulnerability, cve, mitre
- **Network Security**: src, dest, ip, port, protocol, dns, domain, url, http, ssl, tls
- **Authentication**: auth, login, credential, password, token, key, certificate, privilege
- **Endpoint**: process, command, file, registry, service, driver, executable, script
- **Data Security**: hash, encryption, signature, crypto
- **User/Entity**: user, account, device, host, computer, machine, endpoint
- **Operations**: action, event, operation, activity, status, result, error
- **Time/Correlation**: time, timestamp, created, modified, first, last, seen
- **Location**: location, country, region, city, geo, latitude, longitude, asn
- **Cloud**: cloud, aws, azure, gcp, tenant, subscription, instance, resource

### Excluded Categories:
- HR data (employee_id, department, manager, phone_number, etc.)
- Asset management (asset_tag, serial_number, purchase_date, warranty, cost, etc.)
- UI fields (display_name, label, description, notes, icon, theme, etc.)
- Compliance (audit_id, certification, attestation, approval_date, etc.)
- Workflow (task_id, workflow_status, assigned_to, due_date, etc.)

## Examples

### Before Normalization
```json
{
  "cmd": {
    "firewall_logs": "index=firewall src=10.0.0.1 dest=192.168.1.1 dvc=fw01 proto=tcp employee_id=12345 department=IT"
  }
}
```

### After Normalization
```json
{
  "cmd": {
    "firewall_logs": "| rename proto AS protocol src AS src_ip\\n| fields dest index proto src src_ip\\n| eval Time=strftime(_time, \"%F %T\")"
  }
}
```

**Changes:**
- ✅ Normalized `src` → `src_ip`
- ✅ Normalized `proto` → `protocol`
- ✅ Excluded `dvc` (conflicted with another field)
- ✅ Excluded `employee_id` (HR data, non-security)
- ✅ Excluded `department` (organizational data, non-security)
- ✅ Added `| fields` to filter to security-relevant fields
- ✅ Added `| eval Time=` for consistent time formatting

## Troubleshooting

### Conflict Warnings

If you see warnings like:
```
WARNING: Multiple fields map to 'dest_host': ['dest', 'dest_name']
```

This means multiple source fields would map to the same target. The normalizer resolves this by:
1. Keeping the field that already matches the target name (no rename needed)
2. Otherwise, keeping the first field
3. Excluding all other conflicting fields

### Field Exclusions

If important fields are being excluded, check:

1. **Is it in `FIELDS_TO_EXCLUDE`?** - Remove from exclusion list if needed
2. **Does it match security patterns?** - Add keyword to `security_keywords` in `filter_security_fields()`
3. **Is it conflicting with another field?** - Check conflict warnings and adjust `FIELD_NORMALIZATION` mappings

### Re-normalization

If you need to re-normalize already processed indexes (e.g., after updating field mappings):

```bash
python3 archer/mappings/normalize_manual.py --force
```

This will re-process ALL indexes, not just new ones.

## Maintenance

When adding new data sources or field name variants:

1. **Update `FIELD_NORMALIZATION`** - Add new field name variants
2. **Update `FIELDS_TO_EXCLUDE`** - Add non-security fields to exclude
3. **Update `security_keywords`** - Add security-relevant keywords if needed
4. **Run normalizer** - Process the updated schema
5. **Test** - Verify no duplicate field mappings with `verify_schema_duplicates.py`

## Files

- `normalize_manual.py` - Main normalizer implementation
- `schemaSplunk.json` - Production schema file
- `schemaSplunk.json.bak` - Automatic backup before changes
- `__init__.py` - Module exports for Python API
- `README.md` - This documentation

## Related Scripts

- `scripts/normalize_splunk_schema.py` - Original one-time normalization script
- `scripts/verify_schema_duplicates.py` - Verification tool for duplicate field mappings
