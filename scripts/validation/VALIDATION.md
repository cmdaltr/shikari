# Validation Scripts

Schema validation, field mapping, and configuration verification utilities.

## Scripts

### setup_mappings.py
Interactive configuration tool for SIEM field mappings and index names.

**Usage**:
```bash
python scripts/validation/setup_mappings.py
```

**What it configures**:
- SIEM platform selection (MDE, Splunk, Sentinel, etc.)
- Index names for your environment
- Field name mappings
- Data source configurations

**Example**:
```bash
$ python scripts/validation/setup_mappings.py
Select your SIEM platform:
1. Microsoft Defender (MDE)
2. Splunk
3. Azure Sentinel
4. Elastic
Selection: 2

Enter Splunk index name for Windows logs: windows_security
Enter Splunk index name for Sysmon logs: sysmon
...
```

**When to run**:
- Initial Shikari setup
- After changing SIEM platforms
- When index names change in your environment

---

### verify_schema.py
Verify schema definitions and field mappings are valid.

**Usage**:
```bash
python scripts/validation/verify_schema.py
```

**What it checks**:
- Schema files are well-formed
- Required fields are present
- Field types are valid
- No circular dependencies
- Mapping consistency

**Example Output**:
```
✓ Schema validation passed
✓ All required fields present
✓ Field types valid
⚠ Warning: 3 unused fields detected
✗ Error: Invalid field type in windows_security.yml
```

---

### analyze_schema_fields.py
Analyze schema field usage across detections.

**Usage**:
```bash
python scripts/validation/analyze_schema_fields.py
```

**What it reports**:
- Most commonly used fields
- Unused schema fields
- Coverage by data source
- Field usage statistics

**Example Output**:
```
Schema Field Analysis
=====================

Top 10 Most Used Fields:
1. ProcessName          (1,247 detections)
2. CommandLine          (  892 detections)
3. ParentProcessName    (  654 detections)
...

Unused Fields: 23
Coverage: 87.3%
```

**Use cases**:
- Optimizing schema definitions
- Identifying gaps in detection coverage
- Planning data collection priorities

---

### generate_validation_matrix.py
Generate validation matrix showing detection coverage across platforms and techniques.

**Usage**:
```bash
python scripts/validation/generate_validation_matrix.py
```

**Output**:
- HTML validation matrix
- Coverage statistics by tactic
- Platform support breakdown
- Gap analysis

**Example**:
```bash
$ python scripts/validation/generate_validation_matrix.py
Generating validation matrix...
✓ Analyzed 1,247 detections
✓ Coverage: 78.4% of MITRE techniques
✓ Matrix saved to: reports/validation_matrix.html
```

**Output location**: `reports/validation_matrix.html`

---

## Workflows

### Initial Configuration

```bash
# 1. Configure field mappings for your SIEM
python scripts/validation/setup_mappings.py

# 2. Verify configuration is valid
python scripts/validation/verify_schema.py

# 3. Generate coverage report
python scripts/validation/generate_validation_matrix.py
```

### Regular Maintenance

```bash
# Monthly: Analyze field usage
python scripts/validation/analyze_schema_fields.py

# After adding detections: Verify schema
python scripts/validation/verify_schema.py

# Quarterly: Generate new validation matrix
python scripts/validation/generate_validation_matrix.py
```

### Troubleshooting Detection Issues

```bash
# 1. Verify schema is valid
python scripts/validation/verify_schema.py

# 2. Check field usage
python scripts/validation/analyze_schema_fields.py

# 3. Reconfigure mappings if needed
python scripts/validation/setup_mappings.py
```

## Related Documentation

- [Schema Normalization](../../docs/architecture/SCHEMA_NORMALIZATION.md)
- [Detection Validation](../../docs/features/DETECTION_VALIDATION.md)
- [Scripts Overview](../../docs/SCRIPTS.md)
