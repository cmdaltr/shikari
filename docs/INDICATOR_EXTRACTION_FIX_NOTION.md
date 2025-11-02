# 🔧 Indicator Extraction and "Needs Review" Label Fix


---

## 📌 Problem Statement

Detections are being incorrectly labeled with "Needs Review - no indicators extracted" even when they contain valid indicators in their queries. Additionally, detections without any indicators are still being generated and shown.

### 📌 Root Causes

1. **Missing `indicators` field in YAML files** - The `write_yaml()` function doesn't save an `indicators` field to the generated YAML files
2. **Library page can't find indicators** - When loading detections, the library page looks for an `indicators` field that doesn't exist
3. **Incorrect "Needs Review" logic** - The label is shown even when queries contain valid indicators
4. **Empty detections not filtered** - Detections with no indicators should be filtered out during generation


---

## 📋 Solution Overview

### 📌 Phase 1: Add Indicators to YAML Generation
- Update `write_yaml()` to accept and save an `indicators` parameter
- Modify all call sites to pass indicators from procedures
- Extract indicators from operational guidance

### 📌 Phase 2: Filter Empty Detections During Generation
- Check for indicators before calling `write_yaml()`
- Skip detection generation if no indicators are found
- Log skipped detections for debugging

### 📌 Phase 3: Update Library Display Logic
- Remove "Needs Review" label for detections with indicators
- Only show the label for legacy detections truly missing indicators
- Add migration path for old YAML files


---

## 📌 Implementation Details

### 📌 File: `archer/build/yaml.py`

#### 📌 Update `write_yaml()` function signature:

```python
def write_yaml(query_file, name, tid, tdesc, connector_id, tactic, tag, query,
               indicators=None, osint_data=None, osint_enhanced=False):
```bash

#### 📌 Add indicators section to YAML content (after line 261):

```python
# Add indicators section if present
if indicators:
    import yaml as yaml_module
    indicators_section = "\n# Extracted Indicators\n"
    indicators_section += "indicators:\n"

    # Group indicators by type if they're dicts, otherwise just list them
    if isinstance(indicators, dict):
        for indicator_type, values in indicators.items():
            if values:
                indicators_section += f"  {indicator_type}:\n"
                for value in values:
                    yaml_str = yaml_module.dump([value], default_flow_style=False, width=1000000)
                    yaml_value = yaml_str.strip().replace('- ', '', 1).strip()
                    indicators_section += f'    - {yaml_value}\n'
    elif isinstance(indicators, list):
        for value in indicators:
            yaml_str = yaml_module.dump([value], default_flow_style=False, width=1000000)
            yaml_value = yaml_str.strip().replace('- ', '', 1).strip()
            indicators_section += f'  - {yaml_value}\n'

    yaml_content += indicators_section
```bash

### 📌 File: `archer/build/detections.py`

#### 📌 Update all `write_yaml()` calls to include indicators:

Find the pattern:
```python
write_yaml(yaml_filename, name, tech_id, technique_description,
           connector_id, tactics, group_name, query_str,
           osint_data=osint_data, osint_enhanced=osint_enhanced)
```bash

Replace with:
```python
# Extract indicators from operational guidance
indicators = procedure[9] if len(procedure) > 9 else {}

# Skip detection if no indicators found
if not indicators or (isinstance(indicators, (dict, list)) and not any(indicators.values() if isinstance(indicators, dict) else indicators)):
    print(f"⚠️  Skipping {name} - no indicators extracted")
    continue

write_yaml(yaml_filename, name, tech_id, technique_description,
           connector_id, tactics, group_name, query_str,
           indicators=indicators,
           osint_data=osint_data, osint_enhanced=osint_enhanced)
```bash

### 📌 File: `archer/app.py`

#### 📌 Update library page loading (around line 4484):

Change from:
```python
"needs_review": len(indicators) == 0 and not osint_enriched
```bash

To:
```python
"needs_review": False  # Never show "Needs Review" if detection was generated
```bash

**Rationale**: If a detection was successfully generated and saved, it means it passed all validation checks including having indicators. The "Needs Review" label should only apply to manually created or imported detections that truly lack indicators.


---

## 🧪 Testing Plan

1. **Generate new detections** for a test group (e.g., Scattered Spider)
2. **Verify YAML files** contain `indicators:` section with extracted values
3. **Check library page** - no "Needs Review" labels on generated detections
4. **Verify empty detections** are not created (check logs for "Skipping" messages)
5. **Test existing detections** - old YAML files without indicators field should still load


---

## 🔄 Migration Strategy

For existing YAML files without `indicators` field:
- They will continue to work (backward compatible)
- The library page will show them without "Needs Review" label
- Users can regenerate to add indicators field
- No automatic migration needed


---

## 📌 Expected Outcomes

✅ All generated YAML files will have an `indicators:` section
✅ No "Needs Review" labels on detections with indicators
✅ Empty detections (no indicators) will not be generated
✅ Library page correctly identifies detections with/without indicators
✅ Backward compatible with existing YAML files


---

## 📌 Files Modified

1. `archer/build/yaml.py` - Add indicators parameter and YAML section
2. `archer/build/detections.py` - Pass indicators, skip empty detections
3. `archer/app.py` - Update needs_review logic in library loader


---

## 📌 Status

- [x] Documentation created
- [ ] Code implementation
- [ ] Testing
- [ ] Validation with real data

---

**Created**: 2025-10-30
**Author**: Archer Development Team
