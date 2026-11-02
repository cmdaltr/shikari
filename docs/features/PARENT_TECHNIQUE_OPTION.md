# Parent Technique to Subtechnique Expansion Specification

## Objective
When a group uses a parent technique (e.g., T1036: Create Account), automatically expand to include all subtechniques (T1036.001, T1036.002, T1036.003) and generate detections for each subtechnique that has unique indicators from the parent.

## Requirements

### Core Logic
1. **Parent Technique Detection**: If group uses parent technique (T1036), generate detection for parent
2. **Subtechnique Expansion**: Fetch all subtechniques (T1036.001, T1036.002, T1036.003) from MITRE
3. **Procedure Fetching**: Get subtechnique-specific procedures and indicators from MITRE ATT&CK
4. **Indicator Deduplication**: Compare subtechnique indicators with parent indicators
5. **Conditional Generation**: Only create subtechnique detection if indicators are unique from parent
6. **Preserve Parent**: Always keep the parent technique detection

###Constraint
**DO NOT expand** if group only uses a subtechnique (T1036.001) without the parent:
- ✅ Generate T1036.001 only
- ❌ Do NOT include parent T1036
- ❌ Do NOT include other subtechniques (T1036.002, T1036.003)

## Implementation Steps

### Step 1: Add Helper Functions to retrieve.py

#### Function 1: `get_technique_id(bundle, technique_ref)`
Extract the technique ID (T####) from a technique reference.

```python
def get_technique_id(bundle, technique_ref):
    """
    Get the MITRE ATT&CK technique ID (e.g., T1036) from a technique reference.

    Args:
        bundle: MITRE ATT&CK bundle
        technique_ref: Technique reference ID (e.g., 'attack-pattern--...')

    Returns:
        Technique ID string (e.g., 'T1036') or None
    """
    for obj in bundle.objects:
        if obj.get("id") == technique_ref and obj.get("type") == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    return ref.get("external_id")
    return None
```

#### Function 2: `is_parent_technique(tech_id)`
Check if a technique ID is a parent (no dot notation).

```python
def is_parent_technique(tech_id):
    """
    Check if technique ID is a parent technique (e.g., T1036 vs T1036.001).

    Args:
        tech_id: Technique ID string (e.g., 'T1036' or 'T1036.001')

    Returns:
        Boolean: True if parent technique (no dot), False if subtechnique
    """
    return tech_id and "." not in tech_id
```

#### Function 3: `find_subtechniques(bundle, parent_tech_id)`
Find all subtechniques for a given parent technique.

```python
def find_subtechniques(bundle, parent_tech_id):
    """
    Find all subtechniques for a parent technique.

    Args:
        bundle: MITRE ATT&CK bundle
        parent_tech_id: Parent technique ID (e.g., 'T1036')

    Returns:
        List of tuples: [(subtechnique_ref, subtechnique_id, subtechnique_name), ...]
    """
    subtechniques = []

    for obj in bundle.objects:
        if obj.get("type") == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id")

                    # Check if this is a subtechnique of our parent
                    if tech_id and tech_id.startswith(parent_tech_id + "."):
                        subtechniques.append((
                            obj.get("id"),
                            tech_id,
                            obj.get("name")
                        ))
                        break

    return subtechniques
```

#### Function 4: `get_subtechnique_procedures(bundle, subtechnique_ref)`
Get procedures/indicators for a specific subtechnique.

```python
def get_subtechnique_procedures(bundle, subtechnique_ref):
    """
    Get procedures and indicators for a subtechnique.

    Args:
        bundle: MITRE ATT&CK bundle
        subtechnique_ref: Subtechnique reference ID

    Returns:
        Tuple: (description, tactics, detection_guidance, op_guidance)
    """
    for obj in bundle.objects:
        if obj.get("id") == subtechnique_ref and obj.get("type") == "attack-pattern":
            # Extract procedure information
            description = obj.get("description", "")
            tactics = consolidate_tactics(obj.get("kill_chain_phases", []))
            detection = obj.get("x_mitre_detection", "")

            # Parse for indicators
            red_info, blue_info = find_procedure_evidence("", description, detection)
            op_guidance, red_tools = red_info

            return (description, tactics, detection, op_guidance)

    return (None, None, None, None)
```

#### Function 5: `extract_indicators_from_guidance(op_guidance)`
Extract unique indicators from operational guidance.

```python
def extract_indicators_from_guidance(op_guidance):
    """
    Extract indicators from operational guidance dict.

    Args:
        op_guidance: Dictionary containing guidance data

    Returns:
        Set of indicator strings
    """
    indicators = set()

    if not isinstance(op_guidance, dict):
        return indicators

    for key, value in op_guidance.items():
        if isinstance(value, str):
            # Extract quoted values, file paths, commands, etc.
            import re

            # File names
            file_pattern = r'\b([a-zA-Z0-9_-]+\.(exe|dll|bat|ps1|sh|py))\b'
            indicators.update(re.findall(file_pattern, value, re.IGNORECASE))

            # Commands/processes
            cmd_pattern = r'\b(net|whoami|ipconfig|cmd|powershell|bash|sh)\b'
            indicators.update(re.findall(cmd_pattern, value, re.IGNORECASE))

            # Paths
            path_pattern = r'[A-Z]:\\[^\s"]+|/[a-z/]+/[a-z]+'
            indicators.update(re.findall(path_pattern, value, re.IGNORECASE))

    return indicators
```

### Step 2: Modify `retrieve_procedures()` Function

Add expansion logic after processing techniques:

```python
def retrieve_procedures(bundle, retrieved_techniques):
    print(f"[DEBUG] ===== RETRIEVE_PROCEDURES CALLED =====")
    print(f"[DEBUG] Number of retrieved_techniques: {len(retrieved_techniques)}")

    procedures = []
    group_ids = get_all_groups(bundle)

    # Track parent techniques for expansion
    parent_techniques = {}  # {parent_tech_id: (procedure_ref, indicators)}

    # Process each technique (existing logic)
    for group_procedure_desc, procedure_ref in retrieved_techniques:
        print(f"[DEBUG] Processing procedure_ref: {procedure_ref}")

        # Get technique ID
        tech_id = get_technique_id(bundle, procedure_ref)

        # Find the matching attack-pattern object
        for obj in bundle.objects:
            if obj.get("type") == "attack-pattern" and obj.get("id") == procedure_ref:
                # ... existing procedure processing logic ...

                # Track if this is a parent technique
                if tech_id and is_parent_technique(tech_id):
                    parent_indicators = extract_indicators_from_guidance(op_guidance)
                    parent_techniques[tech_id] = (procedure_ref, parent_indicators, procedures[-1])

                break

    # EXPANSION LOGIC: Process parent techniques to add subtechniques
    print(f"[DEBUG] Found {len(parent_techniques)} parent techniques to expand")

    for parent_tech_id, (parent_ref, parent_indicators, parent_proc) in parent_techniques.items():
        print(f"[DEBUG] Expanding parent technique: {parent_tech_id}")

        # Find all subtechniques
        subtechniques = find_subtechniques(bundle, parent_tech_id)
        print(f"[DEBUG]   Found {len(subtechniques)} subtechniques")

        for sub_ref, sub_tech_id, sub_name in subtechniques:
            # Get subtechnique-specific procedures
            sub_desc, sub_tactics, sub_detection, sub_op_guidance = get_subtechnique_procedures(bundle, sub_ref)

            if not sub_desc:
                continue

            # Extract indicators from subtechnique
            sub_indicators = extract_indicators_from_guidance(sub_op_guidance)

            # Check if subtechnique has unique indicators
            unique_indicators = sub_indicators - parent_indicators

            if len(unique_indicators) > 0:
                print(f"[DEBUG]   Subtechnique {sub_tech_id} has {len(unique_indicators)} unique indicators - creating detection")

                # Create procedure entry for subtechnique
                # Copy parent procedure structure but with subtechnique-specific data
                subtechnique_proc = list(parent_proc)  # Copy parent procedure
                subtechnique_proc[0] = sub_tech_id  # Update tech ID
                subtechnique_proc[1] = sub_name  # Update name
                subtechnique_proc[2] = sub_desc  # Update description
                subtechnique_proc[9] = sub_op_guidance  # Update indicators

                procedures.append(tuple(subtechnique_proc))
            else:
                print(f"[DEBUG]   Subtechnique {sub_tech_id} has no unique indicators - skipping")

    print(f"[DEBUG] ===== RETRIEVE_PROCEDURES COMPLETE: {len(procedures)} procedures =====")
    return procedures
```

### Step 3: Update Query Generation

The query generation logic in `detections.py` or `yaml.py` should already handle the new subtechnique procedures since they follow the same structure as parent techniques.

**No changes needed** if procedures are structured correctly.

### Step 4: Testing Strategy

#### Test Case 1: Parent Technique with Unique Subtechniques
**Input**: Group uses T1136 (Create Account)
**Expected**:
- T1136 detection generated
- T1136.001 (Local Account) detection generated IF unique indicators
- T1136.002 (Domain Account) detection generated IF unique indicators
- T1136.003 (Cloud Account) detection generated IF unique indicators

#### Test Case 2: Subtechnique Only (No Parent)
**Input**: Group uses T1136.001 (Local Account) only
**Expected**:
- T1136.001 detection generated
- ❌ T1136 NOT generated
- ❌ T1136.002 NOT generated
- ❌ T1136.003 NOT generated

#### Test Case 3: Parent with Duplicate Indicators
**Input**: Group uses T1055 (Process Injection), all subtechniques have same indicators as parent
**Expected**:
- T1055 detection generated
- ❌ No subtechnique detections (indicators are duplicates)

### Step 5: Verification Script

```python
#!/usr/bin/env python3
from shikari.mitre.enterprise import get_stix_data
from shikari.mitre.retrieve import retrieve_group, retrieve_techniques, retrieve_procedures

url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
bundle = get_stix_data(url)

# Test with Scattered Spider
group_id = retrieve_group(bundle, "Scattered Spider")
techniques = retrieve_techniques(bundle, group_id)
procedures = retrieve_procedures(bundle, techniques)

# Count parent vs subtechniques
parent_count = 0
sub_count = 0

for proc in procedures:
    tech_id = proc[0]
    if "." in tech_id:
        sub_count += 1
        print(f"Subtechnique: {tech_id} - {proc[1]}")
    else:
        parent_count += 1

print(f"\n✓ Parent techniques: {parent_count}")
print(f"✓ Subtechniques: {sub_count}")
print(f"✓ Total detections: {len(procedures)}")
```

## Implementation Checklist

- [ ] Add helper functions to `retrieve.py`
- [ ] Modify `retrieve_procedures()` to expand parent techniques
- [ ] Test with Scattered Spider group
- [ ] Verify no expansion when only subtechnique is used
- [ ] Verify parent is always preserved
- [ ] Verify subtechniques only created when unique indicators exist
- [ ] Update YAML generation to handle subtechniques
- [ ] Test query generation for subtechniques
- [ ] Verify indicator extraction works for subtechniques

## Expected Behavior Examples

### Example 1: T1136 (Create Account)
```
Before:
- T1136: Create Account (1 detection)

After:
- T1136: Create Account (parent - preserved)
- T1136.001: Local Account (unique indicators: net user, useradd)
- T1136.002: Domain Account (unique indicators: dsadd, New-ADUser)
- T1136.003: Cloud Account (unique indicators: aws iam, az ad user)
```

### Example 2: T1078.004 (Cloud Accounts) - Subtechnique Only
```
Before:
- T1078.004: Cloud Accounts (1 detection)

After:
- T1078.004: Cloud Accounts (1 detection)
# No T1078 parent, no other T1078.* subtechniques
```

## Edge Cases to Handle

1. **No Unique Indicators**: Subtechnique has same indicators as parent → Don't create subtechnique detection
2. **Missing Procedure Data**: Subtechnique has no description in MITRE → Skip subtechnique
3. **Multiple Parents**: Group uses multiple parent techniques → Expand each independently
4. **Mixed Usage**: Group uses both T1136 (parent) and T1136.001 (subtechnique) → Include both, expand parent to other subtechniques

## Files to Modify

1. **shikari/mitre/retrieve.py** (Primary changes)
   - Add 5 new helper functions
   - Modify `retrieve_procedures()` function

2. **Testing** (Create new test file)
   - `tests/test_subtechnique_expansion.py`

## Estimated Implementation Time
3-4 hours for implementation + testing

---

**Status**: Specification complete, ready for implementation
**Created**: 2025-10-30
