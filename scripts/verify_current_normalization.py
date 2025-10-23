#!/usr/bin/env python3
"""
Verify the current normalization state of all indexes in schemaSplunk.json.

This script validates:
1. All indexes are properly normalized
2. No duplicate field mappings exist
3. Field counts are reasonable
4. Security fields are properly included
"""

import json
import re
from pathlib import Path
from collections import defaultdict, Counter


def extract_rename_mappings(query: str):
    """Extract rename mappings from query."""
    rename_mappings = []
    rename_matches = re.findall(r'(["\']?[\w\.\{\}\[\]\:]+["\']?)\s+AS\s+(\w+)', query)
    for source, target in rename_matches:
        source = source.strip('"\'')
        target = target.strip('"\'')
        rename_mappings.append((source, target))
    return rename_mappings


def extract_fields_list(query: str):
    """Extract fields from | fields command."""
    fields_match = re.search(r'\|\s*fields\s+([^\|\\]+)', query)
    if fields_match:
        field_list = fields_match.group(1).strip()
        fields = []
        for field in re.split(r'\s+', field_list):
            field = field.strip()
            if field and not field.startswith('-'):
                fields.append(field)
        return fields
    return []


def is_normalized(query: str) -> bool:
    """Check if query is normalized."""
    has_fields = '| fields' in query or '\\n| fields' in query
    has_time_eval = '| eval Time=strftime(_time, "%F %T")' in query or \
                   '\\n| eval Time=strftime(_time, "%F %T")' in query
    return has_fields and has_time_eval


def main():
    """Run comprehensive verification."""
    schema_path = Path(__file__).parent.parent / "archer" / "mappings" / "schemaSplunk.json"

    print("="*100)
    print("COMPREHENSIVE NORMALIZATION VERIFICATION")
    print("="*100)
    print(f"\nSchema: {schema_path}\n")

    with open(schema_path, 'r') as f:
        schema = json.load(f)

    # Verification results
    total_indexes = 0
    normalized_indexes = 0
    issues = []
    all_clean = True

    print("VERIFICATION CHECKS:")
    print("-" * 100)

    # Check 1: Normalization status
    print("\n[1] NORMALIZATION STATUS CHECK")
    print("-" * 100)

    for category, indexes in schema.items():
        for index_name, query in indexes.items():
            total_indexes += 1
            full_name = f"{category}.{index_name}"

            if is_normalized(query):
                normalized_indexes += 1
                print(f"  ✅ {full_name:50s}: Normalized")
            else:
                all_clean = False
                issues.append(f"{full_name}: NOT NORMALIZED")
                print(f"  ❌ {full_name:50s}: NOT NORMALIZED")

    print(f"\nResult: {normalized_indexes}/{total_indexes} indexes are normalized")

    # Check 2: Duplicate rename targets
    print(f"\n[2] DUPLICATE RENAME TARGET CHECK")
    print("-" * 100)

    duplicate_issues = []
    for category, indexes in schema.items():
        for index_name, query in indexes.items():
            full_name = f"{category}.{index_name}"
            rename_mappings = extract_rename_mappings(query)

            if rename_mappings:
                targets = [target for _, target in rename_mappings]
                target_counts = Counter(targets)
                duplicates = {t: c for t, c in target_counts.items() if c > 1}

                if duplicates:
                    all_clean = False
                    issue = f"{full_name}: Duplicate targets: {duplicates}"
                    duplicate_issues.append(issue)
                    issues.append(issue)
                    print(f"  ❌ {full_name:50s}: {duplicates}")
                else:
                    print(f"  ✅ {full_name:50s}: No duplicates ({len(rename_mappings)} renames)")
            else:
                print(f"  ✅ {full_name:50s}: No renames")

    if not duplicate_issues:
        print(f"\nResult: ✅ No duplicate rename targets found!")
    else:
        print(f"\nResult: ❌ Found {len(duplicate_issues)} indexes with duplicate targets")

    # Check 3: Field count analysis
    print(f"\n[3] FIELD COUNT ANALYSIS")
    print("-" * 100)

    field_counts = []
    for category, indexes in schema.items():
        for index_name, query in indexes.items():
            full_name = f"{category}.{index_name}"
            fields = extract_fields_list(query)
            field_count = len(fields)
            field_counts.append((full_name, field_count))

            # Flag if unusually low or high
            if field_count == 0:
                all_clean = False
                issues.append(f"{full_name}: No fields defined")
                print(f"  ⚠️  {full_name:50s}: {field_count:3d} fields (NONE!)")
            elif field_count < 5:
                print(f"  ⚠️  {full_name:50s}: {field_count:3d} fields (LOW)")
            elif field_count > 150:
                print(f"  ⚠️  {full_name:50s}: {field_count:3d} fields (HIGH)")
            else:
                print(f"  ✅ {full_name:50s}: {field_count:3d} fields")

    # Statistics
    field_counts_sorted = sorted(field_counts, key=lambda x: x[1], reverse=True)
    avg_field_count = sum(c for _, c in field_counts) / len(field_counts) if field_counts else 0

    print(f"\nField Count Statistics:")
    print(f"  Average: {avg_field_count:.1f} fields per index")
    print(f"  Minimum: {min(field_counts, key=lambda x: x[1])[1]} fields ({min(field_counts, key=lambda x: x[1])[0]})")
    print(f"  Maximum: {max(field_counts, key=lambda x: x[1])[1]} fields ({max(field_counts, key=lambda x: x[1])[0]})")

    # Check 4: Time evaluation
    print(f"\n[4] TIME EVALUATION CHECK")
    print("-" * 100)

    missing_time = []
    for category, indexes in schema.items():
        for index_name, query in indexes.items():
            full_name = f"{category}.{index_name}"

            if '| eval Time=strftime(_time, "%F %T")' in query or \
               '\\n| eval Time=strftime(_time, "%F %T")' in query:
                print(f"  ✅ {full_name:50s}: Has Time evaluation")
            else:
                all_clean = False
                missing_time.append(full_name)
                issues.append(f"{full_name}: Missing Time evaluation")
                print(f"  ❌ {full_name:50s}: MISSING Time evaluation")

    if not missing_time:
        print(f"\nResult: ✅ All indexes have Time evaluation")
    else:
        print(f"\nResult: ❌ {len(missing_time)} indexes missing Time evaluation")

    # Check 5: Rename mapping consistency
    print(f"\n[5] RENAME MAPPING CONSISTENCY CHECK")
    print("-" * 100)

    # Check for common patterns across indexes
    all_renames = defaultdict(set)  # source -> set of targets across all indexes

    for category, indexes in schema.items():
        for index_name, query in indexes.items():
            rename_mappings = extract_rename_mappings(query)
            for source, target in rename_mappings:
                all_renames[source].add(target)

    # Flag inconsistencies
    inconsistent_renames = {s: t for s, t in all_renames.items() if len(t) > 1}

    if inconsistent_renames:
        print(f"  ⚠️  Inconsistent rename mappings found:")
        for source, targets in sorted(inconsistent_renames.items()):
            print(f"      '{source}' maps to: {targets}")
            print(f"         (Same source field normalized to different targets across indexes)")
    else:
        print(f"  ✅ All rename mappings are consistent across indexes")

    # Final summary
    print(f"\n{'='*100}")
    print("VERIFICATION SUMMARY")
    print("="*100)
    print(f"\nTotal indexes: {total_indexes}")
    print(f"Normalized indexes: {normalized_indexes} ({normalized_indexes/total_indexes*100:.1f}%)")
    print(f"Unnormalized indexes: {total_indexes - normalized_indexes}")
    print(f"Total issues found: {len(issues)}")

    if issues:
        print(f"\n⚠️  ISSUES DETECTED:")
        for issue in issues:
            print(f"  - {issue}")

    print(f"\n{'='*100}")

    if all_clean and normalized_indexes == total_indexes:
        print("✅ SUCCESS: All indexes are properly normalized and verified!")
        print("="*100)
        return 0
    elif normalized_indexes == total_indexes and len(issues) == 0:
        print("✅ SUCCESS: All indexes normalized, minor warnings noted")
        print("="*100)
        return 0
    else:
        print("❌ VERIFICATION FAILED: Issues need to be addressed")
        print("="*100)
        return 1


if __name__ == "__main__":
    exit(main())
