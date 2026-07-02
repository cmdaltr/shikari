#!/usr/bin/env python3
"""
Comprehensive field analysis for all indexes in schemaSplunk.json.

This script:
1. Loads the production schema
2. Extracts all fields from each index
3. Analyzes field normalization mappings
4. Verifies security field filtering
5. Reports on each index's configuration
"""

import json
import re
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple


def extract_fields_from_query(query: str) -> Tuple[Set[str], Set[str], List[str]]:
    """
    Extract fields from a Splunk query.

    Returns:
        Tuple of (all_fields, fields_in_fields_clause, rename_mappings)
    """
    all_fields = set()
    fields_in_clause = set()
    rename_mappings = []

    # Extract from | fields command
    fields_match = re.search(r'\|\s*fields\s+([^\|\\]+)', query)
    if fields_match:
        field_list = fields_match.group(1).strip()
        for field in re.split(r'\s+', field_list):
            field = field.strip()
            if field and not field.startswith('-'):
                fields_in_clause.add(field)
                all_fields.add(field)

    # Extract from | rename command
    rename_matches = re.findall(r'(["\']?[\w\.\{\}\[\]\:]+["\']?)\s+AS\s+(\w+)', query)
    for source, target in rename_matches:
        source = source.strip('"\'')
        target = target.strip('"\'')
        all_fields.add(source)
        all_fields.add(target)
        rename_mappings.append((source, target))

    return all_fields, fields_in_clause, rename_mappings


def categorize_field(field_name: str) -> str:
    """Categorize a field by its security relevance."""
    field_lower = field_name.lower()

    # Security categories
    if any(kw in field_lower for kw in ['threat', 'attack', 'malware', 'virus', 'exploit', 'vulnerability', 'cve', 'mitre']):
        return 'Threat Intelligence'

    if any(kw in field_lower for kw in ['src', 'dest', 'ip', 'port', 'protocol', 'dns', 'domain', 'url', 'http']):
        return 'Network Security'

    if any(kw in field_lower for kw in ['auth', 'login', 'credential', 'password', 'token', 'key', 'privilege', 'permission']):
        return 'Authentication/Access'

    if any(kw in field_lower for kw in ['process', 'command', 'file', 'registry', 'service', 'driver', 'executable']):
        return 'Endpoint Security'

    if any(kw in field_lower for kw in ['hash', 'sha', 'md5', 'encryption', 'signature']):
        return 'Data Security'

    if any(kw in field_lower for kw in ['user', 'account', 'device', 'host', 'computer', 'machine']):
        return 'User/Entity'

    if any(kw in field_lower for kw in ['action', 'event', 'operation', 'activity', 'status', 'result', 'error']):
        return 'Operations/Events'

    if any(kw in field_lower for kw in ['time', 'date', 'created', 'modified', 'first', 'last']):
        return 'Temporal'

    if any(kw in field_lower for kw in ['location', 'country', 'region', 'city', 'geo', 'latitude', 'longitude']):
        return 'Geographic'

    if any(kw in field_lower for kw in ['cloud', 'aws', 'azure', 'gcp', 'tenant', 'subscription', 'instance', 'resource']):
        return 'Cloud/Infrastructure'

    if field_name in {'_time', '_raw', 'index', 'sourcetype', 'source', 'host'}:
        return 'Splunk Standard'

    return 'Other'


def analyze_schema():
    """Analyze all indexes in the production schema."""
    schema_path = Path(__file__).parent.parent / "archer" / "mappings" / "schemaSplunk.json"

    print("="*100)
    print("COMPREHENSIVE SCHEMA FIELD ANALYSIS")
    print("="*100)
    print(f"\nAnalyzing: {schema_path}\n")

    with open(schema_path, 'r') as f:
        schema = json.load(f)

    # Statistics
    total_indexes = 0
    total_fields = set()
    category_stats = defaultdict(int)
    rename_stats = defaultdict(int)

    # Detailed analysis per index
    index_details = []

    for category, indexes in schema.items():
        print(f"\n{'='*100}")
        print(f"{category.upper()} Category")
        print("="*100)

        for index_name, query in indexes.items():
            total_indexes += 1

            # Extract fields
            all_fields, fields_in_clause, rename_mappings = extract_fields_from_query(query)

            # Categorize fields
            field_categories = defaultdict(list)
            for field in fields_in_clause:
                cat = categorize_field(field)
                field_categories[cat].append(field)
                category_stats[cat] += 1

            # Track rename mappings
            rename_count = len(rename_mappings)
            rename_stats[index_name] = rename_count

            # Add to total fields
            total_fields.update(fields_in_clause)

            # Print index details
            print(f"\n{index_name}:")
            print(f"  Total fields in | fields clause: {len(fields_in_clause)}")
            print(f"  Rename mappings: {rename_count}")

            if rename_mappings:
                print(f"  Field renames:")
                for source, target in sorted(rename_mappings):
                    print(f"    - {source} → {target}")

            print(f"  Fields by category:")
            for cat in sorted(field_categories.keys()):
                fields = sorted(field_categories[cat])
                print(f"    [{cat}] ({len(fields)} fields)")
                # Show first 5 fields, then count if more
                if len(fields) <= 5:
                    for field in fields:
                        print(f"      • {field}")
                else:
                    for field in fields[:5]:
                        print(f"      • {field}")
                    print(f"      ... and {len(fields) - 5} more")

            # Store details for summary
            index_details.append({
                'category': category,
                'name': index_name,
                'field_count': len(fields_in_clause),
                'rename_count': rename_count,
                'categories': dict(field_categories)
            })

    # Print summary
    print(f"\n{'='*100}")
    print("OVERALL SUMMARY")
    print("="*100)
    print(f"\nTotal indexes analyzed: {total_indexes}")
    print(f"Unique fields across all indexes: {len(total_fields)}")

    print(f"\n\nFields by Category (across all indexes):")
    for cat in sorted(category_stats.keys(), key=lambda x: category_stats[x], reverse=True):
        print(f"  {cat:30s}: {category_stats[cat]:4d} fields")

    print(f"\n\nRename Mappings Summary:")
    total_renames = sum(rename_stats.values())
    print(f"  Total rename mappings: {total_renames}")
    print(f"  Indexes with renames: {sum(1 for c in rename_stats.values() if c > 0)}")
    print(f"  Indexes without renames: {sum(1 for c in rename_stats.values() if c == 0)}")

    print(f"\n\nTop 10 Indexes by Field Count:")
    sorted_indexes = sorted(index_details, key=lambda x: x['field_count'], reverse=True)
    for i, idx in enumerate(sorted_indexes[:10], 1):
        print(f"  {i:2d}. {idx['category']:3s}.{idx['name']:40s}: {idx['field_count']:3d} fields, {idx['rename_count']:2d} renames")

    # Check for potential issues
    print(f"\n{'='*100}")
    print("POTENTIAL ISSUES CHECK")
    print("="*100)

    # Check for duplicate targets in rename mappings
    print(f"\nChecking for duplicate rename targets...")
    issues_found = False

    for category, indexes in schema.items():
        for index_name, query in indexes.items():
            _, _, rename_mappings = extract_fields_from_query(query)

            if rename_mappings:
                targets = [target for _, target in rename_mappings]
                unique_targets = set(targets)

                if len(targets) != len(unique_targets):
                    issues_found = True
                    from collections import Counter
                    counts = Counter(targets)
                    duplicates = [t for t, c in counts.items() if c > 1]
                    print(f"  ⚠️  {category}.{index_name}: Duplicate targets: {duplicates}")

    if not issues_found:
        print(f"  ✅ No duplicate rename targets found!")

    # Check for indexes without Time eval
    print(f"\nChecking for indexes without Time evaluation...")
    missing_time = []

    for category, indexes in schema.items():
        for index_name, query in indexes.items():
            if '| eval Time=strftime(_time, "%F %T")' not in query and \
               '\\n| eval Time=strftime(_time, "%F %T")' not in query:
                missing_time.append(f"{category}.{index_name}")

    if missing_time:
        print(f"  ⚠️  Indexes missing Time evaluation:")
        for idx in missing_time:
            print(f"      - {idx}")
    else:
        print(f"  ✅ All indexes have Time evaluation!")

    # Export unique fields list
    print(f"\n{'='*100}")
    print("EXPORTING FIELD LISTS")
    print("="*100)

    # Export all unique fields
    output_dir = Path(__file__).parent.parent / "archer" / "mappings"
    fields_file = output_dir / "all_schema_fields.txt"

    with open(fields_file, 'w') as f:
        f.write("# All unique fields across all indexes in schemaSplunk.json\n")
        f.write(f"# Total: {len(total_fields)} fields\n")
        f.write(f"# Generated from {total_indexes} indexes\n\n")
        for field in sorted(total_fields):
            cat = categorize_field(field)
            f.write(f"{field:60s} # {cat}\n")

    print(f"\n  Exported {len(total_fields)} unique fields to: {fields_file}")

    # Export by category
    fields_by_cat_file = output_dir / "fields_by_category.txt"

    with open(fields_by_cat_file, 'w') as f:
        f.write("# Fields organized by security category\n")
        f.write(f"# Total: {len(total_fields)} fields across {total_indexes} indexes\n\n")

        for cat in sorted(category_stats.keys(), key=lambda x: category_stats[x], reverse=True):
            f.write(f"\n{'='*80}\n")
            f.write(f"{cat} ({category_stats[cat]} fields)\n")
            f.write(f"{'='*80}\n\n")

            cat_fields = [field for field in total_fields if categorize_field(field) == cat]
            for field in sorted(cat_fields):
                f.write(f"  {field}\n")

    print(f"  Exported categorized fields to: {fields_by_cat_file}")

    print(f"\n{'='*100}")
    print("ANALYSIS COMPLETE")
    print("="*100)
    print()


if __name__ == "__main__":
    analyze_schema()
