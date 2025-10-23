#!/usr/bin/env python3
"""
Verify that all data sources in the normalized schema are free of duplicate field mappings.
"""

import json
from pathlib import Path
from collections import Counter


def main():
    """Verify all data sources for duplicate field mappings."""
    # Read the normalized schema
    schema_file = Path(__file__).parent.parent / "archer" / "mappings" / "schemaSplunk.json"

    with open(schema_file, 'r') as f:
        schema = json.load(f)

    print('='*80)
    print('VERIFYING ALL DATA SOURCES FOR DUPLICATE FIELD MAPPINGS')
    print('='*80)

    total_sources = 0
    sources_with_duplicates = 0
    all_clean = True

    for category, sources in schema.items():
        print(f'\n{category.upper()} Category:')
        print('-' * 80)

        for source_name, query in sources.items():
            total_sources += 1

            # Extract rename clause
            if '| rename' in query:
                rename_start = query.find('| rename') + len('| rename')
                rename_end = query.find('\\n|', rename_start)
                if rename_end == -1:
                    rename_end = len(query)

                rename_clause = query[rename_start:rename_end].strip()

                # Parse mappings
                targets = []
                parts = rename_clause.split(' AS ')

                for i in range(1, len(parts)):
                    # Get the target field (word after AS, before next field or end)
                    target = parts[i].split()[0]
                    targets.append(target)

                # Check for duplicates
                unique_targets = set(targets)
                if len(targets) != len(unique_targets):
                    all_clean = False
                    sources_with_duplicates += 1
                    print(f'  ❌ {source_name}: DUPLICATE TARGETS FOUND')

                    # Show which targets are duplicated
                    counts = Counter(targets)
                    duplicates = [t for t, c in counts.items() if c > 1]
                    print(f'     Duplicated targets: {duplicates}')
                else:
                    print(f'  ✅ {source_name}: OK ({len(targets)} unique mappings)')
            else:
                print(f'  ✅ {source_name}: No rename clause')

    print(f'\n{"="*80}')
    print(f'SUMMARY:')
    print(f'{"="*80}')
    print(f'Total data sources: {total_sources}')
    print(f'Sources with duplicate mappings: {sources_with_duplicates}')
    print(f'Clean sources: {total_sources - sources_with_duplicates}')

    if all_clean:
        print(f'\n✅ SUCCESS: All data sources are free of duplicate field mappings!')
    else:
        print(f'\n❌ ISSUES FOUND: {sources_with_duplicates} sources have duplicate mappings')


if __name__ == "__main__":
    main()
