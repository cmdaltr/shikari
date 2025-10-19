#!/usr/bin/env python3
"""
Query Example Repository Management Script

Manage the query example repository for enhanced detection generation.

Usage:
    python scripts/manage_query_examples.py update    # Clone/update repositories
    python scripts/manage_query_examples.py rebuild   # Rebuild the index
    python scripts/manage_query_examples.py stats     # Show statistics
    python scripts/manage_query_examples.py search T1003  # Search for technique examples
"""

import sys
import os
import json
from pathlib import Path

# Add archer to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from archer.genai.query_examples import get_repository


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1].lower()
    repo = get_repository()

    if command == "update":
        print("Updating query example repositories...")
        print("This will clone the following repositories:")
        print("  - Splunk Security Content")
        print("  - SigmaHQ Sigma Rules")
        print("  - Microsoft Defender Hunting Queries")
        print()

        force = "--force" in sys.argv
        repo.update_repositories(force=force)
        print("\n✓ Update complete!")
        print("\nNext step: Run 'python scripts/manage_query_examples.py rebuild' to index the examples")

    elif command == "rebuild":
        print("Rebuilding query example index...")
        print("This will parse all downloaded repositories and build the search index.")
        print()

        repo.rebuild_index()
        print("\n✓ Index rebuild complete!")
        print("\nYou can now use enhanced query generation by setting:")
        print("  export ARCHER_ENHANCED_QUERIES=true")

    elif command == "stats":
        stats = repo.get_statistics()
        print("\n=== Query Example Repository Statistics ===\n")

        print(f"Last Updated: {stats.get('last_updated', 'Never')}")
        print(f"Total Examples: {stats.get('total_examples', 0)}")
        print()

        print("Examples by Vendor:")
        for vendor, count in stats.get("by_vendor", {}).items():
            print(f"  {vendor:20s}: {count:6d}")
        print()

        print(f"MITRE ATT&CK Techniques Covered: {len(stats.get('by_technique', {}))}")
        print()

        # Show top 10 techniques by example count
        by_technique = stats.get("by_technique", {})
        if by_technique:
            print("Top 10 Techniques by Example Count:")
            sorted_techniques = sorted(
                by_technique.items(), key=lambda x: x[1], reverse=True
            )[:10]
            for tech_id, count in sorted_techniques:
                print(f"  {tech_id:15s}: {count:3d} examples")

    elif command == "search":
        if len(sys.argv) < 3:
            print("Usage: python scripts/manage_query_examples.py search <technique_id>")
            print("Example: python scripts/manage_query_examples.py search T1003")
            sys.exit(1)

        technique_id = sys.argv[2].upper()
        if not technique_id.startswith("T"):
            technique_id = "T" + technique_id

        # Get vendor filter if provided
        vendor = None
        if len(sys.argv) > 3:
            vendor = sys.argv[3].lower()

        examples = repo.get_examples_for_technique(
            technique_id, vendor=vendor, limit=10
        )

        print(f"\n=== Examples for {technique_id} ===\n")

        if not examples:
            print(f"No examples found for {technique_id}")
            if vendor:
                print(f"(filtered by vendor: {vendor})")
            print("\nTry:")
            print("  1. Running 'rebuild' to update the index")
            print("  2. Searching without vendor filter")
            print("  3. Using a parent technique ID (e.g., T1003 instead of T1003.001)")
        else:
            print(f"Found {len(examples)} examples:")
            for idx, example in enumerate(examples, 1):
                print(f"\n{idx}. {example['name']}")
                print(f"   Source: {example['source']}")
                print(f"   Vendor: {example['vendor']}")
                print(f"   File: {example['file']}")
                if example.get("description"):
                    desc = example["description"][:100]
                    print(f"   Description: {desc}...")
                print(f"   Query length: {len(example['query'])} characters")

                # Show a snippet of the query
                query_snippet = example["query"][:200].replace("\n", "\n   ")
                print(f"   Query snippet:\n   {query_snippet}...")

    elif command == "test":
        print("\n=== Testing Query Example System ===\n")

        # Test 1: Repository exists
        print("1. Checking repository status...")
        stats = repo.get_statistics()
        if stats.get("total_examples", 0) == 0:
            print("   ⚠ No examples found. Run 'update' and 'rebuild' first.")
        else:
            print(f"   ✓ Repository has {stats['total_examples']} examples")

        # Test 2: Try to load enhancer
        print("\n2. Testing prompt enhancer...")
        try:
            from archer.genai.query_prompt_enhancer import get_enhancer

            enhancer = get_enhancer()
            print("   ✓ Prompt enhancer loaded successfully")

            # Test 3: Generate a test prompt
            print("\n3. Generating test prompt...")
            prompt = enhancer.enhance_query_generation_prompt(
                technique_id="T1003",
                technique_name="OS Credential Dumping",
                technique_description="Adversaries may attempt to dump credentials.",
                vendor="splunk",
                indicator_type="cmd",
                indicators=["lsass", "procdump"],
                tactic="Credential Access",
                num_examples=1,
            )
            print(f"   ✓ Generated prompt ({len(prompt)} characters)")

        except Exception as e:
            print(f"   ✗ Error: {e}")

        # Test 4: Check enhanced query generation
        print("\n4. Checking enhanced query generation...")
        enhanced_enabled = os.environ.get("ARCHER_ENHANCED_QUERIES", "false").lower()
        if enhanced_enabled in ["true", "1", "yes"]:
            print("   ✓ Enhanced query generation is ENABLED")
        else:
            print("   ⚠ Enhanced query generation is DISABLED")
            print("     Enable with: export ARCHER_ENHANCED_QUERIES=true")

        print("\n=== Test Complete ===\n")

    elif command == "enable":
        print("\nTo enable enhanced query generation, add to your environment:")
        print("\n  export ARCHER_ENHANCED_QUERIES=true")
        print("\nOr add to your .env file or shell profile.")
        print("\nVerify with:")
        print("  python scripts/manage_query_examples.py test")

    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
