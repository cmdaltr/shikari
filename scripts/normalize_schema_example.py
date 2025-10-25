#!/usr/bin/env python3
"""
Example integration of automatic schema normalization into Archer.

This demonstrates various ways to use the schema normalizer in your workflow.
"""

from archer.mappings import (
    normalize_auto_schema,
    is_schema_normalized,
    validate_schema,
    get_schema_stats,
    on_schema_update_hook,
    pre_query_validation_hook,
)


def example_1_basic_normalization():
    """Example 1: Basic auto-normalization of new indexes"""
    print("=" * 80)
    print("Example 1: Basic Auto-Normalization")
    print("=" * 80)

    # Run auto-normalization (only processes new/unnormalized indexes)
    stats = normalize_auto_schema()

    print(f"\nResults:")
    print(f"  Total indexes: {stats['total_indexes']}")
    print(f"  Already normalized: {stats['normalized_indexes']}")
    print(f"  Newly normalized: {stats['new_indexes']}")

    if stats["new_indexes"] > 0:
        print(f"\n✅ Successfully normalized {stats['new_indexes']} new indexes!")
    else:
        print(f"\n✅ All indexes already normalized - nothing to do!")


def example_2_schema_update_workflow():
    """Example 2: Integrate into schema update workflow"""
    print("\n" + "=" * 80)
    print("Example 2: Schema Update Workflow Integration")
    print("=" * 80)

    def update_schema_file(new_schema_data):
        """Simulated schema update function"""
        # In real implementation, this would save to schemaSplunk.json
        print("\n1. Updating schema file with new data...")
        # save_to_file(new_schema_data)

        # Auto-normalize any new indexes
        print("\n2. Running auto-normalization on new indexes...")
        on_schema_update_hook()

        print("\n✅ Schema update complete!")

    # Example usage
    new_data = {"cmd": {"new_firewall_index": "index=firewall src=10.0.0.1 dest=192.168.1.1 ..."}}
    # update_schema_file(new_data)
    print("\nThis would automatically normalize any new indexes added to the schema.")


def example_3_query_validation():
    """Example 3: Validate queries before execution"""
    print("\n" + "=" * 80)
    print("Example 3: Pre-Query Validation")
    print("=" * 80)

    def execute_detection_query(index_name, query):
        """Simulated query execution with validation"""
        print(f"\n1. Preparing to execute query for index: {index_name}")

        # Validate query is normalized
        if not is_schema_normalized(query):
            print(f"   ⚠️  Query is not normalized!")
            print(f"   Running auto-normalization...")

            stats = normalize_auto_schema(silent=True)

            if stats["new_indexes"] > 0:
                print(f"   ✅ Normalized {stats['new_indexes']} indexes")
                print(f"   Reloading normalized query...")
                # query = reload_query_from_schema(index_name)

        print(f"2. Executing normalized query...")
        # result = splunk_client.execute(query)
        print(f"   ✅ Query executed successfully")

    # Example: Check if a query is normalized
    normalized_query = "| fields _time user action\\n| eval Time=strftime(_time, '%F %T')"
    unnormalized_query = "index=test src=10.0.0.1 dest=192.168.1.1"

    print(f"\nChecking normalized query: {is_schema_normalized(normalized_query)}")
    print(f"Checking unnormalized query: {is_schema_normalized(unnormalized_query)}")


def example_4_schema_validation():
    """Example 4: Validate entire schema"""
    print("\n" + "=" * 80)
    print("Example 4: Schema Validation")
    print("=" * 80)

    # Get current schema statistics
    stats = get_schema_stats()

    print(f"\nSchema Statistics:")
    print(f"  Total indexes: {stats['total_indexes']}")
    print(f"  Normalized: {stats['normalized_count']}")
    print(f"  Unnormalized: {stats['unnormalized_count']}")

    if stats["unnormalized_count"] > 0:
        print(f"\n  Unnormalized indexes:")
        for index in stats["unnormalized_indexes"]:
            print(f"    - {index}")

        print(f"\n  Running auto-normalization...")
        normalize_auto_schema()
    else:
        print(f"\n  ✅ All indexes are normalized!")

    # Validate entire schema
    print(f"\nValidating schema...")
    is_valid = validate_schema()
    print(f"  Schema valid: {is_valid}")


def example_5_forced_renormalization():
    """Example 5: Force re-normalization of all indexes"""
    print("\n" + "=" * 80)
    print("Example 5: Forced Re-Normalization")
    print("=" * 80)

    print("\nThis is useful when:")
    print("  - Field normalization mappings have been updated")
    print("  - Security field filters have changed")
    print("  - You want to ensure consistency across all indexes")

    print("\nRunning forced re-normalization of ALL indexes...")
    # stats = normalize_auto_schema(force=True)

    print("\n⚠️  Note: This will re-process ALL indexes, not just new ones!")
    print("Use with caution in production environments.")


def example_6_integration_patterns():
    """Example 6: Common integration patterns"""
    print("\n" + "=" * 80)
    print("Example 6: Integration Patterns")
    print("=" * 80)

    print("\n1. Startup Validation Pattern:")
    print("   Run validation when application starts")
    print(
        """
    def app_startup():
        # Validate schema on startup
        if not validate_schema():
            print("Normalizing schema on startup...")
            normalize_auto_schema()
    """
    )

    print("\n2. Pre-Flight Check Pattern:")
    print("   Validate before critical operations")
    print(
        """
    def run_detection_batch():
        # Ensure schema is normalized before batch
        stats = get_schema_stats()
        if stats['unnormalized_count'] > 0:
            normalize_auto_schema()

        # Run detections
        for detection in detections:
            execute(detection)
    """
    )

    print("\n3. Scheduled Maintenance Pattern:")
    print("   Periodic schema normalization")
    print(
        """
    import schedule

    def schema_maintenance():
        stats = normalize_auto_schema()
        if stats['new_indexes'] > 0:
            send_notification(f"Normalized {stats['new_indexes']} indexes")

    # Run daily at 2 AM
    schedule.every().day.at("02:00").do(schema_maintenance)
    """
    )

    print("\n4. CI/CD Pipeline Pattern:")
    print("   Validate in continuous integration")
    print(
        """
    def test_schema_normalized():
        assert validate_schema(), "Schema contains unnormalized indexes"

    def ci_pipeline():
        # Run tests
        test_schema_normalized()

        # If tests fail, auto-fix
        if not validate_schema():
            normalize_auto_schema()
            commit_and_push("Auto-normalize schema")
    """
    )


def main():
    """Run all examples"""
    print("\n" + "=" * 80)
    print("ARCHER SCHEMA NORMALIZATION - INTEGRATION EXAMPLES")
    print("=" * 80)

    # Run examples
    example_1_basic_normalization()
    example_2_schema_update_workflow()
    example_3_query_validation()
    example_4_schema_validation()
    example_5_forced_renormalization()
    example_6_integration_patterns()

    print("\n" + "=" * 80)
    print("Examples complete!")
    print("=" * 80)
    print("\nFor more information, see:")
    print("  - archer/mappings/README.md")
    print("  - archer/mappings/normalize_manual.py")
    print("  - archer/mappings/normalize_auto.py")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
