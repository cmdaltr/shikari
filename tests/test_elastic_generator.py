#!/usr/bin/env python3
"""
Test script for Elastic query generator
"""

import os
import sys

# Add archer to path
sys.path.insert(0, os.path.dirname(__file__))

from archer.build.elastic import ElasticQueryGenerator

def test_elastic_generator():
    """Test generating an Elastic query for a sample technique"""

    print("Testing Elastic Query Generator...")
    print("=" * 60)

    # Check for API key
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("⚠ ANTHROPIC_API_KEY not set - skipping API call test")
        print("Testing initialization and validation logic only...")

        # Create generator
        try:
            generator = ElasticQueryGenerator()
            print("✓ Generator initialized successfully")
        except Exception as e:
            print(f"✗ Failed to initialize generator: {e}")
            return False

        # Test validation logic
        print("\nTesting query validation...")

        # Valid query
        valid_query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"process.name": "lsass.exe"}}
                    ]
                }
            }
        }
        is_valid, error = generator.validate_query(valid_query)
        print(f"  Valid query test: {'✓ PASS' if is_valid else '✗ FAIL'}")

        # Invalid query (missing 'query' key)
        invalid_query = {"match": {"field": "value"}}
        is_valid, error = generator.validate_query(invalid_query)
        print(f"  Invalid query test: {'✓ PASS' if not is_valid else '✗ FAIL'}")
        if not is_valid:
            print(f"    Expected error: {error}")

        print("\n✓ Basic tests completed successfully!")
        return True

    # Create generator
    try:
        generator = ElasticQueryGenerator()
        print("✓ Generator initialized successfully")
    except Exception as e:
        print(f"✗ Failed to initialize generator: {e}")
        return False

    # Test query generation
    try:
        print("\nGenerating query for T1003.001 - OS Credential Dumping: LSASS Memory")
        result = generator.generate_query(
            technique_id="T1003.001",
            technique_name="OS Credential Dumping: LSASS Memory",
            tactic="Credential Access",
            description="Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
            osint_data=None,
            group_name="Test Group"
        )

        print("\n" + "=" * 60)
        print("Query Generation Result:")
        print("=" * 60)
        print(f"Query Name: {result.get('query_name', 'N/A')}")
        print(f"Severity: {result.get('severity', 'N/A')}")
        print(f"ECS Fields: {', '.join(result.get('ecs_fields', []))}")
        print(f"Data Streams: {', '.join(result.get('data_streams', []))}")
        print(f"Description: {result.get('description', 'N/A')}")

        # Validate query
        is_valid, error = generator.validate_query(result.get('query_dsl', {}))
        print(f"\nQuery Validation: {'✓ VALID' if is_valid else '✗ INVALID'}")
        if not is_valid:
            print(f"  Error: {error}")

        # Display formatted query
        if result.get('query_dsl'):
            print("\nQuery DSL:")
            print("-" * 60)
            formatted_query = generator.format_query_for_display(result['query_dsl'])
            print(formatted_query)

        if result.get('detection_notes'):
            print("\nDetection Notes:")
            print("-" * 60)
            print(result['detection_notes'])

        print("\n" + "=" * 60)
        print("✓ Test completed successfully!")
        return True

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_elastic_generator()
    sys.exit(0 if success else 1)
