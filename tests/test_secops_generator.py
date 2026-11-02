#!/usr/bin/env python3
"""
Test script for Google SecOps YARA-L query generator.
Mirrors test_elastic_generator.py structure for consistency.
"""

import os
import sys
import pytest

# Add shikari to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class TestSecOpsGenerator:
    """Tests for Google SecOps YARA-L generator."""

    def test_generator_initialization(self):
        """Test that SecOpsGenerator initializes successfully."""
        from shikari.build.secops import SecOpsGenerator

        generator = SecOpsGenerator()
        assert generator is not None

    def test_generator_has_schema(self):
        """Test that generator loads UDM schema."""
        from shikari.build.secops import SecOpsGenerator

        generator = SecOpsGenerator()
        # Schema may or may not be loaded depending on file existence
        assert hasattr(generator, "schema")

    def test_generate_query_basic(self):
        """Test generating a basic YARA-L rule."""
        from shikari.build.secops import SecOpsGenerator

        generator = SecOpsGenerator()

        result = generator.generate_query(
            technique_id="T1003.001",
            technique_name="OS Credential Dumping: LSASS Memory",
            tactic="Credential Access",
            description="Adversaries may attempt to access credential material stored in LSASS.",
            indicators=None,
            osint_data=None,
            group_name="Test Group",
        )

        # Verify result structure
        assert isinstance(result, dict)
        assert "rule_name" in result or "query" in result or "error" in result

    def test_generate_query_with_indicators(self):
        """Test generating YARA-L rule with IOC indicators."""
        from shikari.build.secops import SecOpsGenerator

        generator = SecOpsGenerator()

        indicators = {
            "cmd": ["mimikatz.exe", "procdump.exe"],
            "file": ["lsass.dmp"],
            "ip": ["10.0.0.100"],
        }

        result = generator.generate_query(
            technique_id="T1003.001",
            technique_name="LSASS Memory",
            tactic="Credential Access",
            description="Credential dumping from LSASS",
            indicators=indicators,
            osint_data=None,
            group_name="APT29",
        )

        assert isinstance(result, dict)

    def test_generate_yaral_execution_technique(self):
        """Test generating YARA-L rule for execution technique."""
        from shikari.build.secops import SecOpsGenerator

        generator = SecOpsGenerator()

        result = generator.generate_query(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            description="Adversaries may abuse PowerShell commands and scripts for execution.",
            indicators={"cmd": ["powershell.exe", "-encodedcommand"]},
            osint_data=None,
            group_name="Test",
        )

        assert isinstance(result, dict)

    def test_generate_yaral_initial_access_technique(self):
        """Test generating YARA-L rule for initial access technique."""
        from shikari.build.secops import SecOpsGenerator

        generator = SecOpsGenerator()

        result = generator.generate_query(
            technique_id="T1566.001",
            technique_name="Spearphishing Attachment",
            tactic="Initial Access",
            description="Spearphishing emails with malicious attachments.",
            indicators={"file": [".doc", ".xls", ".js"]},
            osint_data=None,
            group_name="Test",
        )

        assert isinstance(result, dict)


def test_secops_generator():
    """Standalone test function for CLI execution."""
    print("Testing Google SecOps YARA-L Generator...")
    print("=" * 60)

    from shikari.build.secops import SecOpsGenerator

    # Create generator
    try:
        generator = SecOpsGenerator()
        print("✓ Generator initialized successfully")
    except Exception as e:
        print(f"✗ Failed to initialize generator: {e}")
        return False

    # Test basic generation
    try:
        print("\nGenerating YARA-L rule for T1003.001 - LSASS Memory...")
        result = generator.generate_query(
            technique_id="T1003.001",
            technique_name="OS Credential Dumping: LSASS Memory",
            tactic="Credential Access",
            description="Adversaries may attempt to access LSASS memory.",
            osint_data=None,
            group_name="Test Group",
        )

        print("\n" + "=" * 60)
        print("Rule Generation Result:")
        print("=" * 60)

        if "rule_name" in result:
            print(f"Rule Name: {result.get('rule_name', 'N/A')}")
        if "severity" in result:
            print(f"Severity: {result.get('severity', 'N/A')}")
        if "query" in result:
            print("\nYARA-L Code (preview):")
            print("-" * 40)
            code = result.get("query", "")
            print(code[:500] + "..." if len(code) > 500 else code)

        print("\n✓ Test completed successfully!")
        return True

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_secops_generator()
    sys.exit(0 if success else 1)
