#!/usr/bin/env python3
"""
Unit Tests: File Intelligence Parser

Tests the file parsing and extraction functionality:
1. File type detection (PDF, TXT, JSON, YARA, etc.)
2. TTP extraction from text content
3. IOC extraction (hashes, IPs, domains, registry keys)
4. STIX JSON parsing

Can be run directly: python test_file_parser.py
Or via pytest: pytest test_file_parser.py
"""

import os
import sys
import json
from unittest.mock import MagicMock, patch

# Add shikari to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def test_parser_initialization():
    """Test that FileIntelligenceParser initializes successfully."""
    from shikari.parsers.file_intelligence import FileIntelligenceParser

    parser = FileIntelligenceParser()
    assert parser is not None
    assert hasattr(parser, "parse_file")
    return True


def test_detect_file_type_pdf():
    """Test PDF file type detection."""
    from shikari.parsers.file_intelligence import FileIntelligenceParser

    parser = FileIntelligenceParser()
    assert parser._detect_file_type("report.pdf") == "pdf"
    assert parser._detect_file_type("/path/to/threat_report.PDF") == "pdf"
    return True


def test_detect_file_type_text():
    """Test text file type detection."""
    from shikari.parsers.file_intelligence import FileIntelligenceParser

    parser = FileIntelligenceParser()
    assert parser._detect_file_type("notes.txt") == "text"
    assert parser._detect_file_type("README.md") == "text"
    return True


def test_detect_file_type_json():
    """Test JSON file type detection."""
    from shikari.parsers.file_intelligence import FileIntelligenceParser

    parser = FileIntelligenceParser()
    assert parser._detect_file_type("stix_bundle.json") == "json"
    return True


def test_detect_file_type_from_content():
    """Test file type detection from content."""
    from shikari.parsers.file_intelligence import FileIntelligenceParser

    parser = FileIntelligenceParser()

    # JSON content
    json_content = b'{"objects": [{"type": "indicator"}]}'
    assert parser._detect_file_type("unknown_file", json_content) == "json"

    # YARA content
    yara_content = b'rule test_rule { strings: $a = "test" condition: $a }'
    assert parser._detect_file_type("unknown_file", yara_content) == "yara"
    return True


def test_extract_ttps_from_text():
    """Test extracting MITRE ATT&CK techniques from text."""
    from shikari.parsers.file_intelligence import FileIntelligenceParser

    parser = FileIntelligenceParser()

    text = """
    The threat actor used T1566.001 (Spearphishing Attachment) for initial access.
    They then executed T1059.001 (PowerShell) to run malicious scripts.
    Finally, T1003.001 (LSASS Memory) was used for credential theft.
    """

    ttps = parser._extract_ttps(text)

    assert "T1566.001" in ttps
    assert "T1059.001" in ttps
    assert "T1003.001" in ttps
    return True


def test_extract_ttps_case_insensitive():
    """Test that TTP extraction is case insensitive."""
    from shikari.parsers.file_intelligence import FileIntelligenceParser

    parser = FileIntelligenceParser()

    text = "The attack used t1059.001 and T1078 techniques."
    ttps = parser._extract_ttps(text)

    assert "T1059.001" in ttps
    assert "T1078" in ttps
    return True


def test_extract_ttps_deduplicates():
    """Test that duplicate TTPs are removed."""
    from shikari.parsers.file_intelligence import FileIntelligenceParser

    parser = FileIntelligenceParser()

    text = "T1059.001 was used. Later, T1059.001 appeared again. And T1059.001 once more."
    ttps = parser._extract_ttps(text)

    assert ttps.count("T1059.001") == 1
    return True


def test_extract_iocs_hashes():
    """Test extracting file hashes from text."""
    from shikari.parsers.file_intelligence import FileIntelligenceParser

    parser = FileIntelligenceParser()

    text = """
    MD5: d41d8cd98f00b204e9800998ecf8427e
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """

    iocs = parser._extract_iocs(text)

    assert len(iocs["hash"]) >= 2
    return True


def test_extract_iocs_registry_keys():
    """Test extracting registry keys from text."""
    from shikari.parsers.file_intelligence import FileIntelligenceParser

    parser = FileIntelligenceParser()

    text = r"Persistence via HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
    iocs = parser._extract_iocs(text)

    assert len(iocs["reg"]) >= 1
    return True


def test_parse_text_file():
    """Test parsing plain text file."""
    from shikari.parsers.file_intelligence import FileIntelligenceParser

    parser = FileIntelligenceParser()

    content = b"""
    Threat Report: APT29

    Techniques observed: T1566.001, T1059.001
    C2 server: 10.0.0.100
    """

    result = parser.parse_file("report.txt", content)

    assert "ttps" in result
    assert "iocs" in result
    assert "T1566.001" in result["ttps"]
    return True


def test_parse_json_stix_format():
    """Test parsing STIX JSON format."""
    from shikari.parsers.file_intelligence import FileIntelligenceParser

    parser = FileIntelligenceParser()

    stix_data = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Spearphishing",
                "description": "T1566.001 - Spearphishing Attachment"
            }
        ]
    }
    content = json.dumps(stix_data).encode("utf-8")

    result = parser.parse_file("bundle.json", content)

    assert "ttps" in result
    assert "T1566.001" in result["ttps"]
    return True


def test_parse_file_returns_complete_result():
    """Test that parse_file returns complete result structure."""
    from shikari.parsers.file_intelligence import FileIntelligenceParser

    parser = FileIntelligenceParser()

    content = b"Sample threat report with T1059.001 technique."
    result = parser.parse_file("report.txt", content)

    # Check all required fields
    assert "ttps" in result
    assert "iocs" in result
    assert "raw_text" in result
    assert "metadata" in result

    # Check IOC structure
    assert "cmd" in result["iocs"]
    assert "reg" in result["iocs"]
    assert "ip" in result["iocs"]
    assert "domain" in result["iocs"]
    assert "hash" in result["iocs"]
    assert "file" in result["iocs"]
    return True


def test_file_upload_workflow():
    """Standalone test function for CLI execution."""
    print("Testing File Upload Intelligence Workflow...")
    print("=" * 60)

    tests = [
        ("Parser initialization", test_parser_initialization),
        ("Detect PDF file type", test_detect_file_type_pdf),
        ("Detect text file type", test_detect_file_type_text),
        ("Detect JSON file type", test_detect_file_type_json),
        ("Detect file type from content", test_detect_file_type_from_content),
        ("Extract TTPs from text", test_extract_ttps_from_text),
        ("TTP extraction case insensitive", test_extract_ttps_case_insensitive),
        ("TTP extraction deduplicates", test_extract_ttps_deduplicates),
        ("Extract hashes", test_extract_iocs_hashes),
        ("Extract registry keys", test_extract_iocs_registry_keys),
        ("Parse text file", test_parse_text_file),
        ("Parse STIX JSON", test_parse_json_stix_format),
        ("Complete result structure", test_parse_file_returns_complete_result),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            print(f"PASS: {name}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {name}")
            print(f"      {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {name}")
            print(f"       {e}")
            failed += 1

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")

    return failed == 0


if __name__ == "__main__":
    success = test_file_upload_workflow()
    sys.exit(0 if success else 1)
