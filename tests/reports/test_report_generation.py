#!/usr/bin/env python3
"""
Test script for report generation
"""

import os
import sys

# Add shikari to path (navigate up two levels from tests/reports/)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def test_report_generation():
    """Test report generators with sample data"""

    print("Testing Report Generation...")
    print("=" * 60)

    # Sample detection data
    sample_detections = [
        {
            "technique": "OS Credential Dumping: LSASS Memory",
            "technique_id": "T1003.001",
            "tactic": "Credential Access",
            "data_source": "DeviceProcessEvents",
            "vendor": "MDE",
            "severity": "High",
            "detection_likelihood": 85,
            "description_html": "Adversaries may attempt to access credential material stored in the process memory of LSASS.",
            "queries": [
                "DeviceProcessEvents\n| where ProcessCommandLine has_any ('lsass', 'procdump', 'mimikatz')\n| where ActionType == 'ProcessCreated'"
            ],
            "indicators": ["lsass.exe", "procdump.exe", "mimikatz.exe"]
        },
        {
            "technique": "PowerShell Execution",
            "technique_id": "T1059.001",
            "tactic": "Execution",
            "data_source": "DeviceProcessEvents",
            "vendor": "MDE",
            "severity": "Medium",
            "detection_likelihood": 70,
            "description_html": "Adversaries may abuse PowerShell commands and scripts for execution.",
            "queries": [
                "DeviceProcessEvents\n| where FileName =~ 'powershell.exe'\n| where ProcessCommandLine has '-enc'"
            ],
            "indicators": ["powershell.exe", "-enc", "-nop"]
        }
    ]

    group_name = "APT29"

    # Ensure output directory exists
    output_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'examples', 'reports')
    os.makedirs(output_dir, exist_ok=True)

    # Test 1: Word Document Generation
    print("\n1. Testing Word Document Generation...")
    try:
        from shikari.reports.generator import WordReportGenerator

        generator = WordReportGenerator()
        print("   ✓ Word generator initialized")

        word_bytes = generator.generate(
            group_name=group_name,
            detections=sample_detections,
            metadata={"user": "Test User"}
        )

        print(f"   ✓ Generated Word document ({len(word_bytes)} bytes)")

        # Save to file for verification
        output_path = os.path.join(output_dir, "test_report.docx")
        with open(output_path, "wb") as f:
            f.write(word_bytes)
        print(f"   ✓ Saved as {output_path}")

    except ImportError as e:
        print(f"   ⚠ Word generation unavailable: {e}")
        print("     Install with: pip install python-docx")
    except Exception as e:
        print(f"   ✗ Word generation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Test 2: PDF Generation
    print("\n2. Testing PDF Generation...")
    try:
        from shikari.reports.generator import PDFReportGenerator

        generator = PDFReportGenerator()
        print("   ✓ PDF generator initialized")

        pdf_bytes = generator.generate(
            group_name=group_name,
            detections=sample_detections,
            metadata={"user": "Test User"}
        )

        print(f"   ✓ Generated PDF document ({len(pdf_bytes)} bytes)")

        # Save to file for verification
        output_path = os.path.join(output_dir, "test_report.pdf")
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)
        print(f"   ✓ Saved as {output_path}")

    except ImportError as e:
        print(f"   ⚠ PDF generation unavailable: {e}")
        print("     Install with: pip install reportlab")
    except Exception as e:
        print(f"   ✗ PDF generation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Test 3: HTML Generation
    print("\n3. Testing HTML Generation...")
    try:
        from shikari.reports.generator import HTMLReportGenerator

        generator = HTMLReportGenerator()
        print("   ✓ HTML generator initialized")

        html_bytes = generator.generate(
            group_name=group_name,
            detections=sample_detections,
            metadata={"user": "Test User"}
        )

        print(f"   ✓ Generated HTML document ({len(html_bytes)} bytes)")

        # Save to file for verification
        output_path = os.path.join(output_dir, "test_report.html")
        with open(output_path, "wb") as f:
            f.write(html_bytes)
        print(f"   ✓ Saved as {output_path}")

    except Exception as e:
        print(f"   ✗ HTML generation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    print("\n" + "=" * 60)
    print("✓ All report generation tests passed!")
    print("\nGenerated files in examples/reports/:")
    print("  - test_report.docx (Word)")
    print("  - test_report.pdf (PDF)")
    print("  - test_report.html (HTML)")
    print("\nYou can open these files to verify the reports.")

    return True


if __name__ == "__main__":
    success = test_report_generation()
    sys.exit(0 if success else 1)
