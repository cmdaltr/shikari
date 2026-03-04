#!/usr/bin/env python3
"""
Test script for correlation-only report generation
"""

import os
import sys

# Add archer to path (navigate up two levels from tests/reports/)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def test_correlation_only_report():
    """Test report generators with only correlation data (no detections)"""

    print("Testing Correlation-Only Report Generation...")
    print("=" * 60)

    # Sample correlation data (NO detections)
    sample_correlations = [
        {
            "name": "APT29 Multi-Stage Attack Chain",
            "techniques": [
                {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment"},
                {"id": "T1059.001", "name": "PowerShell Execution"},
                {"id": "T1003.001", "name": "OS Credential Dumping: LSASS"}
            ],
            "severity": "Critical",
            "time_window": "1h",
            "vendor": "MDE",
            "combined_query": "DeviceProcessEvents\n| where Timestamp > ago(1h)\n| summarize count() by AccountName\n| where count_ > 3"
        },
        {
            "name": "Lateral Movement Pattern",
            "techniques": [
                {"id": "T1021.001", "name": "Remote Desktop Protocol"},
                {"id": "T1047", "name": "Windows Management Instrumentation"}
            ],
            "severity": "High",
            "time_window": "30m",
            "vendor": "Splunk",
            "combined_query": "index=windows earliest=-30m | stats count by src_ip, dest_ip"
        }
    ]

    group_name = "Correlation Rules"

    # Ensure output directory exists
    output_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'examples', 'reports')
    os.makedirs(output_dir, exist_ok=True)

    # Test 1: Word Document with Correlations Only
    print("\n1. Testing Word Document (Correlations Only)...")
    try:
        from archer.reports.generator import WordReportGenerator

        generator = WordReportGenerator()
        print("   ✓ Word generator initialized")

        # Empty detections list, only correlations
        word_bytes = generator.generate(
            group_name=group_name,
            detections=[],  # Empty!
            correlations=sample_correlations,
            metadata={"user": "Test User"}
        )

        print(f"   ✓ Generated Word document ({len(word_bytes)} bytes)")

        # Save to file
        output_path = os.path.join(output_dir, "test_correlation_report.docx")
        with open(output_path, "wb") as f:
            f.write(word_bytes)
        print(f"   ✓ Saved as {output_path}")

    except Exception as e:
        print(f"   ✗ Word generation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Test 2: PDF with Correlations Only
    print("\n2. Testing PDF (Correlations Only)...")
    try:
        from archer.reports.generator import PDFReportGenerator

        generator = PDFReportGenerator()
        print("   ✓ PDF generator initialized")

        pdf_bytes = generator.generate(
            group_name=group_name,
            detections=[],  # Empty!
            correlations=sample_correlations,
            metadata={"user": "Test User"}
        )

        print(f"   ✓ Generated PDF document ({len(pdf_bytes)} bytes)")

        output_path = os.path.join(output_dir, "test_correlation_report.pdf")
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)
        print(f"   ✓ Saved as {output_path}")

    except Exception as e:
        print(f"   ✗ PDF generation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    print("\n" + "=" * 60)
    print("✓ Correlation-only report generation tests passed!")
    print("\nGenerated files in examples/reports/:")
    print("  - test_correlation_report.docx (Word)")
    print("  - test_correlation_report.pdf (PDF)")
    print("\nThese reports contain ONLY correlation rules, no detections.")

    return True


if __name__ == "__main__":
    success = test_correlation_only_report()
    sys.exit(0 if success else 1)
