#!/usr/bin/env python3
"""
Security Tests: SSRF Protection

Tests that the blog analyzer properly blocks Server-Side Request Forgery (SSRF) attacks:
1. Blocks requests to localhost/loopback addresses
2. Blocks requests to private IP ranges (RFC 1918)
3. Rejects non-HTTP(S) URL schemes
4. Handles empty/malformed URLs safely

Can be run directly: python test_ssrf_protection.py
Or via pytest: pytest test_ssrf_protection.py
"""

import os
import sys
from unittest.mock import MagicMock, patch

# Add shikari to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def _addrinfo(ip):
    """blog_analyzer resolves hosts with getaddrinfo so every resolved address is checked."""
    import socket
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]


def test_blog_analysis_ssrf_localhost():
    """Test that SSRF to localhost is blocked."""
    from shikari.parsers.blog_analyzer import analyze_blog_post

    with patch("socket.getaddrinfo", return_value=_addrinfo("127.0.0.1")):
        result = analyze_blog_post("http://localhost/admin")

    assert result["success"] is False
    error_lower = result.get("error", "").lower()
    assert "not allowed" in error_lower or "localhost" in error_lower
    return True


def test_blog_analysis_ssrf_private_ip():
    """Test that SSRF to private IPs is blocked."""
    from shikari.parsers.blog_analyzer import analyze_blog_post

    with patch("socket.getaddrinfo", return_value=_addrinfo("192.168.1.1")):
        result = analyze_blog_post("http://internal.corp/data")

    assert result["success"] is False
    error_lower = result.get("error", "").lower()
    assert "not allowed" in error_lower or "private" in error_lower
    return True


def test_blog_analysis_invalid_scheme():
    """Test that non-HTTP(S) schemes are rejected."""
    from shikari.parsers.blog_analyzer import analyze_blog_post

    result = analyze_blog_post("ftp://example.com/file")

    assert result["success"] is False
    error_lower = result.get("error", "").lower()
    assert "scheme" in error_lower or "http" in error_lower
    return True


def test_blog_analysis_empty_url():
    """Test handling of empty URL."""
    from shikari.parsers.blog_analyzer import analyze_blog_post

    result = analyze_blog_post("")

    assert result["success"] is False
    return True


def test_blog_analysis_extracts_techniques():
    """Test that blog analysis extracts MITRE techniques from content."""
    from shikari.parsers.blog_analyzer import analyze_blog_post

    mock_html = """
    <html>
    <head><title>APT29 Campaign</title></head>
    <body>
        <p>The threat actor used T1566.001 (Spearphishing).</p>
        <p>They executed T1059.001 (PowerShell) commands.</p>
        <p>T1003.001 was used for credential dumping.</p>
    </body>
    </html>
    """

    mock_response = MagicMock()
    mock_response.is_redirect = False
    mock_response.content = mock_html.encode()
    mock_response.raise_for_status = MagicMock()
    mock_response.headers = {"content-type": "text/html"}

    with patch("shikari.parsers.blog_analyzer.requests.get", return_value=mock_response), \
         patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
        result = analyze_blog_post("https://example.com/threat-report")

    if not result["success"]:
        raise AssertionError(f"Analysis failed: {result.get('error')}")

    assert "techniques" in result
    ttps = result.get("techniques", [])
    assert any("T1566" in t or "T1059" in t or "T1003" in t for t in ttps)
    return True


def test_ssrf_protection():
    """Standalone test function for CLI execution."""
    print("Testing SSRF Protection...")
    print("=" * 60)

    tests = [
        ("SSRF localhost blocking", test_blog_analysis_ssrf_localhost),
        ("SSRF private IP blocking", test_blog_analysis_ssrf_private_ip),
        ("Invalid scheme rejection", test_blog_analysis_invalid_scheme),
        ("Empty URL handling", test_blog_analysis_empty_url),
        ("Technique extraction (mock)", test_blog_analysis_extracts_techniques),
    ]

    passed = 0
    failed = 0
    skipped = 0

    for name, test_func in tests:
        try:
            result = test_func()
            if result is None:
                skipped += 1
            else:
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
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")

    return failed == 0


if __name__ == "__main__":
    success = test_ssrf_protection()
    sys.exit(0 if success else 1)
