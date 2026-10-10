"""
Unit tests for Blog Analyzer.

Tests the blog parsing and intelligence extraction logic with mocked
network requests, verifying actual extraction behavior.
"""
import pytest
from unittest.mock import patch, MagicMock
from bs4 import BeautifulSoup


def _addrinfo(ip):
    import socket
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]


class TestTechniqueExtraction:
    """Test ATT&CK technique ID extraction from text."""

    def test_extract_single_technique(self):
        """Test extracting a single technique ID."""
        from archer.parsers.blog_analyzer import _extract_techniques

        text = "The attacker used T1059.001 for execution."
        result = _extract_techniques(text)

        assert "T1059.001" in result
        assert len(result) == 1

    def test_extract_multiple_techniques(self):
        """Test extracting multiple technique IDs."""
        from archer.parsers.blog_analyzer import _extract_techniques

        text = """
        Initial access via T1566.001, followed by T1059.001 execution.
        Later they used T1003.001 for credential dumping.
        """
        result = _extract_techniques(text)

        assert "T1566.001" in result
        assert "T1059.001" in result
        assert "T1003.001" in result
        assert len(result) == 3

    def test_extract_parent_technique(self):
        """Test extracting parent technique without sub-technique."""
        from archer.parsers.blog_analyzer import _extract_techniques

        text = "They used T1059 for command execution."
        result = _extract_techniques(text)

        assert "T1059" in result

    def test_extract_techniques_deduplication(self):
        """Test that duplicate techniques are deduplicated."""
        from archer.parsers.blog_analyzer import _extract_techniques

        text = "T1059.001 was used. Later, T1059.001 was used again."
        result = _extract_techniques(text)

        assert result.count("T1059.001") == 1

    def test_extract_techniques_sorted(self):
        """Test that techniques are returned sorted."""
        from archer.parsers.blog_analyzer import _extract_techniques

        text = "T1566.001, T1003.001, T1059.001 were observed."
        result = _extract_techniques(text)

        assert result == sorted(result)

    def test_extract_no_techniques(self):
        """Test text with no techniques returns empty list."""
        from archer.parsers.blog_analyzer import _extract_techniques

        text = "This is a normal blog post with no threat intel."
        result = _extract_techniques(text)

        assert result == []

    def test_extract_invalid_technique_format_ignored(self):
        """Test that invalid technique formats are ignored."""
        from archer.parsers.blog_analyzer import _extract_techniques

        text = "T999 is invalid. T12345 too. But T1059.001 is valid."
        result = _extract_techniques(text)

        assert "T1059.001" in result
        assert "T999" not in result
        assert "T12345" not in result


class TestTacticsExtraction:
    """Test MITRE tactic extraction from text."""

    def test_extract_single_tactic(self):
        """Test extracting a single tactic."""
        from archer.parsers.blog_analyzer import _extract_tactics

        text = "The Execution phase involved running PowerShell scripts."
        result = _extract_tactics(text)

        assert "Execution" in result

    def test_extract_multiple_tactics(self):
        """Test extracting multiple tactics."""
        from archer.parsers.blog_analyzer import _extract_tactics

        text = """
        Initial Access was achieved through phishing.
        Execution involved PowerShell.
        Credential Access was performed using Mimikatz.
        """
        result = _extract_tactics(text)

        assert "Initial Access" in result
        assert "Execution" in result
        assert "Credential Access" in result

    def test_extract_tactics_case_insensitive(self):
        """Test that tactic extraction is case-insensitive."""
        from archer.parsers.blog_analyzer import _extract_tactics

        text = "INITIAL ACCESS and execution were observed."
        result = _extract_tactics(text)

        assert "Initial Access" in result
        assert "Execution" in result

    def test_extract_no_tactics(self):
        """Test text with no tactics returns empty list."""
        from archer.parsers.blog_analyzer import _extract_tactics

        text = "This is a normal text without MITRE tactics."
        result = _extract_tactics(text)

        assert result == []


class TestGroupNameExtraction:
    """Test threat group name extraction from text."""

    def test_extract_apt_group(self):
        """Test extracting APT group names."""
        from archer.parsers.blog_analyzer import _extract_group_name

        text = "This analysis covers APT29 activity."
        soup = BeautifulSoup("<html><body></body></html>", "html.parser")

        result = _extract_group_name(text, soup)

        assert result == "APT29"

    def test_extract_unc_group(self):
        """Test extracting UNC group names."""
        from archer.parsers.blog_analyzer import _extract_group_name

        text = "UNC2452 was observed targeting organizations."
        soup = BeautifulSoup("<html><body></body></html>", "html.parser")

        result = _extract_group_name(text, soup)

        assert result == "UNC2452"

    def test_extract_fin_group(self):
        """Test extracting FIN group names."""
        from archer.parsers.blog_analyzer import _extract_group_name

        text = "FIN7 continues to target retail organizations."
        soup = BeautifulSoup("<html><body></body></html>", "html.parser")

        result = _extract_group_name(text, soup)

        assert result == "FIN7"

    def test_extract_named_group(self):
        """Test extracting named threat groups."""
        from archer.parsers.blog_analyzer import _extract_group_name

        text = "Lazarus Group has been active recently."
        soup = BeautifulSoup("<html><body></body></html>", "html.parser")

        result = _extract_group_name(text, soup)

        assert result == "Lazarus Group"

    def test_extract_group_from_title(self):
        """Test extracting group name from HTML title."""
        from archer.parsers.blog_analyzer import _extract_group_name

        text = "Some analysis content without group name."
        soup = BeautifulSoup(
            "<html><head><title>APT28 Campaign Analysis</title></head><body></body></html>",
            "html.parser"
        )

        result = _extract_group_name(text, soup)

        assert result == "APT28"

    def test_no_group_name_found(self):
        """Test when no group name is found."""
        from archer.parsers.blog_analyzer import _extract_group_name

        text = "Generic threat activity observed."
        soup = BeautifulSoup("<html><body></body></html>", "html.parser")

        result = _extract_group_name(text, soup)

        assert result == ""


class TestProcedureExtraction:
    """Test procedure/TTPs extraction from text."""

    def test_extract_procedure_with_keywords(self):
        """Test extracting sentences with procedure keywords."""
        from archer.parsers.blog_analyzer import _extract_procedures

        text = """
        The attacker executed PowerShell commands to download malware.
        Then they uploaded the stolen data to a remote server.
        """
        result = _extract_procedures(text)

        # Should find sentences with 'executed' and 'uploaded'
        assert len(result) >= 1
        assert any("executed" in p.lower() or "uploaded" in p.lower() for p in result)

    def test_extract_procedures_length_filter(self):
        """Test that very short sentences are filtered out."""
        from archer.parsers.blog_analyzer import _extract_procedures

        text = "Run it. The attacker executed a sophisticated multi-stage attack chain."
        result = _extract_procedures(text)

        # Short sentence "Run it." should be filtered
        assert not any(len(p) < 30 for p in result)

    def test_extract_procedures_limit(self):
        """Test that procedures are limited to 10."""
        from archer.parsers.blog_analyzer import _extract_procedures

        # Create text with many procedure-like sentences
        sentences = [
            f"The attacker executed command {i} to perform malicious activity number {i}."
            for i in range(20)
        ]
        text = " ".join(sentences)

        result = _extract_procedures(text)

        assert len(result) <= 10


class TestDescriptionExtraction:
    """Test threat description extraction."""

    def test_extract_description_threat_keywords(self):
        """Test extracting description with threat keywords."""
        from archer.parsers.blog_analyzer import _extract_description

        text = """
        Short intro.

        The threat actor known as APT29 has been conducting espionage
        campaigns targeting government organizations worldwide.

        More details follow.
        """
        result = _extract_description(text)

        assert "threat actor" in result.lower() or "apt29" in result.lower()
        assert len(result) <= 500

    def test_extract_description_max_length(self):
        """Test that description is limited to 500 characters."""
        from archer.parsers.blog_analyzer import _extract_description

        # Create a very long paragraph
        long_para = "The threat actor " + "performed malicious activities. " * 50
        text = f"\n\n{long_para}\n\n"

        result = _extract_description(text)

        assert len(result) <= 500


class TestIOCExtraction:
    """Test IOC extraction from text."""

    def test_extract_iocs_returns_dict(self):
        """Test that IOC extraction returns a dictionary structure."""
        from archer.parsers.blog_analyzer import _extract_iocs

        text = "IOCs: evil.com, 192.168.1.100"

        result = _extract_iocs(text)

        # Verify structure
        assert isinstance(result, dict)


class TestAnalyzeBlogPost:
    """Test the main analyze_blog_post function."""

    def test_analyze_blog_post_success(self, sample_blog_html):
        """Test successful blog analysis."""
        from archer.parsers.blog_analyzer import analyze_blog_post
        import socket as socket_module

        # Mock socket.gethostbyname at module level since it's imported dynamically
        original_getaddrinfo = socket_module.getaddrinfo
        socket_module.getaddrinfo = MagicMock(return_value=_addrinfo("93.184.216.34"))

        try:
            with patch("archer.parsers.blog_analyzer.requests.get") as mock_get:
                # Setup mocks
                mock_response = MagicMock()
                mock_response.is_redirect = False
                mock_response.content = sample_blog_html.encode()
                mock_response.raise_for_status = MagicMock()
                mock_get.return_value = mock_response

                result = analyze_blog_post("https://example.com/blog/apt29")

                # Verify success
                assert result["success"] is True

                # Verify techniques extracted
                assert "T1566.001" in result["techniques"]
                assert "T1059.001" in result["techniques"]
                assert "T1003.001" in result["techniques"]

                # Verify group name extracted
                assert "APT29" in result["group_name"]

                # Verify tactics extracted
                assert len(result["tactics"]) > 0
        finally:
            # Restore original
            socket_module.getaddrinfo = original_getaddrinfo

    def test_boilerplate_filter_keeps_body_with_lookalike_classes(self):
        """CISA's <body> carries node-type-advisory; a substring 'ad' match stripped the whole page."""
        from archer.parsers.blog_analyzer import analyze_blog_post

        html = """
        <html><body class="path-node node-page--node-type-advisory">
          <nav class="usa-nav">T1190 in the menu</nav>
          <div class="l-page-section--with-heading">
            <p>Actors used T1566.004 voice phishing and T1621 MFA request generation.</p>
          </div>
          <div class="l-full__footer">T1105 in the footer</div>
        </body></html>
        """
        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_response.content = html.encode()
        mock_response.raise_for_status = MagicMock()

        with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")), \
             patch("archer.parsers.blog_analyzer.requests.get", return_value=mock_response):
            result = analyze_blog_post("https://www.cisa.gov/advisory")

        assert result["success"] is True
        assert "T1566.004" in result["techniques"]
        assert "T1621" in result["techniques"]
        # Real navigation and footer chrome is still stripped
        assert "T1190" not in result["techniques"]
        assert "T1105" not in result["techniques"]

    def test_analyze_blog_post_invalid_scheme(self):
        """Test that invalid URL schemes are rejected."""
        from archer.parsers.blog_analyzer import analyze_blog_post

        result = analyze_blog_post("ftp://example.com/blog")

        assert result["success"] is False
        assert "Invalid URL scheme" in result["error"]

    def test_analyze_blog_post_localhost_blocked(self):
        """Test that localhost URLs are blocked (SSRF prevention)."""
        from archer.parsers.blog_analyzer import analyze_blog_post

        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = _addrinfo("127.0.0.1")

            result = analyze_blog_post("http://localhost/admin")

            assert result["success"] is False
            assert "localhost" in result["error"].lower() or "not allowed" in result["error"].lower()

    def test_analyze_blog_post_private_ip_blocked(self):
        """Test that private IPs are blocked (SSRF prevention)."""
        from archer.parsers.blog_analyzer import analyze_blog_post

        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = _addrinfo("192.168.1.1")

            result = analyze_blog_post("http://internal.company.com/blog")

            assert result["success"] is False
            assert "private" in result["error"].lower() or "not allowed" in result["error"].lower()

    def test_analyze_blog_post_dns_failure(self):
        """Test handling of DNS resolution failure."""
        from archer.parsers.blog_analyzer import analyze_blog_post
        import socket

        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.side_effect = socket.gaierror("DNS lookup failed")

            result = analyze_blog_post("https://nonexistent.example.com/blog")

            assert result["success"] is False
            assert "resolve" in result["error"].lower()

    def test_analyze_blog_post_request_failure(self):
        """Test handling of HTTP request failure."""
        from archer.parsers.blog_analyzer import analyze_blog_post
        import requests

        with patch("socket.getaddrinfo") as mock_dns, \
             patch("archer.parsers.blog_analyzer.requests.get") as mock_get:

            mock_dns.return_value = _addrinfo("93.184.216.34")
            mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")

            result = analyze_blog_post("https://example.com/slow-blog")

            assert result["success"] is False
            assert "failed to fetch" in result["error"].lower() or "timed out" in result["error"].lower()

    def test_analyze_blog_post_response_too_large(self):
        """Test that oversized responses are rejected."""
        from archer.parsers.blog_analyzer import analyze_blog_post

        with patch("socket.getaddrinfo") as mock_dns, \
             patch("archer.parsers.blog_analyzer.requests.get") as mock_get:

            mock_dns.return_value = _addrinfo("93.184.216.34")

            # Create a response larger than 10MB
            mock_response = MagicMock()
            mock_response.is_redirect = False
            mock_response.content = b"x" * (11 * 1024 * 1024)  # 11MB
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            result = analyze_blog_post("https://example.com/huge-blog")

            assert result["success"] is False
            assert "too large" in result["error"].lower()


class TestAutoSearchBlogs:
    """Test automatic blog searching functionality."""

    def test_auto_search_crowdstrike_success(self):
        """Test successful Crowdstrike blog search."""
        from archer.parsers.blog_analyzer import auto_search_blogs

        with patch("archer.parsers.blog_analyzer.search_crowdstrike_blog") as mock_cs, \
             patch("archer.parsers.blog_analyzer.analyze_blog_post") as mock_analyze:

            mock_cs.return_value = "https://crowdstrike.com/blog/apt29"
            mock_analyze.return_value = {
                "success": True,
                "techniques": ["T1059.001"],
                "group_name": "APT29",
            }

            result = auto_search_blogs("APT29")

            assert result["success"] is True
            assert result["source"] == "Crowdstrike"
            assert result["source_url"] == "https://crowdstrike.com/blog/apt29"

    def test_auto_search_fallback_to_dfir(self):
        """Test fallback to DFIR Report when Crowdstrike has no results."""
        from archer.parsers.blog_analyzer import auto_search_blogs

        with patch("archer.parsers.blog_analyzer.search_crowdstrike_blog") as mock_cs, \
             patch("archer.parsers.blog_analyzer.search_dfir_report") as mock_dfir, \
             patch("archer.parsers.blog_analyzer.analyze_blog_post") as mock_analyze:

            mock_cs.return_value = None  # No Crowdstrike result
            mock_dfir.return_value = "https://thedfirreport.com/apt29"
            mock_analyze.return_value = {
                "success": True,
                "techniques": ["T1059.001"],
            }

            result = auto_search_blogs("APT29")

            assert result["success"] is True
            assert result["source"] == "The DFIR Report"

    def test_auto_search_no_results(self):
        """Test when no blog posts are found."""
        from archer.parsers.blog_analyzer import auto_search_blogs

        with patch("archer.parsers.blog_analyzer.search_crowdstrike_blog") as mock_cs, \
             patch("archer.parsers.blog_analyzer.search_dfir_report") as mock_dfir:

            mock_cs.return_value = None
            mock_dfir.return_value = None

            result = auto_search_blogs("UnknownGroup12345")

            assert result["success"] is False
            assert "no blog posts found" in result["error"].lower()
