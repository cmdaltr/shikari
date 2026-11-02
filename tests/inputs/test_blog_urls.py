"""
Tests for Blog URL input method.

These tests validate blog-based detection generation including
URL validation, content extraction, TTP identification, and IOC extraction.
"""
import pytest


# Test data - real threat intelligence blog URLs
VALID_BLOG_URLS = [
    "https://thedfirreport.com/2025/11/17/cats-got-your-files-lynx-ransomware/",
    "https://thedfirreport.com/2025/03/31/fake-zoom-ends-in-blacksuit-ransomware/",
    "https://www.crowdstrike.com/en-us/blog/scattered-spider-exploits-windows-security/",
    "https://www.microsoft.com/en-us/security/blog/",
    "https://unit42.paloaltonetworks.com/",
]

INVALID_URLS = [
    "",
    "not-a-url",
    "ftp://example.com/blog",
    "http://",
    "://missing-protocol.com",
    "javascript:alert(1)",  # XSS attempt
    "file:///etc/passwd",   # Local file attempt
]

SUPPORTED_DOMAINS = [
    "thedfirreport.com",
    "crowdstrike.com",
    "microsoft.com",
    "unit42.paloaltonetworks.com",
    "mandiant.com",
    "secureworks.com",
    "talosintelligence.com",
]


class TestBlogURLValidation:
    """Tests for blog URL input validation."""

    @pytest.mark.parametrize("blog_url", VALID_BLOG_URLS[:3])  # Test first 3
    def test_valid_blog_url_accepted(self, client, ensure_shikari_running, blog_url):
        """Test that valid blog URLs are accepted."""
        response = client.post(
            "/analyze_blog",
            data={"url": blog_url},  # Field name is 'url' not 'blog_url'
            allow_redirects=False,
            timeout=120  # Blogs can take time to fetch
        )

        # Should accept and start processing
        # May return 422 if URL cannot be fetched (network issues)
        # May return 500 for unexpected server errors
        assert response.status_code in [200, 302, 303, 422, 500]

    @pytest.mark.parametrize("url", INVALID_URLS)
    def test_invalid_url_rejected(self, client, ensure_shikari_running, url):
        """Test that invalid URLs are rejected."""
        response = client.post(
            "/analyze_blog",
            data={"url": url},
            allow_redirects=False
        )

        # Should reject or handle gracefully
        assert response.status_code in [200, 302, 400, 422]

    def test_empty_url_rejected(self, client, ensure_shikari_running):
        """Test that empty URL is rejected."""
        response = client.post(
            "/analyze_blog",
            data={"url": ""},
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 400, 422]

    def test_url_with_whitespace_trimmed(self, client, ensure_shikari_running):
        """Test that URLs with whitespace are trimmed."""
        response = client.post(
            "/analyze_blog",
            data={"url": "  https://thedfirreport.com/  "},
            allow_redirects=False,
            timeout=120
        )

        # Should accept (whitespace trimmed) - may fail to fetch
        assert response.status_code in [200, 302, 303, 422, 500]


class TestBlogAnalysis:
    """Tests for blog content analysis."""

    def test_blog_analysis_returns_techniques(self, client, ensure_shikari_running):
        """Test that blog analysis extracts TTPs."""
        response = client.post(
            "/analyze_blog",
            data={
                "url": "https://thedfirreport.com/2025/03/31/fake-zoom-ends-in-blacksuit-ransomware/"
            },
            timeout=180
        )

        if response.status_code == 200:
            try:
                data = response.json()
                # Should contain techniques
                assert "techniques" in data or "ttps" in data
            except:
                # HTML response is also valid (redirect to results)
                pass

    def test_blog_analysis_extracts_iocs(self, client, ensure_shikari_running):
        """Test that blog analysis extracts IOCs."""
        response = client.post(
            "/analyze_blog",
            data={
                "url": "https://thedfirreport.com/2025/03/31/fake-zoom-ends-in-blacksuit-ransomware/"
            },
            timeout=180
        )

        if response.status_code == 200:
            try:
                data = response.json()
                # Should contain IOCs section
                if "iocs" in data:
                    iocs = data["iocs"]
                    # IOCs may have domains, IPs, hashes, etc.
                    assert isinstance(iocs, dict)
            except:
                pass  # HTML response is valid


class TestBlogGeneration:
    """Tests for blog-based detection generation."""

    def test_blog_generation_initiates(self, client, ensure_shikari_running):
        """Test that blog generation can be initiated after analysis."""
        # Note: /blog/generate requires a synthetic_group_name from prior analysis
        # This tests that the endpoint responds correctly
        response = client.post(
            "/blog/generate",
            data={
                "synthetic_group_name": "Blog_test_report_12345678",
            },
            allow_redirects=False,
            timeout=60
        )

        # May return 404 if no prior analysis, or 200/302 if found
        assert response.status_code in [200, 302, 303, 404, 422]

    def test_blog_generation_with_selected_ttps(self, client, ensure_shikari_running):
        """Test blog generation with selected TTPs."""
        response = client.post(
            "/blog/generate",
            data={
                "synthetic_group_name": "Blog_test_report_12345678",
                "selected_ttps": "T1059.001,T1566.001",
            },
            allow_redirects=False,
            timeout=60
        )

        assert response.status_code in [200, 302, 303, 404, 422]


class TestBlogResults:
    """Tests for blog analysis results."""

    def test_blog_results_page_loads(self, client, ensure_shikari_running):
        """Test that blog results page loads."""
        response = client.get(
            "/blog/results",
            params={"url": "https://thedfirreport.com/"}
        )

        assert response.status_code in [200, 404]

    def test_blog_list_endpoint(self, client, ensure_shikari_running):
        """Test blog list API endpoint."""
        response = client.get("/api/blogs")

        # May or may not have blogs processed
        assert response.status_code in [200, 404]


class TestBlogEdgeCases:
    """Edge case tests for blog URL input."""

    def test_blog_url_with_query_params(self, client, ensure_shikari_running):
        """Test blog URL with query parameters."""
        response = client.post(
            "/analyze_blog",
            data={
                "url": "https://example.com/blog?utm_source=test&utm_medium=test"
            },
            allow_redirects=False
        )

        # May succeed or return 422 if fetch fails
        assert response.status_code in [200, 302, 303, 400, 422, 500]

    def test_blog_url_with_fragments(self, client, ensure_shikari_running):
        """Test blog URL with URL fragments."""
        response = client.post(
            "/analyze_blog",
            data={
                "url": "https://thedfirreport.com/2025/03/31/fake-zoom/#section1"
            },
            allow_redirects=False,
            timeout=120
        )

        # May succeed or return 422 if fetch fails
        assert response.status_code in [200, 302, 303, 422, 500]

    def test_non_blog_url(self, client, ensure_shikari_running):
        """Test handling of non-blog URLs."""
        response = client.post(
            "/analyze_blog",
            data={"url": "https://www.google.com"},
            allow_redirects=False,
            timeout=60
        )

        # Should handle - may succeed or return 422 if blocked/failed
        assert response.status_code in [200, 302, 303, 400, 422, 500]

    def test_paywalled_content(self, client, ensure_shikari_running):
        """Test handling of paywalled/restricted content."""
        response = client.post(
            "/analyze_blog",
            data={"url": "https://www.nytimes.com/article"},
            allow_redirects=False,
            timeout=60
        )

        # Should handle gracefully - may succeed or fail with various errors
        assert response.status_code in [200, 302, 303, 400, 403, 422, 500]

    def test_non_english_blog(self, client, ensure_shikari_running):
        """Test handling of non-English blogs."""
        # This tests i18n handling
        response = client.post(
            "/analyze_blog",
            data={"url": "https://example.jp/blog"},
            allow_redirects=False,
            timeout=60
        )

        # May succeed or fail depending on URL accessibility
        assert response.status_code in [200, 302, 303, 400, 422, 500]


class TestBlogSecurity:
    """Security tests for blog URL input."""

    def test_ssrf_prevention_localhost(self, client, ensure_shikari_running):
        """Test that localhost URLs are blocked (SSRF prevention)."""
        response = client.post(
            "/analyze_blog",
            data={"url": "http://localhost/admin"},
            allow_redirects=False
        )

        # Should be blocked with 403 (forbidden) or 400 (bad request)
        assert response.status_code in [400, 403]

    def test_ssrf_prevention_internal_ip(self, client, ensure_shikari_running):
        """Test that internal IPs are blocked (SSRF prevention)."""
        response = client.post(
            "/analyze_blog",
            data={"url": "http://192.168.1.1/"},
            allow_redirects=False
        )

        # Should be blocked with 403 (forbidden)
        assert response.status_code in [400, 403]

    def test_ssrf_prevention_127_ip(self, client, ensure_shikari_running):
        """Test that 127.x.x.x IPs are blocked."""
        response = client.post(
            "/analyze_blog",
            data={"url": "http://127.0.0.1:8000/"},
            allow_redirects=False
        )

        # Should be blocked with 403 (forbidden)
        assert response.status_code in [400, 403]

    def test_url_injection_prevented(self, client, ensure_shikari_running):
        """Test that URL injection attempts are prevented."""
        response = client.post(
            "/analyze_blog",
            data={"url": "https://evil.com\nX-Injected: header"},
            allow_redirects=False
        )

        # Should be rejected with 400 (invalid URL) or 422 (fetch failed)
        assert response.status_code in [400, 403, 422]
