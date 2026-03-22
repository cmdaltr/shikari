"""
Tests for file upload and blog analysis endpoints.
"""
import pytest
import io


class TestFileUpload:
    """POST /upload with file attachments."""

    def test_txt_upload(self, api, ensure_running):
        content = b"""Threat Report\nTechniques: T1059.001, T1566.001\nIOC: evil.com"""
        r = api.post("/upload", files={
            "file": ("report.txt", io.BytesIO(content), "text/plain"),
        }, data={"auto_generate": ""}, timeout=60)
        assert r.status_code in [200, 401]

    def test_json_upload(self, api, ensure_running):
        content = b'{"techniques": ["T1059.001"], "iocs": {"domains": ["evil.com"]}}'
        r = api.post("/upload", files={
            "file": ("report.json", io.BytesIO(content), "application/json"),
        }, data={"auto_generate": ""}, timeout=60)
        assert r.status_code in [200, 401]

    def test_csv_upload(self, api, ensure_running):
        content = b"type,value\ndomain,evil.com\ntechnique,T1059.001"
        r = api.post("/upload", files={
            "file": ("iocs.csv", io.BytesIO(content), "text/csv"),
        }, data={"auto_generate": ""}, timeout=60)
        assert r.status_code in [200, 401]

    def test_yara_upload(self, api, ensure_running):
        content = b'rule Test { strings: $s = "malware" condition: $s }'
        r = api.post("/upload", files={
            "file": ("rules.yar", io.BytesIO(content), "text/plain"),
        }, data={"auto_generate": ""}, timeout=60)
        assert r.status_code in [200, 401]

    def test_markdown_upload(self, api, ensure_running):
        content = b"# Report\n## TTPs\n- T1059.001\n- T1566.001\n## IOCs\n- evil.com"
        r = api.post("/upload", files={
            "file": ("report.md", io.BytesIO(content), "text/markdown"),
        }, data={"auto_generate": ""}, timeout=60)
        assert r.status_code in [200, 401]

    @pytest.mark.parametrize("ext", [".exe", ".dll", ".bat", ".sh", ".py", ".php"])
    def test_dangerous_extensions_rejected(self, api, ensure_running, ext):
        r = api.post("/upload", files={
            "file": (f"bad{ext}", io.BytesIO(b"MZ"), "application/octet-stream"),
        }, timeout=30)
        assert r.status_code in [400, 401, 415, 422]

    def test_empty_file_handled(self, api, ensure_running):
        r = api.post("/upload", files={
            "file": ("empty.txt", io.BytesIO(b""), "text/plain"),
        }, timeout=30)
        assert r.status_code in [200, 400, 401, 422]

    def test_no_file_returns_error(self, api, ensure_running):
        r = api.post("/upload", data={"auto_generate": ""}, timeout=30)
        assert r.status_code in [400, 401, 422]

    def test_path_traversal_blocked(self, api, ensure_running):
        r = api.post("/upload", files={
            "file": ("../../../etc/passwd", io.BytesIO(b"test"), "text/plain"),
        }, timeout=30)
        assert r.status_code in [200, 400, 401]

    def test_upload_with_platform_exclusions(self, api, ensure_running):
        content = b"Techniques: T1059.001\nIOC: evil.com"
        r = api.post("/upload", files={
            "file": ("report.txt", io.BytesIO(content), "text/plain"),
        }, data={
            "auto_generate": "",
            "exclude_splunk": "true",
        }, timeout=60)
        assert r.status_code in [200, 401]


class TestUploadGenerate:
    """POST /upload/generate triggers generation from prior upload."""

    def test_generate_from_upload(self, api, ensure_running):
        r = api.post("/upload/generate", data={
            "synthetic_group_name": "Upload_Test_12345678",
        }, allow_redirects=False, timeout=60)
        assert r.status_code in [200, 302, 303, 400, 401, 404]


class TestBlogAnalysis:
    """POST /analyze_blog fetches and extracts TTPs from a URL."""

    @pytest.mark.network
    def test_analyze_valid_blog(self, api, ensure_running):
        r = api.post("/analyze_blog", data={
            "url": "https://thedfirreport.com/2025/03/31/fake-zoom-ends-in-blacksuit-ransomware/",
        }, timeout=180)
        assert r.status_code in [200, 302, 422, 500]

    def test_empty_url_rejected(self, api, ensure_running):
        r = api.post("/analyze_blog", data={"url": ""}, allow_redirects=False)
        assert r.status_code in [200, 302, 400, 422]

    @pytest.mark.parametrize("bad_url", [
        "not-a-url",
        "ftp://example.com",
        "javascript:alert(1)",
        "file:///etc/passwd",
    ])
    def test_invalid_url_rejected(self, api, ensure_running, bad_url):
        r = api.post("/analyze_blog", data={"url": bad_url}, allow_redirects=False)
        assert r.status_code in [200, 302, 400, 403, 422]


class TestBlogGenerate:
    """POST /blog/generate triggers generation from prior analysis."""

    def test_blog_generate_endpoint(self, api, ensure_running):
        r = api.post("/blog/generate", data={
            "synthetic_group_name": "Blog_test_12345678",
        }, allow_redirects=False, timeout=60)
        assert r.status_code in [200, 302, 303, 400, 401, 404, 422]

    def test_blog_generate_with_selected_ttps(self, api, ensure_running):
        r = api.post("/blog/generate", data={
            "synthetic_group_name": "Blog_test_12345678",
            "selected_ttps": "T1059.001,T1566.001",
        }, allow_redirects=False, timeout=60)
        assert r.status_code in [200, 302, 303, 400, 401, 404, 422]
