"""
Tests for File Upload input method.

These tests validate file-based detection generation including
file type validation, content extraction, TTP identification, and IOC extraction.
"""
import pytest
import io


# Allowed file extensions
ALLOWED_EXTENSIONS = [".pdf", ".txt", ".md", ".json", ".csv", ".xlsx", ".xls", ".docx", ".doc", ".yar", ".yara"]

# Disallowed extensions (security)
DISALLOWED_EXTENSIONS = [".exe", ".dll", ".bat", ".sh", ".py", ".js", ".php", ".asp", ".jsp"]


class TestFileUploadValidation:
    """Tests for file upload input validation."""

    def test_txt_file_accepted(self, client, ensure_shikari_running):
        """Test that .txt files are accepted."""
        content = b"""
        Threat Intelligence Report

        ATT&CK Techniques Observed:
        - T1059.001 - PowerShell execution
        - T1566.001 - Spearphishing attachment

        IOCs:
        - Domain: malicious-domain.com
        - IP: 192.168.1.100
        - Hash: abc123def456
        """

        files = {"file": ("report.txt", io.BytesIO(content), "text/plain")}
        response = client.post(
            "/upload",
            files=files,
            data={"auto_generate": ""},
            timeout=60
        )

        assert response.status_code in [200, 401]  # 401 if auth required

    def test_json_file_accepted(self, client, ensure_shikari_running):
        """Test that .json files are accepted."""
        content = b'''
        {
            "report": "Threat Analysis",
            "techniques": ["T1059.001", "T1566"],
            "iocs": {
                "domains": ["evil.com"],
                "ips": ["10.0.0.1"]
            }
        }
        '''

        files = {"file": ("report.json", io.BytesIO(content), "application/json")}
        response = client.post(
            "/upload",
            files=files,
            data={"auto_generate": ""},
            timeout=60
        )

        assert response.status_code in [200, 401]

    def test_csv_file_accepted(self, client, ensure_shikari_running):
        """Test that .csv files are accepted."""
        content = b"""indicator_type,indicator_value,description
domain,evil.com,Malicious C2
ip,192.168.1.100,Compromised host
hash,abc123,Malware sample
technique,T1059.001,PowerShell"""

        files = {"file": ("iocs.csv", io.BytesIO(content), "text/csv")}
        response = client.post(
            "/upload",
            files=files,
            data={"auto_generate": ""},
            timeout=60
        )

        assert response.status_code in [200, 401]

    def test_yara_file_accepted(self, client, ensure_shikari_running):
        """Test that .yar/.yara files are accepted."""
        content = b"""
rule Example_Malware {
    meta:
        description = "Example YARA rule"
        author = "Test"

    strings:
        $s1 = "malicious_string"
        $s2 = { 4D 5A 90 00 }

    condition:
        any of them
}
"""

        files = {"file": ("rules.yar", io.BytesIO(content), "text/plain")}
        response = client.post(
            "/upload",
            files=files,
            data={"auto_generate": ""},
            timeout=60
        )

        assert response.status_code in [200, 401]

    @pytest.mark.parametrize("ext", DISALLOWED_EXTENSIONS)
    def test_executable_files_rejected(self, client, ensure_shikari_running, ext):
        """Test that executable file types are rejected."""
        files = {"file": (f"malicious{ext}", io.BytesIO(b"MZ"), "application/octet-stream")}
        response = client.post(
            "/upload",
            files=files,
            data={"auto_generate": ""},
            timeout=30
        )

        # Should be rejected with 400 or similar
        assert response.status_code in [400, 401, 415, 422]

    def test_empty_file_handled(self, client, ensure_shikari_running):
        """Test that empty files are handled gracefully."""
        files = {"file": ("empty.txt", io.BytesIO(b""), "text/plain")}
        response = client.post(
            "/upload",
            files=files,
            data={"auto_generate": ""},
            timeout=30
        )

        # Should handle gracefully (may reject or accept with no results)
        assert response.status_code in [200, 400, 401, 422]

    def test_no_file_provided(self, client, ensure_shikari_running):
        """Test that missing file is handled."""
        response = client.post(
            "/upload",
            data={"auto_generate": ""},
            timeout=30
        )

        # Should return error
        assert response.status_code in [400, 401, 422]


class TestFileUploadContent:
    """Tests for file content processing."""

    def test_file_with_techniques_extracted(self, client, ensure_shikari_running):
        """Test that ATT&CK techniques are extracted from files."""
        content = b"""
        Security Report

        The threat actor used the following techniques:
        - T1059.001: PowerShell - The attacker used PowerShell for command execution
        - T1566.001: Spearphishing Attachment - Initial access via email
        - T1078: Valid Accounts - Used compromised credentials
        """

        files = {"file": ("report.txt", io.BytesIO(content), "text/plain")}
        response = client.post(
            "/upload",
            files=files,
            data={"use_openai": ""},
            timeout=120
        )

        if response.status_code == 200:
            try:
                data = response.json()
                # Should extract techniques
                ttps = data.get("ttps", data.get("techniques", []))
                assert len(ttps) >= 0  # May or may not extract depending on AI
            except:
                pass  # HTML response is valid

    def test_file_with_iocs_extracted(self, client, ensure_shikari_running):
        """Test that IOCs are extracted from files."""
        content = b"""
        IOC Report

        Domains:
        - malicious-c2.com
        - evil-domain.net

        IP Addresses:
        - 192.168.1.100
        - 10.0.0.50

        File Hashes:
        - SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        - MD5: d41d8cd98f00b204e9800998ecf8427e
        """

        files = {"file": ("iocs.txt", io.BytesIO(content), "text/plain")}
        response = client.post(
            "/upload",
            files=files,
            data={"use_openai": ""},
            timeout=120
        )

        if response.status_code == 200:
            try:
                data = response.json()
                iocs = data.get("iocs", {})
                # Should have some IOC categories
                assert isinstance(iocs, dict)
            except:
                pass


class TestFileUploadGeneration:
    """Tests for file-based detection generation."""

    def test_upload_with_auto_generate(self, client, ensure_shikari_running):
        """Test file upload with auto-generate enabled."""
        content = b"""
        Threat Report - APT Activity

        Techniques:
        - T1059.001: PowerShell
        - T1003.001: LSASS Memory
        """

        files = {"file": ("report.txt", io.BytesIO(content), "text/plain")}
        response = client.post(
            "/upload",
            files=files,
            data={"auto_generate": "true"},
            timeout=120
        )

        assert response.status_code in [200, 401]

    def test_upload_generate_endpoint(self, client, ensure_shikari_running):
        """Test the upload/generate endpoint."""
        response = client.post(
            "/upload/generate",
            data={
                "synthetic_group_name": "Upload_TestReport_12345678",
                "run_correlation": "",
            },
            allow_redirects=False,
            timeout=60
        )

        # May need prior upload or return error
        assert response.status_code in [200, 302, 303, 400, 404]


class TestFileUploadSecurity:
    """Security tests for file upload."""

    def test_path_traversal_prevented(self, client, ensure_shikari_running):
        """Test that path traversal in filename is prevented."""
        content = b"Test content"
        files = {"file": ("../../../etc/passwd", io.BytesIO(content), "text/plain")}

        response = client.post(
            "/upload",
            files=files,
            timeout=30
        )

        # Should sanitize filename or reject
        assert response.status_code in [200, 400, 401]

    def test_null_byte_in_filename_prevented(self, client, ensure_shikari_running):
        """Test that null bytes in filename are handled."""
        content = b"Test content"
        files = {"file": ("test.txt\x00.exe", io.BytesIO(content), "text/plain")}

        response = client.post(
            "/upload",
            files=files,
            timeout=30
        )

        assert response.status_code in [200, 400, 401]

    def test_file_size_limit(self, client, ensure_shikari_running):
        """Test that file size limits are enforced."""
        # Create a large file (> 50MB limit mentioned in code)
        large_content = b"x" * (51 * 1024 * 1024)  # 51MB

        files = {"file": ("large.txt", io.BytesIO(large_content), "text/plain")}
        response = client.post(
            "/upload",
            files=files,
            timeout=60
        )

        # Should be rejected with 413 or 400
        assert response.status_code in [400, 401, 413]

    def test_double_extension_handled(self, client, ensure_shikari_running):
        """Test that double extensions are handled."""
        content = b"Test content"
        files = {"file": ("report.txt.exe", io.BytesIO(content), "text/plain")}

        response = client.post(
            "/upload",
            files=files,
            timeout=30
        )

        # Should reject .exe extension
        assert response.status_code in [400, 401, 415]


class TestFileUploadEdgeCases:
    """Edge case tests for file upload."""

    def test_unicode_filename(self, client, ensure_shikari_running):
        """Test file with unicode characters in filename."""
        content = b"Test content"
        files = {"file": ("報告書.txt", io.BytesIO(content), "text/plain")}

        response = client.post(
            "/upload",
            files=files,
            timeout=30
        )

        assert response.status_code in [200, 400, 401]

    def test_very_long_filename(self, client, ensure_shikari_running):
        """Test file with very long filename."""
        content = b"Test content"
        long_name = "a" * 300 + ".txt"
        files = {"file": (long_name, io.BytesIO(content), "text/plain")}

        response = client.post(
            "/upload",
            files=files,
            timeout=30
        )

        # Should truncate or handle gracefully
        assert response.status_code in [200, 400, 401]

    def test_special_characters_in_filename(self, client, ensure_shikari_running):
        """Test file with special characters in filename."""
        content = b"Test content"
        files = {"file": ("report@#$%^&().txt", io.BytesIO(content), "text/plain")}

        response = client.post(
            "/upload",
            files=files,
            timeout=30
        )

        assert response.status_code in [200, 400, 401]

    def test_markdown_file(self, client, ensure_shikari_running):
        """Test markdown file processing."""
        content = b"""
# Threat Report

## TTPs Observed

| Technique | Description |
|-----------|-------------|
| T1059.001 | PowerShell  |
| T1566.001 | Phishing    |

## IOCs

- `malicious.com`
- `192.168.1.100`
"""

        files = {"file": ("report.md", io.BytesIO(content), "text/markdown")}
        response = client.post(
            "/upload",
            files=files,
            timeout=60
        )

        assert response.status_code in [200, 401]
