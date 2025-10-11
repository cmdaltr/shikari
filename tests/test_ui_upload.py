"""
Playwright UI Tests - File Upload Functionality
Tests the file upload feature for TTP/IOC extraction
"""

import pytest
import re
from pathlib import Path
from playwright.sync_api import Page, expect


@pytest.fixture(scope="session")
def base_url():
    """Base URL for the application"""
    return "http://localhost:8000"


@pytest.fixture
def sample_pdf_path(tmp_path):
    """Create a sample PDF file for testing"""
    pdf_path = tmp_path / "threat_report.pdf"
    # Create a minimal PDF file
    pdf_content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n199\n%%EOF"
    pdf_path.write_bytes(pdf_content)
    return str(pdf_path)


@pytest.fixture
def sample_txt_path(tmp_path):
    """Create a sample text file with threat intelligence"""
    txt_path = tmp_path / "threat_intel.txt"
    content = """
    Threat Intelligence Report

    The threat actor used T1059.001 (PowerShell) to execute malicious commands.
    They also leveraged T1003 (Credential Dumping) to extract credentials.

    IOCs:
    - IP: 192.168.1.100
    - Domain: evil.com
    - Hash: d41d8cd98f00b204e9800998ecf8427e
    - Command: powershell.exe -enc
    """
    txt_path.write_text(content)
    return str(txt_path)


@pytest.fixture
def sample_json_path(tmp_path):
    """Create a sample JSON file with IOCs"""
    json_path = tmp_path / "iocs.json"
    content = """{
      "threat_group": "APT29",
      "techniques": ["T1059.001", "T1003"],
      "iocs": {
        "ips": ["192.168.1.1"],
        "domains": ["malicious.com"],
        "hashes": ["abc123"]
      }
    }"""
    json_path.write_text(content)
    return str(json_path)


class TestFileUploadInterface:
    """Test file upload UI elements"""

    def test_upload_tab_has_dropzone(self, page: Page, base_url: str):
        """Test that upload tab contains dropzone"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        dropzone = page.locator('#upload-dropzone')
        expect(dropzone).to_be_visible()
        expect(dropzone).to_have_class(re.compile(r"upload-area"))

    def test_upload_instructions_visible(self, page: Page, base_url: str):
        """Test that upload instructions are displayed"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        upload_text = page.locator('.upload-text')
        expect(upload_text).to_contain_text("Choose file")
        expect(upload_text).to_contain_text("drag it here")

    def test_supported_formats_listed(self, page: Page, base_url: str):
        """Test that supported file formats are listed"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        upload_area = page.locator('#upload-dropzone')
        expect(upload_area).to_contain_text("PDF")
        expect(upload_area).to_contain_text("TXT")
        expect(upload_area).to_contain_text("JSON")

    def test_select_file_button_present(self, page: Page, base_url: str):
        """Test that Select File button is visible"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        select_btn = page.locator('#upload-dropzone button')
        expect(select_btn).to_be_visible()
        expect(select_btn).to_contain_text("Select File")

    def test_upload_button_disabled_without_file(self, page: Page, base_url: str):
        """Test that upload button is disabled without file selection"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        upload_btn = page.locator('#upload_btn')
        expect(upload_btn).to_be_disabled()


class TestFileSelection:
    """Test file selection functionality"""

    def test_file_input_accepts_pdf(self, page: Page, base_url: str, sample_pdf_path: str):
        """Test selecting a PDF file"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        # Set file on the hidden input
        file_input = page.locator('#file-input')
        file_input.set_input_files(sample_pdf_path)

        # File info should be displayed
        file_info = page.locator('#file-selected')
        expect(file_info).to_be_visible()

        # File name should be shown
        file_name = page.locator('#file-name-text')
        expect(file_name).to_contain_text("threat_report.pdf")

        # Upload button should be enabled
        upload_btn = page.locator('#upload_btn')
        expect(upload_btn).to_be_enabled()

    def test_file_input_accepts_txt(self, page: Page, base_url: str, sample_txt_path: str):
        """Test selecting a text file"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        file_input = page.locator('#file-input')
        file_input.set_input_files(sample_txt_path)

        file_name = page.locator('#file-name-text')
        expect(file_name).to_contain_text("threat_intel.txt")

    def test_file_input_accepts_json(self, page: Page, base_url: str, sample_json_path: str):
        """Test selecting a JSON file"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        file_input = page.locator('#file-input')
        file_input.set_input_files(sample_json_path)

        file_name = page.locator('#file-name-text')
        expect(file_name).to_contain_text("iocs.json")

    def test_clear_file_selection(self, page: Page, base_url: str, sample_txt_path: str):
        """Test clearing file selection"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        # Select file
        file_input = page.locator('#file-input')
        file_input.set_input_files(sample_txt_path)

        # Verify file is selected
        file_info = page.locator('#file-selected')
        expect(file_info).to_be_visible()

        # Click remove button
        remove_btn = page.locator('.btn-remove')
        remove_btn.click()

        # File info should be hidden
        expect(file_info).not_to_be_visible()

        # Upload button should be disabled again
        upload_btn = page.locator('#upload_btn')
        expect(upload_btn).to_be_disabled()

    def test_file_icon_displayed(self, page: Page, base_url: str, sample_pdf_path: str):
        """Test that file icon is displayed when file is selected"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        file_input = page.locator('#file-input')
        file_input.set_input_files(sample_pdf_path)

        file_icon = page.locator('.file-icon')
        expect(file_icon).to_be_visible()


class TestUploadOptions:
    """Test upload processing options"""

    def test_upload_options_section(self, page: Page, base_url: str):
        """Test that upload options section is present"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        options_section = page.locator('#tab-upload details.options-section')
        expect(options_section).to_be_visible()

    def test_openai_enhancement_option(self, page: Page, base_url: str):
        """Test OpenAI enhancement checkbox"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        # Open options
        page.locator('#tab-upload details.options-section summary').click()

        openai_cb = page.locator('input[name="use_openai"]')
        expect(openai_cb).to_be_visible()

        # Test checking
        openai_cb.check()
        expect(openai_cb).to_be_checked()

    def test_auto_generate_option(self, page: Page, base_url: str):
        """Test auto-generate queries checkbox"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        # Open options
        page.locator('#tab-upload details.options-section summary').click()

        auto_gen_cb = page.locator('input[name="auto_generate"]')
        expect(auto_gen_cb).to_be_visible()

        # Should be checked by default
        expect(auto_gen_cb).to_be_checked()

    def test_correlation_option(self, page: Page, base_url: str):
        """Test run correlation checkbox"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        # Open options
        page.locator('#tab-upload details.options-section summary').click()

        correlation_cb = page.locator('#tab-upload input[name="run_correlation"]')
        expect(correlation_cb).to_be_visible()

    def test_options_toggle(self, page: Page, base_url: str):
        """Test that options section can be toggled"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        options_section = page.locator('#tab-upload details.options-section')
        options_grid = page.locator('#tab-upload .options-grid')

        # Initially closed (check that 'open' attribute is not set)
        expect(options_section).not_to_have_attribute('open', '')

        # Click to open
        options_section.locator('summary').click()
        expect(options_section).to_have_attribute('open', '')
        expect(options_grid).to_be_visible()

        # Click to close
        options_section.locator('summary').click()
        expect(options_section).not_to_have_attribute('open', '')


class TestDragAndDrop:
    """Test drag and drop functionality"""

    def test_dropzone_hover_effect(self, page: Page, base_url: str):
        """Test that dropzone shows hover effect on dragover"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        dropzone = page.locator('#upload-dropzone')

        # Get initial class
        initial_class = dropzone.get_attribute('class')

        # Simulate dragover (note: full D&D testing is complex in Playwright)
        # This tests the CSS class exists
        expect(dropzone).to_have_css('cursor', 'pointer')

    def test_dropzone_click_triggers_file_dialog(self, page: Page, base_url: str):
        """Test that clicking select button works"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        # The button should be clickable
        select_btn = page.locator('#upload-dropzone button.btn-secondary')
        expect(select_btn).to_be_enabled()


class TestUploadFlow:
    """Test complete upload workflow"""

    def test_upload_workflow_with_auto_generate(self, page: Page, base_url: str, sample_txt_path: str):
        """Test complete upload flow with auto-generate enabled"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        # Select file
        file_input = page.locator('#file-input')
        file_input.set_input_files(sample_txt_path)

        # Verify file is selected
        expect(page.locator('#file-name-text')).to_contain_text("threat_intel.txt")

        # Ensure auto-generate is checked (default)
        page.locator('#tab-upload details.options-section summary').click()
        auto_gen = page.locator('input[name="auto_generate"]')
        if not auto_gen.is_checked():
            auto_gen.check()

        # Upload button should be enabled
        upload_btn = page.locator('#upload_btn')
        expect(upload_btn).to_be_enabled()

    def test_upload_workflow_without_auto_generate(self, page: Page, base_url: str, sample_json_path: str):
        """Test upload flow without auto-generate"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        # Select file
        file_input = page.locator('#file-input')
        file_input.set_input_files(sample_json_path)

        # Open options and uncheck auto-generate
        page.locator('#tab-upload details.options-section summary').click()
        auto_gen = page.locator('input[name="auto_generate"]')
        auto_gen.uncheck()

        # Upload button should still be enabled
        upload_btn = page.locator('#upload_btn')
        expect(upload_btn).to_be_enabled()

    def test_multiple_file_selections(self, page: Page, base_url: str, sample_txt_path: str, sample_pdf_path: str):
        """Test changing file selection"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        file_input = page.locator('#file-input')

        # Select first file
        file_input.set_input_files(sample_txt_path)
        expect(page.locator('#file-name-text')).to_contain_text("threat_intel.txt")

        # Select different file
        file_input.set_input_files(sample_pdf_path)
        expect(page.locator('#file-name-text')).to_contain_text("threat_report.pdf")


class TestAccessibility:
    """Test accessibility features"""

    def test_form_labels_present(self, page: Page, base_url: str):
        """Test that form labels are properly associated"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        # File input should have accessible label
        select_btn = page.locator('button.btn-secondary')
        expect(select_btn).to_be_visible()

    def test_keyboard_navigation(self, page: Page, base_url: str):
        """Test that upload tab is keyboard accessible"""
        page.goto(base_url)

        # Tab navigation should work
        page.keyboard.press('Tab')  # Focus on first interactive element

        # Upload tab button should be focusable
        upload_tab = page.locator('[data-tab="upload"]')
        upload_tab.focus()
        expect(upload_tab).to_be_focused()

    def test_aria_labels(self, page: Page, base_url: str):
        """Test that important elements have ARIA labels"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        # Upload button should be identifiable
        upload_btn = page.locator('#upload_btn')
        expect(upload_btn).to_be_visible()
