"""
Playwright UI Tests - Tabbed Interface
Tests the new VirusTotal-inspired tabbed interface
"""

import pytest
from playwright.sync_api import Page, expect


@pytest.fixture(scope="session")
def base_url():
    """Base URL for the application"""
    return "http://localhost:8000"


class TestTabbedInterface:
    """Test tabbed interface functionality"""

    def test_page_loads(self, page: Page, base_url: str):
        """Test that the main page loads successfully"""
        page.goto(base_url)
        expect(page).to_have_title("Archer Hunting Application")

        # Check for main heading
        heading = page.locator("h1")
        expect(heading).to_contain_text("Archer")

    def test_all_tabs_present(self, page: Page, base_url: str):
        """Test that all three tabs are present"""
        page.goto(base_url)

        # Check for tab buttons
        generate_tab = page.locator('[data-tab="generate"]')
        upload_tab = page.locator('[data-tab="upload"]')
        emulate_tab = page.locator('[data-tab="emulate"]')

        expect(generate_tab).to_be_visible()
        expect(upload_tab).to_be_visible()
        expect(emulate_tab).to_be_visible()

    def test_generate_tab_active_by_default(self, page: Page, base_url: str):
        """Test that Generate tab is active on page load"""
        page.goto(base_url)

        generate_tab = page.locator('[data-tab="generate"]')
        expect(generate_tab).to_have_class(/active/)

        # Check that Generate tab pane is visible
        generate_pane = page.locator('#tab-generate')
        expect(generate_pane).to_be_visible()

    def test_tab_switching(self, page: Page, base_url: str):
        """Test switching between tabs"""
        page.goto(base_url)

        # Click Upload tab
        upload_tab = page.locator('[data-tab="upload"]')
        upload_tab.click()

        # Verify Upload tab is now active
        expect(upload_tab).to_have_class(/active/)

        # Verify Upload pane is visible
        upload_pane = page.locator('#tab-upload')
        expect(upload_pane).to_be_visible()

        # Verify Generate pane is hidden
        generate_pane = page.locator('#tab-generate')
        expect(generate_pane).not_to_be_visible()

        # Click Emulate tab
        emulate_tab = page.locator('[data-tab="emulate"]')
        emulate_tab.click()

        # Verify Emulate tab is now active
        expect(emulate_tab).to_have_class(/active/)
        expect(page.locator('#tab-emulate')).to_be_visible()

    def test_tab_content_isolation(self, page: Page, base_url: str):
        """Test that only one tab pane is visible at a time"""
        page.goto(base_url)

        # Initially, only Generate should be visible
        expect(page.locator('#tab-generate')).to_be_visible()
        expect(page.locator('#tab-upload')).not_to_be_visible()
        expect(page.locator('#tab-emulate')).not_to_be_visible()

        # Switch to Upload
        page.locator('[data-tab="upload"]').click()
        expect(page.locator('#tab-generate')).not_to_be_visible()
        expect(page.locator('#tab-upload')).to_be_visible()
        expect(page.locator('#tab-emulate')).not_to_be_visible()

        # Switch to Emulate
        page.locator('[data-tab="emulate"]').click()
        expect(page.locator('#tab-generate')).not_to_be_visible()
        expect(page.locator('#tab-upload')).not_to_be_visible()
        expect(page.locator('#tab-emulate')).to_be_visible()

    def test_tab_icons_present(self, page: Page, base_url: str):
        """Test that tab icons are displayed"""
        page.goto(base_url)

        # Check for SVG icons in each tab
        generate_icon = page.locator('[data-tab="generate"] .tab-icon')
        upload_icon = page.locator('[data-tab="upload"] .tab-icon')
        emulate_icon = page.locator('[data-tab="emulate"] .tab-icon')

        expect(generate_icon).to_be_visible()
        expect(upload_icon).to_be_visible()
        expect(emulate_icon).to_be_visible()

    def test_tab_labels(self, page: Page, base_url: str):
        """Test that tab labels are correct"""
        page.goto(base_url)

        generate_tab = page.locator('[data-tab="generate"]')
        upload_tab = page.locator('[data-tab="upload"]')
        emulate_tab = page.locator('[data-tab="emulate"]')

        expect(generate_tab).to_contain_text("Generate")
        expect(upload_tab).to_contain_text("Upload")
        expect(emulate_tab).to_contain_text("Emulate")


class TestGenerateTab:
    """Test Generate tab functionality"""

    def test_generate_form_present(self, page: Page, base_url: str):
        """Test that the generate form is present"""
        page.goto(base_url)

        form = page.locator('#generate-form')
        expect(form).to_be_visible()

        # Check for group name input
        group_input = page.locator('#group_name_input')
        expect(group_input).to_be_visible()

    def test_generate_button_disabled_initially(self, page: Page, base_url: str):
        """Test that generate button is disabled when form is empty"""
        page.goto(base_url)

        generate_btn = page.locator('#generate_btn')
        expect(generate_btn).to_be_disabled()

    def test_generate_button_enabled_with_input(self, page: Page, base_url: str):
        """Test that generate button enables when group name is entered"""
        page.goto(base_url)

        group_input = page.locator('#group_name_input')
        generate_btn = page.locator('#generate_btn')

        # Type group name
        group_input.fill("APT29")

        # Button should now be enabled
        expect(generate_btn).to_be_enabled()

    def test_group_name_validation(self, page: Page, base_url: str):
        """Test group name length validation"""
        page.goto(base_url)

        group_input = page.locator('#group_name_input')
        error_msg = page.locator('#group-name-error')

        # Type long name (>30 chars)
        group_input.fill("This is a very long threat group name")

        # Error should be visible
        expect(error_msg).to_be_visible()

    def test_advanced_options_collapsible(self, page: Page, base_url: str):
        """Test that advanced options are collapsible"""
        page.goto(base_url)

        # Find details element
        advanced_options = page.locator('details.options-section').first

        # Initially closed
        expect(advanced_options).not_to_have_attribute('open')

        # Click to open
        advanced_options.locator('summary').click()
        expect(advanced_options).to_have_attribute('open')

    def test_checkbox_options(self, page: Page, base_url: str):
        """Test checkbox options are present and functional"""
        page.goto(base_url)

        # Open advanced options
        page.locator('details.options-section').first.locator('summary').click()

        # Check for checkboxes
        correlation_cb = page.locator('input[name="run_correlation"]')
        semantic_cb = page.locator('input[name="semantic"]')

        expect(correlation_cb).to_be_visible()
        expect(semantic_cb).to_be_visible()

        # Test checking
        correlation_cb.check()
        expect(correlation_cb).to_be_checked()


class TestUploadTab:
    """Test Upload tab functionality"""

    def test_upload_form_present(self, page: Page, base_url: str):
        """Test that upload form is present"""
        page.goto(base_url)

        # Switch to Upload tab
        page.locator('[data-tab="upload"]').click()

        form = page.locator('#upload-form')
        expect(form).to_be_visible()

    def test_upload_dropzone_visible(self, page: Page, base_url: str):
        """Test that upload dropzone is visible"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        dropzone = page.locator('#upload-dropzone')
        expect(dropzone).to_be_visible()
        expect(dropzone).to_contain_text("Choose file or drag it here")

    def test_upload_button_disabled_initially(self, page: Page, base_url: str):
        """Test that upload button is disabled without file"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        upload_btn = page.locator('#upload_btn')
        expect(upload_btn).to_be_disabled()

    def test_file_selection_button(self, page: Page, base_url: str):
        """Test that file selection button is present"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        select_btn = page.locator('#upload-dropzone button.btn-secondary')
        expect(select_btn).to_be_visible()
        expect(select_btn).to_contain_text("Select File")

    def test_supported_formats_message(self, page: Page, base_url: str):
        """Test that supported formats message is displayed"""
        page.goto(base_url)
        page.locator('[data-tab="upload"]').click()

        upload_text = page.locator('.upload-text')
        expect(upload_text).to_contain_text("PDF")
        expect(upload_text).to_contain_text("JSON")


class TestEmulateTab:
    """Test Emulate tab functionality"""

    def test_emulate_form_present(self, page: Page, base_url: str):
        """Test that emulate form is present"""
        page.goto(base_url)

        # Switch to Emulate tab
        page.locator('[data-tab="emulate"]').click()

        form = page.locator('#emulate-form')
        expect(form).to_be_visible()

    def test_technique_input_present(self, page: Page, base_url: str):
        """Test that technique input is present"""
        page.goto(base_url)
        page.locator('[data-tab="emulate"]').click()

        technique_input = page.locator('#emulate_technique')
        expect(technique_input).to_be_visible()

    def test_emulate_button_disabled_initially(self, page: Page, base_url: str):
        """Test that emulate button is disabled when form is empty"""
        page.goto(base_url)
        page.locator('[data-tab="emulate"]').click()

        emulate_btn = page.locator('#emulate_btn')
        expect(emulate_btn).to_be_disabled()

    def test_emulate_button_enabled_with_input(self, page: Page, base_url: str):
        """Test that emulate button enables with technique input"""
        page.goto(base_url)
        page.locator('[data-tab="emulate"]').click()

        technique_input = page.locator('#emulate_technique')
        emulate_btn = page.locator('#emulate_btn')

        # Type technique ID
        technique_input.fill("T1059.001")

        # Button should be enabled
        expect(emulate_btn).to_be_enabled()

    def test_execution_mode_radios(self, page: Page, base_url: str):
        """Test execution mode radio buttons"""
        page.goto(base_url)
        page.locator('[data-tab="emulate"]').click()

        simulate_radio = page.locator('input[name="emulation_mode"][value="simulate"]')
        live_radio = page.locator('input[name="emulation_mode"][value="live"]')

        expect(simulate_radio).to_be_visible()
        expect(live_radio).to_be_visible()

        # Simulate should be checked by default
        expect(simulate_radio).to_be_checked()
        expect(live_radio).not_to_be_checked()

        # Click live mode
        live_radio.check()
        expect(live_radio).to_be_checked()
        expect(simulate_radio).not_to_be_checked()

    def test_remote_execution_toggle(self, page: Page, base_url: str):
        """Test remote execution configuration toggle"""
        page.goto(base_url)
        page.locator('[data-tab="emulate"]').click()

        # Open emulation options
        page.locator('details.options-section').first.locator('summary').click()

        remote_cb = page.locator('input[name="remote_execution"]')
        remote_config = page.locator('#remote-config')

        # Remote config should be hidden initially
        expect(remote_config).not_to_be_visible()

        # Check remote execution
        remote_cb.check()

        # Remote config should now be visible
        expect(remote_config).to_be_visible()


class TestResponsiveDesign:
    """Test responsive design and mobile compatibility"""

    def test_mobile_viewport(self, page: Page, base_url: str):
        """Test layout on mobile viewport"""
        # Set mobile viewport
        page.set_viewport_size({"width": 375, "height": 667})
        page.goto(base_url)

        # Tabs should still be visible
        tabs_header = page.locator('.tabs-header')
        expect(tabs_header).to_be_visible()

        # Tab buttons should be visible
        expect(page.locator('[data-tab="generate"]')).to_be_visible()

    def test_tablet_viewport(self, page: Page, base_url: str):
        """Test layout on tablet viewport"""
        # Set tablet viewport
        page.set_viewport_size({"width": 768, "height": 1024})
        page.goto(base_url)

        # All elements should be properly laid out
        expect(page.locator('.tabs-container')).to_be_visible()
        expect(page.locator('#generate-form')).to_be_visible()
