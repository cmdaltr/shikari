# Shikari Test Suite

Comprehensive test suite for the Shikari Detection Generation Platform covering every component, endpoint, and user interaction.

## Test Categories

| Category | Directory | What it covers | Requires server | Speed |
|----------|-----------|----------------|-----------------|-------|
| **Unit** | `tests/unit/` | MITRE parsing, file parsing, blog analysis, progress tracking | No | Fast |
| **Integration** | `tests/integration/` | FastAPI TestClient, mocked endpoints | No | Fast |
| **API** | `tests/api/` | Every HTTP endpoint against a live server | Yes | Medium |
| **Input Methods** | `tests/inputs/` | Threat groups, CVEs, techniques, uploads, blogs, profiles | Yes | Medium |
| **Security** | `tests/security/` + `tests/api/test_security.py` | XSS, SQLi, SSRF, command injection, path traversal | Yes | Fast |
| **UI (Playwright)** | `tests/ui/` | Browser-based testing with screenshots | Yes | Slow |
| **Features (E2E)** | `tests/features/` | Full generation pipelines end-to-end | Yes | Very slow |

## Quick Start

### Prerequisites

```bash
# Install test dependencies
pip install pytest requests pytest-playwright pytest-html

# Install Playwright browsers
playwright install chromium

# Ensure Shikari is running
uvicorn shikari.app:app --host 0.0.0.0 --port 8000 --reload
```

### Run Everything

```bash
./tests/run_all_tests.sh
```

### Run by Category

```bash
# Unit tests only (no server needed)
pytest tests/unit/ -v

# API endpoint tests
pytest tests/api/ -v

# Input method validation tests
pytest tests/inputs/ -v

# Security tests
pytest tests/api/test_security.py tests/security/ -v

# UI tests (headless)
pytest tests/ui/ -v

# UI tests (visible browser)
pytest tests/ui/ -v --headed

# End-to-end generation tests (slow)
pytest tests/features/ -v --run-feature-tests
```

### Run Specific Test Files

```bash
# Health and page routes
pytest tests/api/test_health_and_pages.py -v

# Threat group autocomplete API
pytest tests/api/test_threat_groups_api.py -v

# Generation endpoints (group, CVE, technique)
pytest tests/api/test_generation_endpoints.py -v

# Research tab (keyword/actor filter, XLSX export)
pytest tests/api/test_research_tab.py -v

# Upload and blog analysis
pytest tests/api/test_upload_and_blog.py -v

# Company profiling
pytest tests/api/test_company_profile.py -v

# Emulation (Atomic Red Team)
pytest tests/api/test_emulation.py -v

# Correlation engine
pytest tests/api/test_correlation.py -v

# Results and downloads
pytest tests/api/test_results_and_downloads.py -v

# OSINT status and bespoke detections
pytest tests/api/test_osint_status.py -v

# Field mappings
pytest tests/api/test_mappings.py -v

# Drafts and manual editor
pytest tests/api/test_drafts.py -v

# Detection Library (CRUD, search, export)
pytest tests/api/test_library.py -v

# Authentication, MFA, admin
pytest tests/api/test_auth.py -v

# Ask Shikari and Threat Briefing
pytest tests/api/test_ask_and_briefing.py -v

# LLM provider detection
pytest tests/api/test_llm_detection.py -v
```

## Standalone Runner

For more control and JSON output:

```bash
# Run all tests
python tests/run_test.py

# Test specific items
python tests/run_test.py --group "Scattered Spider"
python tests/run_test.py --cve "CVE-2025-55182"
python tests/run_test.py --blog "https://thedfirreport.com/..."
python tests/run_test.py --profile "Splunk"

# Limit scope
python tests/run_test.py --groups 2 --cves 2 --blogs 3 --profiles 2

# JSON output
python tests/run_test.py --json

# Custom URL and timeout
python tests/run_test.py --url http://localhost:8080 --timeout 1800

# List/add/remove test data
python tests/run_test.py --list
python tests/run_test.py --add groups "Volt Typhoon"
python tests/run_test.py --remove groups "Volt Typhoon"
```

## Test Output

### Logs

All test output is saved to `tests/logs/` with timestamps:
- `unit_YYYYMMDD_HHMMSS.log`
- `api_YYYYMMDD_HHMMSS.log`
- `ui_YYYYMMDD_HHMMSS.log`
- etc.

### Screenshots

UI tests capture screenshots to `tests/screenshots/`:

| Screenshot | What it shows |
|------------|---------------|
| `01_home_page.png` | Shikari home page after login |
| `02_all_tabs.png` | All five tabs visible |
| `03_generate_tab.png` | Generate tab form elements |
| `04_autocomplete_dropdown.png` | Threat group autocomplete in action |
| `05_cve_input.png` | CVE ID input field |
| `06_technique_input.png` | Technique ID input field |
| `07_generation_options.png` | OSINT enhancement, comparison toggles |
| `08_platform_exclusions.png` | Platform exclusion checkboxes |
| `09_research_tab.png` | Research tab layout |
| `10_keyword_filter.png` | Keyword filter with results |
| `11_actor_filter.png` | Actor name filter |
| `12_upload_tab.png` | Upload tab with file/blog inputs |
| `13_blog_url_input.png` | Blog URL input field |
| `14_file_upload_area.png` | File drop zone |
| `15_profile_tab.png` | Company profile tab |
| `16_domain_input.png` | Domain input for profiling |
| `17_emulate_tab.png` | Emulate tab (Atomic Red Team) |
| `20_generate_form_filled.png` | Generate form with Scattered Spider |
| `21_progress_page.png` | Progress page after generation starts |
| `22_progress_mid_generation.png` | Progress bar mid-generation |
| `23_hunt_techniques_filled.png` | Hunt mode with technique IDs |
| `24_cve_input_filled.png` | CVE generation form |
| `30_results_page.png` | Results page with detections |
| `31_detection_cards.png` | Individual detection cards |
| `32_platform_tabs.png` | Platform filter tabs on results |
| `33_osint_comparison.png` | OSINT comparison panel |
| `34_correlation_results.png` | Correlation query results |
| `35_individual_queries.png` | Per-technique query blocks |
| `36_download_buttons.png` | Download YAML/ZIP buttons |
| `37_copy_button_clicked.png` | Copy-to-clipboard button |
| `40_login_page.png` | Login page |
| `41_login_error.png` | Login error state |
| `42_register_page.png` | Registration page |
| `43_library_page.png` | Detection Library |
| `44_library_search.png` | Library search results |
| `45_coverage_page.png` | Coverage dashboard |
| `46_manual_editor.png` | Manual YAML editor |
| `47_how_it_works.png` | How It Works page |
| `48_progress_page.png` | Progress tracking page |
| `50_ask_panel.png` | Ask Shikari chat panel |
| `51_ask_question_typed.png` | Question typed in Ask panel |
| `52_threat_briefing_button.png` | Threat Briefing button |

### HTML Reports

Generate with the `--report` flag:
```bash
./tests/run_all_tests.sh --report
# Output: tests/reports/test_report_YYYYMMDD_HHMMSS.html
```

## API Endpoint Coverage

The API test suite covers every endpoint in Shikari:

| Endpoint | Test File | Tests |
|----------|-----------|-------|
| `GET /health` | `test_health_and_pages.py` | Status, response time |
| `GET /` | `test_health_and_pages.py` | Page load, tabs, form |
| `GET /how-it-works` | `test_health_and_pages.py` | Page load |
| `GET /login` | `test_auth.py` | Page load, form |
| `POST /login` | `test_auth.py` | Valid/invalid credentials |
| `GET /logout` | `test_auth.py` | Redirect |
| `GET /register` | `test_auth.py` | Page load |
| `POST /register` | `test_auth.py` | Validation |
| `GET /forgot-password` | `test_auth.py` | Page load |
| `POST /api/auth/request-reset` | `test_auth.py` | Email enumeration safe |
| `POST /api/auth/reset-password` | `test_auth.py` | Invalid token |
| `GET /api/mfa/status` | `test_auth.py` | MFA state |
| `POST /api/mfa/setup` | `test_auth.py` | MFA init |
| `POST /api/mfa/verify` | `test_auth.py` | Invalid code |
| `POST /api/mfa/disable` | `test_auth.py` | MFA disable |
| `POST /api/backup-codes/generate` | `test_auth.py` | Backup codes |
| `POST /api/change-password` | `test_auth.py` | Wrong current |
| `GET /api/llm/detect` | `test_llm_detection.py` | Provider list |
| `POST /api/llm/preference` | `test_llm_detection.py` | Set provider |
| `GET /threat_groups` | `test_threat_groups_api.py` | Autocomplete, known groups |
| `POST /generate` | `test_generation_endpoints.py` | All options, exclusions |
| `POST /generate/cve` | `test_generation_endpoints.py` | Valid/invalid CVEs |
| `POST /hunt/technique` | `test_generation_endpoints.py` | Single/multi, options |
| `POST /api/technique_names` | `test_generation_endpoints.py` | Name resolution |
| `GET /progress` | `test_health_and_pages.py` | Page load |
| `GET /progress_status` | `test_results_and_downloads.py` | Progress JSON |
| `GET /results` | `test_results_and_downloads.py` | Page load |
| `GET /api/detection/{file}` | `test_results_and_downloads.py` | YAML retrieval |
| `GET /api/download/detection/{file}` | `test_results_and_downloads.py` | File download |
| `GET /api/download/all/{group}` | `test_results_and_downloads.py` | ZIP download |
| `GET /api/attack-flow/{file}` | `test_results_and_downloads.py` | Flow data |
| `GET /api/download/flow/{file}` | `test_results_and_downloads.py` | Flow download |
| `GET /correlations/{group}.json` | `test_correlation.py` | Correlation data |
| `GET /api/correlation/params` | `test_correlation.py` | Get params |
| `POST /api/correlation/params` | `test_correlation.py` | Set params |
| `POST /upload` | `test_upload_and_blog.py` | All file types, security |
| `POST /upload/generate` | `test_upload_and_blog.py` | Generate from upload |
| `POST /analyze_blog` | `test_upload_and_blog.py` | URL analysis |
| `POST /blog/generate` | `test_upload_and_blog.py` | Generate from blog |
| `POST /profile` | `test_company_profile.py` | Company analysis |
| `POST /profile/generate-detections` | `test_company_profile.py` | Profile generation |
| `POST /emulate` | `test_emulation.py` | Emulation modes |
| `POST /api/ask` | `test_ask_and_briefing.py` | Q&A endpoint |
| `POST /api/threat-briefing` | `test_ask_and_briefing.py` | Briefing endpoint |
| `GET /api/actors/by-keyword` | `test_research_tab.py` | Keyword search |
| `POST /api/actors/techniques` | `test_research_tab.py` | Technique consolidation |
| `POST /api/research/export-xlsx` | `test_research_tab.py` | XLSX export |
| `GET /api/status/osint` | `test_osint_status.py` | OSINT repo health |
| `POST /api/status/osint/accept-failures` | `test_osint_status.py` | Accept failures |
| `POST /api/status/osint/retry-failed` | `test_osint_status.py` | Retry failed |
| `GET /api/status/bespoke` | `test_osint_status.py` | Bespoke status |
| `GET /api/bespoke/sample-searches` | `test_osint_status.py` | Sample searches |
| `POST /api/bespoke/reload` | `test_osint_status.py` | Reload bespoke |
| `GET /api/reference/coverage` | `test_osint_status.py` | Reference coverage |
| `GET /api/reference/queries` | `test_osint_status.py` | Reference queries |
| `GET /coverage` | `test_osint_status.py` | Coverage page |
| `POST /api/mappings/save` | `test_mappings.py` | Save mapping |
| `GET /api/mappings/load` | `test_mappings.py` | Load mappings |
| `POST /api/mappings/test` | `test_mappings.py` | Test mapping |
| `POST /save_draft` | `test_drafts.py` | Save draft |
| `GET /load_draft` | `test_drafts.py` | Load draft |
| `GET /list_drafts` | `test_drafts.py` | List drafts |
| `GET /manual` | `test_drafts.py` | Manual editor |
| `POST /manual_submit` | `test_drafts.py` | Submit YAML |
| `GET /library` | `test_library.py` | Library page |
| `GET /api/library/detections` | `test_library.py` | List detections |
| `POST /api/library/search` | `test_library.py` | Search |
| `POST /api/library/export` | `test_library.py` | Export |
| `POST /api/library/save` | `test_library.py` | Save detection |
| `POST /api/library/tags` | `test_library.py` | Tag detection |
| `POST /api/library/visibility` | `test_library.py` | Set visibility |
| `POST /api/library/delete` | `test_library.py` | Delete detection |
| `GET /api/profile/timeline` | `test_auth.py` | Activity timeline |
| `GET /api/profile/apikeys` | `test_auth.py` | List API keys |
| `POST /api/profile/apikeys` | `test_auth.py` | Create API key |
| `GET /api/users` | `test_auth.py` | User list |
| `GET /api/admin/users` | `test_auth.py` | Admin user list |
| `POST /api/admin/users` | `test_auth.py` | Create user |
| `PUT /api/admin/users/{id}` | `test_auth.py` | Update user |
| `DELETE /api/admin/users/{id}` | `test_auth.py` | Delete user |
| `POST /api/admin/reset-password` | `test_auth.py` | Admin reset |
| `GET /api/activities` | `test_auth.py` | Activity log |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SHIKARI_BASE_URL` | Shikari server URL | `http://127.0.0.1:8000` |
| `SHIKARI_TEST_EMAIL` | Login email for tests | `admin@shikari.app` |
| `SHIKARI_TEST_PASSWORD` | Login password for tests | *(see conftest)* |

## File Structure

```
tests/
├── README.md                           # This file
├── run_all_tests.sh                    # Comprehensive runner script
├── run_test.py                         # Standalone Python runner
├── conftest.py                         # Global pytest config
├── pytest.ini                          # Pytest markers and options
│
├── unit/                               # Unit tests (no server)
│   ├── test_mitre.py                   # MITRE ATT&CK parsing
│   ├── test_mitre_procedures.py        # Procedure extraction
│   ├── test_mitre_integration.py       # MITRE integration
│   ├── test_blog_analyzer.py           # Blog content analysis
│   ├── test_file_parser.py             # File upload parsing
│   ├── test_company_profiler.py        # Company profiling
│   └── test_progress.py               # Progress tracking
│
├── integration/                        # FastAPI TestClient tests
│   ├── conftest.py                     # TestClient fixtures
│   └── test_web_api.py                 # Mocked endpoint tests
│
├── api/                                # Live API endpoint tests
│   ├── conftest.py                     # Session, auth, API helper
│   ├── test_health_and_pages.py        # Health, all page routes
│   ├── test_llm_detection.py           # LLM provider detection
│   ├── test_threat_groups_api.py       # Autocomplete endpoint
│   ├── test_generation_endpoints.py    # Generate, CVE, Hunt
│   ├── test_research_tab.py           # Keyword/actor filter, XLSX
│   ├── test_upload_and_blog.py         # File upload, blog analysis
│   ├── test_company_profile.py         # Company profiling
│   ├── test_emulation.py              # Atomic Red Team emulation
│   ├── test_correlation.py            # Correlation engine
│   ├── test_results_and_downloads.py   # Results, downloads
│   ├── test_osint_status.py           # OSINT repos, bespoke, coverage
│   ├── test_mappings.py               # Field mappings
│   ├── test_drafts.py                 # Drafts, manual editor
│   ├── test_library.py               # Detection Library CRUD
│   ├── test_auth.py                   # Auth, MFA, admin
│   ├── test_ask_and_briefing.py       # Ask Shikari, Threat Briefing
│   └── test_security.py              # XSS, SQLi, SSRF, CMDi
│
├── inputs/                             # Input method validation
│   ├── test_threat_groups.py          # Group name inputs
│   ├── test_cves.py                   # CVE ID inputs
│   ├── test_techniques.py            # Technique ID inputs
│   ├── test_file_uploads.py           # File upload types/security
│   ├── test_blog_urls.py             # Blog URL validation/SSRF
│   └── test_company_profiles.py       # Company name inputs
│
├── ui/                                 # Playwright browser tests
│   ├── conftest.py                    # Browser fixtures, screenshot dir
│   ├── test_homepage.py               # All tabs, form elements
│   ├── test_generation_flow.py        # Full generation user journey
│   ├── test_results_page.py           # Results page sections
│   ├── test_other_pages.py            # Login, library, coverage, etc.
│   └── test_ask_panel.py             # Ask Shikari chat panel
│
├── features/                           # End-to-end feature tests
│   ├── test_cve_workflow.py           # Full CVE generation pipeline
│   └── test_technique_hunt_workflow.py # Full hunt pipeline
│
├── security/                           # Dedicated security tests
│   └── test_ssrf_protection.py        # SSRF prevention
│
├── reports/                            # Generated test reports
├── logs/                               # Test run logs
└── screenshots/                        # UI test screenshots
```
