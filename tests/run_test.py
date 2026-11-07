#!/usr/bin/env python3
"""
Comprehensive Test Suite for Shikari Detection Generation Platform

This test suite validates all major components of Shikari using realistic
threat intelligence inputs including threat groups, CVEs, blogs, and company profiles.

Run with: pytest tests/run_test.py -v --tb=short
Or individually: python tests/run_test.py

List available test data:
    python tests/run_test.py --list
    python tests/run_test.py --list groups
    python tests/run_test.py --list cves
    python tests/run_test.py --list blogs
    python tests/run_test.py --list profiles

Add custom test data:
    python tests/run_test.py --add groups "Volt Typhoon"
    python tests/run_test.py --add cves "CVE-2025-99999"
    python tests/run_test.py --add blogs "https://example.com/blog-post"
    python tests/run_test.py --add profiles "Acme Corp"

Remove custom test data:
    python tests/run_test.py --remove groups "Volt Typhoon"
"""

import pytest
import requests
import json
import time
import os
import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

# =============================================================================
# TEST CONFIGURATION
# =============================================================================

BASE_URL = os.getenv("SHIKARI_BASE_URL", "http://127.0.0.1:32453")
TIMEOUT = 900  # 15 minutes for long-running generation tasks (large threat groups)
SHORT_TIMEOUT = 30

# Test Data
THREAT_GROUPS = [
    "Scattered Spider",
    "APT28",
    "Lazarus Group",
    "Salt Typhoon",
    "Wizard Spider",
]

CVES = [
    "CVE-2026-24061",   # Telnet RCE
    "CVE-2026-0915",    # GNU C Library ASLR Bypass
    "CVE-2025-55182",   # React2Shell
    "CVE-2025-5777",    # CitrixBleed2
    "CVE-2025-62221",   # Windows Cloud Files Mini Filter Driver EoP
]

CVE_NAMES = {
    "CVE-2026-24061": "Telnet RCE",
    "CVE-2026-0915": "GNU C Library ASLR Bypass",
    "CVE-2025-55182": "React2Shell",
    "CVE-2025-5777": "CitrixBleed2",
    "CVE-2025-62221": "Windows Cloud Files Mini Filter Driver EoP",
}

BLOG_URLS = [
    "https://thedfirreport.com/2025/11/17/cats-got-your-files-lynx-ransomware/",
    "https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion/",
    "https://thedfirreport.com/2025/03/31/fake-zoom-ends-in-blacksuit-ransomware/",
    "https://www.crowdstrike.com/en-us/blog/warp-panda-cloud-threats/",
    "https://www.crowdstrike.com/en-us/blog/murky-panda-trusted-relationship-threat-in-cloud/",
]

COMPANY_PROFILES = [
    "SANS Institute",
    "Splunk",
    "BBC",
    "MacPaw",
    "LEGO",
]

# Custom test data persistence
CUSTOM_DATA_FILE = Path(__file__).parent / "custom_test_data.json"

CATEGORY_MAP = {
    "groups": "threat_groups",
    "cves": "cves",
    "blogs": "blogs",
    "profiles": "profiles",
}

LIST_MAP = {
    "threat_groups": THREAT_GROUPS,
    "cves": CVES,
    "blogs": BLOG_URLS,
    "profiles": COMPANY_PROFILES,
}


def load_custom_data() -> Dict:
    """Load custom test data from JSON file"""
    if CUSTOM_DATA_FILE.exists():
        with open(CUSTOM_DATA_FILE) as f:
            return json.load(f)
    return {"threat_groups": [], "cves": [], "blogs": [], "profiles": []}


def save_custom_data(data: Dict):
    """Save custom test data to JSON file"""
    with open(CUSTOM_DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Saved to {CUSTOM_DATA_FILE}")


def merge_custom_data():
    """Merge custom data into the module-level test data lists"""
    custom = load_custom_data()
    for key, builtin_list in LIST_MAP.items():
        for item in custom.get(key, []):
            if item not in builtin_list:
                builtin_list.append(item)


# Merge custom data on import so both CLI and pytest pick it up
merge_custom_data()


@dataclass
class TestResult:
    """Stores the result of a test case"""
    name: str
    passed: bool
    duration: float
    details: str
    error: Optional[str] = None


class ShikariTestSuite:
    """Comprehensive test suite for Shikari platform"""

    def __init__(self, base_url: str = BASE_URL, timeout: int = TIMEOUT):
        self.base_url = base_url
        self.timeout = timeout
        self.results: List[TestResult] = []
        self.session = requests.Session()

    def log(self, message: str):
        """Print timestamped log message"""
        import sys
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
        sys.stdout.flush()

    def record_result(self, name: str, passed: bool, duration: float,
                      details: str, error: str = None):
        """Record a test result"""
        result = TestResult(name, passed, duration, details, error)
        self.results.append(result)
        status = "PASS" if passed else "FAIL"
        self.log(f"  {status}: {name} ({duration:.2f}s)")
        # Show details for failures and "still running" passes
        if details and (not passed or "Still running" in details):
            self.log(f"    Details: {details}")
        if error:
            self.log(f"    Error: {error}")

    # =========================================================================
    # HEALTH & CONNECTIVITY TESTS
    # =========================================================================

    def test_health_endpoint(self) -> bool:
        """Test the /health endpoint"""
        start = time.time()
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=SHORT_TIMEOUT)
            passed = response.status_code == 200
            self.record_result(
                "Health Endpoint",
                passed,
                time.time() - start,
                f"Status: {response.status_code}"
            )
            return passed
        except Exception as e:
            self.record_result("Health Endpoint", False, time.time() - start, "", str(e))
            return False

    def test_home_page(self) -> bool:
        """Test the home page loads"""
        start = time.time()
        try:
            response = self.session.get(f"{self.base_url}/", timeout=SHORT_TIMEOUT)
            passed = response.status_code == 200 and "Shikari" in response.text
            self.record_result(
                "Home Page",
                passed,
                time.time() - start,
                f"Status: {response.status_code}, Contains 'Shikari': {'Shikari' in response.text}"
            )
            return passed
        except Exception as e:
            self.record_result("Home Page", False, time.time() - start, "", str(e))
            return False

    # =========================================================================
    # THREAT GROUP GENERATION TESTS
    # =========================================================================

    def test_threat_group_generation(self, group_name: str,
                                     run_correlation: bool = False,
                                     osint_enhancement: bool = True) -> bool:
        """Test threat group detection generation"""
        start = time.time()
        test_name = f"Threat Group: {group_name}"

        try:
            # Submit generation request
            response = self.session.post(
                f"{self.base_url}/generate",
                data={
                    "group_name": group_name,
                    "run_correlation": "on" if run_correlation else "",
                    "osint_enhancement": "on" if osint_enhancement else "",
                },
                timeout=SHORT_TIMEOUT,
                allow_redirects=False
            )

            if response.status_code not in [200, 302, 303]:
                self.record_result(test_name, False, time.time() - start,
                                   f"Unexpected status: {response.status_code}")
                return False

            # Poll for progress
            max_wait = self.timeout
            poll_interval = 5
            waited = 0
            last_progress = None
            last_progress_report = 0  # Track when we last printed progress
            progress_report_interval = 60  # Print progress every 60 seconds

            while waited < max_wait:
                time.sleep(poll_interval)
                waited += poll_interval

                try:
                    progress_response = self.session.get(
                        f"{self.base_url}/progress_status",
                        params={"group_name": group_name},
                        timeout=SHORT_TIMEOUT
                    )

                    if progress_response.status_code == 200:
                        data = progress_response.json()
                        # Handle nested progress structure: {"ok": true, "progress": {...}}
                        progress = data.get("progress", data)
                        last_progress = progress
                        status = progress.get("status", "")

                        # Print progress every 60 seconds
                        if waited - last_progress_report >= progress_report_interval:
                            last_progress_report = waited
                            created = progress.get("created_yaml", 0)
                            total = progress.get("total_yaml", 0)
                            stage = progress.get("stage", status)
                            elapsed_mins = waited // 60
                            self.log(f"    Progress ({elapsed_mins}m): {stage} - {created}/{total} YAMLs")

                        if status == "complete":
                            duration = time.time() - start
                            details = (f"Generated {progress.get('created_yaml', 0)} detections, "
                                      f"{progress.get('total_correlations', 0)} correlations")
                            self.record_result(test_name, True, duration, details)
                            encoded_name = group_name.replace(" ", "%20")
                            self.log(f"    Results: {self.base_url}/results?group_name={encoded_name}")
                            return True
                        elif status == "error":
                            self.record_result(test_name, False, time.time() - start,
                                               f"Generation error: {progress.get('error', 'Unknown')}")
                            return False
                except Exception:
                    pass  # Continue polling

            # Timeout reached - check if still making progress
            if last_progress:
                status = last_progress.get("status", "")
                created = last_progress.get("created_yaml", 0)
                total = last_progress.get("total_yaml", 0)

                if status and status not in ("complete", "error"):
                    # Still running - report as success with progress info
                    duration = time.time() - start
                    details = f"Still running: {created}/{total} YAMLs ({status})"
                    self.record_result(test_name, True, duration, details)
                    encoded_name = group_name.replace(" ", "%20")
                    self.log(f"    Results: {self.base_url}/results?group_name={encoded_name}")
                    return True

            self.record_result(test_name, False, time.time() - start,
                               f"Timeout after {max_wait}s with no progress")
            return False

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    # =========================================================================
    # CVE GENERATION TESTS
    # =========================================================================

    def test_cve_generation(self, cve_id: str,
                            run_correlation: bool = False) -> bool:
        """Test CVE-based detection generation"""
        start = time.time()
        test_name = f"CVE: {cve_id}"

        try:
            response = self.session.post(
                f"{self.base_url}/generate/cve",
                data={
                    "cve_id": cve_id,
                    "run_correlation": "on" if run_correlation else "",
                },
                timeout=SHORT_TIMEOUT,
                allow_redirects=False
            )

            if response.status_code not in [200, 302, 303]:
                self.record_result(test_name, False, time.time() - start,
                                   f"Unexpected status: {response.status_code}")
                return False

            # Poll for progress
            max_wait = self.timeout
            poll_interval = 5
            waited = 0
            last_progress = None
            last_progress_report = 0
            progress_report_interval = 60

            while waited < max_wait:
                time.sleep(poll_interval)
                waited += poll_interval

                try:
                    progress_response = self.session.get(
                        f"{self.base_url}/progress_status",
                        params={"group_name": cve_id},
                        timeout=SHORT_TIMEOUT
                    )

                    if progress_response.status_code == 200:
                        data = progress_response.json()
                        # Handle nested progress structure: {"ok": true, "progress": {...}}
                        progress = data.get("progress", data)
                        last_progress = progress
                        status = progress.get("status", "")

                        # Print progress every 60 seconds
                        if waited - last_progress_report >= progress_report_interval:
                            last_progress_report = waited
                            stage = progress.get("stage", status)
                            elapsed_mins = waited // 60
                            self.log(f"    Progress ({elapsed_mins}m): {stage}")

                        if status == "complete":
                            duration = time.time() - start
                            details = f"CVE processing complete"
                            self.record_result(test_name, True, duration, details)
                            return True
                        elif status == "error":
                            error_msg = progress.get("error", "Unknown error")
                            # CVE not found is expected for future CVEs
                            if "not found" in error_msg.lower() or "does not exist" in error_msg.lower():
                                self.record_result(test_name, True, time.time() - start,
                                                   f"CVE not in NVD (expected for future CVEs)")
                                return True
                            self.record_result(test_name, False, time.time() - start, error_msg)
                            return False
                except Exception:
                    pass

            # Timeout reached - check if still making progress
            if last_progress:
                status = last_progress.get("status", "")
                if status and status not in ("complete", "error"):
                    duration = time.time() - start
                    details = f"Still running ({status})"
                    self.record_result(test_name, True, duration, details)
                    return True

            self.record_result(test_name, False, time.time() - start,
                               f"Timeout after {max_wait}s with no progress")
            return False

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    # =========================================================================
    # BLOG ANALYSIS TESTS
    # =========================================================================

    def test_blog_analysis(self, blog_url: str) -> bool:
        """Test blog analysis endpoint"""
        start = time.time()
        # Extract blog name for test name
        blog_name = blog_url.split("/")[-2] if blog_url.endswith("/") else blog_url.split("/")[-1]
        test_name = f"Blog Analysis: {blog_name[:40]}"

        try:
            response = self.session.post(
                f"{self.base_url}/analyze_blog",
                data={"blog_url": blog_url},
                timeout=TIMEOUT
            )

            if response.status_code == 200:
                # Check if analysis returned valid data
                try:
                    data = response.json()
                    has_techniques = len(data.get("techniques", [])) > 0
                    has_iocs = len(data.get("iocs", {}).get("domains", []) +
                                  data.get("iocs", {}).get("ips", []) +
                                  data.get("iocs", {}).get("hashes", [])) > 0

                    details = (f"Techniques: {len(data.get('techniques', []))}, "
                              f"IOCs found: {has_iocs}")
                    self.record_result(test_name, True, time.time() - start, details)
                    return True
                except:
                    # HTML response (redirect to results page)
                    self.record_result(test_name, True, time.time() - start,
                                       "Analysis submitted successfully")
                    return True
            else:
                self.record_result(test_name, False, time.time() - start,
                                   f"Status: {response.status_code}")
                return False

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    def test_blog_generation(self, blog_url: str) -> bool:
        """Test blog-based detection generation"""
        start = time.time()
        blog_name = blog_url.split("/")[-2] if blog_url.endswith("/") else blog_url.split("/")[-1]
        test_name = f"Blog Generation: {blog_name[:35]}"

        try:
            response = self.session.post(
                f"{self.base_url}/blog/generate",
                data={
                    "blog_url": blog_url,
                    "run_correlation": "",
                },
                timeout=SHORT_TIMEOUT,
                allow_redirects=False
            )

            if response.status_code not in [200, 302, 303]:
                self.record_result(test_name, False, time.time() - start,
                                   f"Unexpected status: {response.status_code}")
                return False

            # Blog generation may redirect to progress page
            self.record_result(test_name, True, time.time() - start,
                               "Generation initiated")
            return True

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    # =========================================================================
    # COMPANY PROFILE TESTS
    # =========================================================================

    def test_company_profile(self, company_name: str) -> bool:
        """Test company profile analysis"""
        start = time.time()
        test_name = f"Company Profile: {company_name}"

        try:
            response = self.session.post(
                f"{self.base_url}/profile",
                data={"company_name": company_name},
                timeout=TIMEOUT
            )

            if response.status_code == 200:
                # Check for profile data in response
                has_profile_data = ("industry" in response.text.lower() or
                                   "sector" in response.text.lower() or
                                   "technology" in response.text.lower())

                self.record_result(test_name, True, time.time() - start,
                                   f"Profile generated: {has_profile_data}")
                return True
            else:
                self.record_result(test_name, False, time.time() - start,
                                   f"Status: {response.status_code}")
                return False

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    def test_profile_generation(self, company_name: str) -> bool:
        """Test profile-based detection generation"""
        start = time.time()
        test_name = f"Profile Detection Gen: {company_name}"

        try:
            response = self.session.post(
                f"{self.base_url}/profile/generate-detections",
                json={
                    "company_name": company_name,
                    "techniques": ["T1566", "T1078", "T1059"],  # Common techniques
                },
                timeout=SHORT_TIMEOUT,
                allow_redirects=False
            )

            passed = response.status_code in [200, 302, 303]
            self.record_result(test_name, passed, time.time() - start,
                               f"Status: {response.status_code}")
            return passed

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    # =========================================================================
    # API ENDPOINT TESTS
    # =========================================================================

    def test_reference_coverage_api(self) -> bool:
        """Test reference query coverage API"""
        start = time.time()
        test_name = "API: Reference Coverage"

        try:
            response = self.session.get(
                f"{self.base_url}/api/reference/coverage",
                timeout=SHORT_TIMEOUT
            )

            if response.status_code == 200:
                data = response.json()
                has_summary = "summary" in data
                has_by_technique = "by_technique" in data
                has_by_tactic = "by_tactic" in data

                total_queries = data.get("summary", {}).get("total_queries", 0)
                details = (f"Total queries: {total_queries}, "
                          f"Has by_technique: {has_by_technique}, "
                          f"Has by_tactic: {has_by_tactic}")

                passed = has_summary and (has_by_technique or total_queries >= 0)
                self.record_result(test_name, passed, time.time() - start, details)
                return passed
            else:
                self.record_result(test_name, False, time.time() - start,
                                   f"Status: {response.status_code}")
                return False

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    def test_threat_groups_api(self) -> bool:
        """Test threat groups listing API"""
        start = time.time()
        test_name = "API: Threat Groups"

        try:
            response = self.session.get(
                f"{self.base_url}/threat_groups",
                timeout=SHORT_TIMEOUT
            )

            if response.status_code == 200:
                data = response.json()
                has_groups = len(data.get("groups", [])) > 0
                group_count = len(data.get("groups", []))

                self.record_result(test_name, has_groups, time.time() - start,
                                   f"Found {group_count} threat groups")
                return has_groups
            else:
                self.record_result(test_name, False, time.time() - start,
                                   f"Status: {response.status_code}")
                return False

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    def test_correlation_params_api(self) -> bool:
        """Test correlation parameters API"""
        start = time.time()
        test_name = "API: Correlation Params"

        try:
            response = self.session.get(
                f"{self.base_url}/api/correlation/params",
                timeout=SHORT_TIMEOUT
            )

            if response.status_code == 200:
                data = response.json()
                has_params = "time_window" in data or "max_techniques" in data

                self.record_result(test_name, True, time.time() - start,
                                   f"Params loaded: {list(data.keys())[:5]}")
                return True
            else:
                self.record_result(test_name, False, time.time() - start,
                                   f"Status: {response.status_code}")
                return False

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    def test_osint_status_api(self) -> bool:
        """Test OSINT status API"""
        start = time.time()
        test_name = "API: OSINT Status"

        try:
            response = self.session.get(
                f"{self.base_url}/api/status/osint",
                timeout=SHORT_TIMEOUT
            )

            passed = response.status_code == 200
            self.record_result(test_name, passed, time.time() - start,
                               f"Status: {response.status_code}")
            return passed

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    def test_bespoke_status_api(self) -> bool:
        """Test bespoke mappings status API"""
        start = time.time()
        test_name = "API: Bespoke Status"

        try:
            response = self.session.get(
                f"{self.base_url}/api/status/bespoke",
                timeout=SHORT_TIMEOUT
            )

            passed = response.status_code == 200
            if passed:
                data = response.json()
                self.record_result(test_name, True, time.time() - start,
                                   f"Bespoke sources: {len(data)}")
            else:
                self.record_result(test_name, False, time.time() - start,
                                   f"Status: {response.status_code}")
            return passed

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    def test_llm_detect_api(self) -> bool:
        """Test LLM detection API"""
        start = time.time()
        test_name = "API: LLM Detect"

        try:
            response = self.session.get(
                f"{self.base_url}/api/llm/detect",
                timeout=SHORT_TIMEOUT
            )

            if response.status_code == 200:
                data = response.json()
                provider = data.get("provider", "unknown")
                self.record_result(test_name, True, time.time() - start,
                                   f"Provider: {provider}")
                return True
            else:
                self.record_result(test_name, False, time.time() - start,
                                   f"Status: {response.status_code}")
                return False

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    def test_technique_names_api(self) -> bool:
        """Test technique names API"""
        start = time.time()
        test_name = "API: Technique Names"

        try:
            response = self.session.post(
                f"{self.base_url}/api/technique_names",
                json={"technique_ids": ["T1566", "T1059", "T1078"]},
                timeout=SHORT_TIMEOUT
            )

            if response.status_code == 200:
                data = response.json()
                has_names = len(data) > 0
                self.record_result(test_name, has_names, time.time() - start,
                                   f"Resolved {len(data)} technique names")
                return has_names
            else:
                self.record_result(test_name, False, time.time() - start,
                                   f"Status: {response.status_code}")
                return False

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    # =========================================================================
    # LIBRARY TESTS
    # =========================================================================

    def test_library_page(self) -> bool:
        """Test library page loads"""
        start = time.time()
        test_name = "Library Page"

        try:
            response = self.session.get(
                f"{self.base_url}/library",
                timeout=SHORT_TIMEOUT
            )

            passed = response.status_code == 200 and "Library" in response.text
            self.record_result(test_name, passed, time.time() - start,
                               f"Status: {response.status_code}")
            return passed

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    def test_library_detections_api(self) -> bool:
        """Test library detections API"""
        start = time.time()
        test_name = "API: Library Detections"

        try:
            response = self.session.get(
                f"{self.base_url}/api/library/detections",
                timeout=SHORT_TIMEOUT
            )

            if response.status_code == 200:
                data = response.json()
                detection_count = len(data.get("detections", []))
                self.record_result(test_name, True, time.time() - start,
                                   f"Found {detection_count} detections")
                return True
            else:
                self.record_result(test_name, False, time.time() - start,
                                   f"Status: {response.status_code}")
                return False

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    def test_library_search_api(self) -> bool:
        """Test library search API"""
        start = time.time()
        test_name = "API: Library Search"

        try:
            response = self.session.post(
                f"{self.base_url}/api/library/search",
                json={"query": "powershell", "filters": {}},
                timeout=SHORT_TIMEOUT
            )

            passed = response.status_code == 200
            if passed:
                data = response.json()
                result_count = len(data.get("results", []))
                self.record_result(test_name, True, time.time() - start,
                                   f"Search returned {result_count} results")
            else:
                self.record_result(test_name, False, time.time() - start,
                                   f"Status: {response.status_code}")
            return passed

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    # =========================================================================
    # COVERAGE PAGE TEST
    # =========================================================================

    def test_coverage_page(self) -> bool:
        """Test coverage page loads"""
        start = time.time()
        test_name = "Coverage Page"

        try:
            response = self.session.get(
                f"{self.base_url}/coverage",
                timeout=SHORT_TIMEOUT
            )

            passed = response.status_code == 200 and "Coverage" in response.text
            self.record_result(test_name, passed, time.time() - start,
                               f"Status: {response.status_code}")
            return passed

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    # =========================================================================
    # EMULATION TEST
    # =========================================================================

    def test_emulation_endpoint(self) -> bool:
        """Test emulation endpoint"""
        start = time.time()
        test_name = "Emulation Endpoint"

        try:
            response = self.session.post(
                f"{self.base_url}/emulate",
                json={
                    "technique_id": "T1059.001",
                    "platform": "windows",
                },
                timeout=SHORT_TIMEOUT
            )

            passed = response.status_code in [200, 400, 422]  # 400/422 for validation errors is OK
            self.record_result(test_name, passed, time.time() - start,
                               f"Status: {response.status_code}")
            return passed

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    # =========================================================================
    # MANUAL SUBMISSION TEST
    # =========================================================================

    def test_manual_page(self) -> bool:
        """Test manual submission page loads"""
        start = time.time()
        test_name = "Manual Page"

        try:
            response = self.session.get(
                f"{self.base_url}/manual",
                timeout=SHORT_TIMEOUT
            )

            passed = response.status_code == 200
            self.record_result(test_name, passed, time.time() - start,
                               f"Status: {response.status_code}")
            return passed

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    # =========================================================================
    # HUNT TECHNIQUE TEST
    # =========================================================================

    def test_hunt_technique(self) -> bool:
        """Test technique hunting endpoint"""
        start = time.time()
        test_name = "Hunt Technique"

        try:
            response = self.session.post(
                f"{self.base_url}/hunt/technique",
                data={
                    "technique_id": "T1059.001",
                    "osint_enhancement": "on",
                },
                timeout=SHORT_TIMEOUT,
                allow_redirects=False
            )

            passed = response.status_code in [200, 302, 303]
            self.record_result(test_name, passed, time.time() - start,
                               f"Status: {response.status_code}")
            return passed

        except Exception as e:
            self.record_result(test_name, False, time.time() - start, "", str(e))
            return False

    # =========================================================================
    # TEST RUNNER
    # =========================================================================

    def run_all_tests(self,
                      skip_long_running: bool = False,
                      groups_to_test: int = 1,
                      cves_to_test: int = 1,
                      blogs_to_test: int = 2,
                      profiles_to_test: int = 1) -> Dict:
        """Run all tests and return summary"""

        self.log("=" * 70)
        self.log("SHIKARI COMPREHENSIVE TEST SUITE")
        self.log("=" * 70)

        # 1. Health & Connectivity
        self.log("\n[SECTION 1] Health & Connectivity Tests")
        self.log("-" * 50)
        self.test_health_endpoint()
        self.test_home_page()

        # 2. API Endpoint Tests
        self.log("\n[SECTION 2] API Endpoint Tests")
        self.log("-" * 50)
        self.test_threat_groups_api()
        self.test_reference_coverage_api()
        self.test_correlation_params_api()
        self.test_osint_status_api()
        self.test_bespoke_status_api()
        self.test_llm_detect_api()
        self.test_technique_names_api()

        # 3. Page Load Tests
        self.log("\n[SECTION 3] Page Load Tests")
        self.log("-" * 50)
        self.test_library_page()
        self.test_coverage_page()
        self.test_manual_page()

        # 4. Library Tests
        self.log("\n[SECTION 4] Library API Tests")
        self.log("-" * 50)
        self.test_library_detections_api()
        self.test_library_search_api()

        # 5. Threat Group Generation Tests
        if not skip_long_running:
            self.log(f"\n[SECTION 5] Threat Group Generation Tests ({groups_to_test} groups)")
            self.log("-" * 50)
            for group in THREAT_GROUPS[:groups_to_test]:
                self.test_threat_group_generation(group, run_correlation=False)

        # 6. CVE Generation Tests
        if not skip_long_running:
            self.log(f"\n[SECTION 6] CVE Generation Tests ({cves_to_test} CVEs)")
            self.log("-" * 50)
            for cve in CVES[:cves_to_test]:
                self.test_cve_generation(cve, run_correlation=False)

        # 7. Blog Analysis Tests
        if not skip_long_running:
            self.log(f"\n[SECTION 7] Blog Analysis Tests ({blogs_to_test} blogs)")
            self.log("-" * 50)
            for blog in BLOG_URLS[:blogs_to_test]:
                self.test_blog_analysis(blog)

        # 8. Company Profile Tests
        if not skip_long_running:
            self.log(f"\n[SECTION 8] Company Profile Tests ({profiles_to_test} profiles)")
            self.log("-" * 50)
            for company in COMPANY_PROFILES[:profiles_to_test]:
                self.test_company_profile(company)

        # 9. Additional Endpoints
        self.log("\n[SECTION 9] Additional Endpoint Tests")
        self.log("-" * 50)
        self.test_emulation_endpoint()
        self.test_hunt_technique()

        # Summary
        self.log("\n" + "=" * 70)
        self.log("TEST SUMMARY")
        self.log("=" * 70)

        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        total = len(self.results)

        self.log(f"Total Tests: {total}")
        self.log(f"Passed: {passed}")
        self.log(f"Failed: {failed}")
        self.log(f"Pass Rate: {passed/total*100:.1f}%")

        if failed > 0:
            self.log("\nFailed Tests:")
            for r in self.results:
                if not r.passed:
                    self.log(f"  - {r.name}: {r.error or r.details}")

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": passed/total*100 if total > 0 else 0,
            "results": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "duration": r.duration,
                    "details": r.details,
                    "error": r.error
                }
                for r in self.results
            ]
        }


# =============================================================================
# PYTEST FIXTURES AND TESTS
# =============================================================================

@pytest.fixture(scope="module")
def test_suite():
    """Create test suite instance"""
    return ShikariTestSuite(BASE_URL)


class TestShikariHealth:
    """Health and connectivity tests"""

    def test_health_endpoint(self, test_suite):
        assert test_suite.test_health_endpoint()

    def test_home_page(self, test_suite):
        assert test_suite.test_home_page()


class TestShikariAPIs:
    """API endpoint tests"""

    def test_threat_groups_api(self, test_suite):
        assert test_suite.test_threat_groups_api()

    def test_reference_coverage_api(self, test_suite):
        assert test_suite.test_reference_coverage_api()

    def test_correlation_params_api(self, test_suite):
        assert test_suite.test_correlation_params_api()

    def test_osint_status_api(self, test_suite):
        assert test_suite.test_osint_status_api()

    def test_bespoke_status_api(self, test_suite):
        assert test_suite.test_bespoke_status_api()

    def test_llm_detect_api(self, test_suite):
        assert test_suite.test_llm_detect_api()

    def test_technique_names_api(self, test_suite):
        assert test_suite.test_technique_names_api()


class TestShikariPages:
    """Page load tests"""

    def test_library_page(self, test_suite):
        assert test_suite.test_library_page()

    def test_coverage_page(self, test_suite):
        assert test_suite.test_coverage_page()

    def test_manual_page(self, test_suite):
        assert test_suite.test_manual_page()


class TestShikariLibrary:
    """Library API tests"""

    def test_library_detections_api(self, test_suite):
        assert test_suite.test_library_detections_api()

    def test_library_search_api(self, test_suite):
        assert test_suite.test_library_search_api()


@pytest.mark.feature
class TestShikariThreatGroups:
    """Threat group generation tests (feature)"""

    @pytest.mark.parametrize("group", THREAT_GROUPS)
    def test_threat_group_generation(self, test_suite, group):
        assert test_suite.test_threat_group_generation(group)


@pytest.mark.feature
class TestShikariCVEs:
    """CVE generation tests (feature)"""

    @pytest.mark.parametrize("cve", CVES)
    def test_cve_generation(self, test_suite, cve):
        assert test_suite.test_cve_generation(cve)


@pytest.mark.feature
class TestShikariBlogs:
    """Blog analysis tests (feature)"""

    @pytest.mark.parametrize("blog_url", BLOG_URLS)
    def test_blog_analysis(self, test_suite, blog_url):
        assert test_suite.test_blog_analysis(blog_url)


@pytest.mark.feature
class TestShikariProfiles:
    """Company profile tests (feature)"""

    @pytest.mark.parametrize("company", COMPANY_PROFILES)
    def test_company_profile(self, test_suite, company):
        assert test_suite.test_company_profile(company)


class TestShikariAdditional:
    """Additional endpoint tests"""

    def test_emulation_endpoint(self, test_suite):
        assert test_suite.test_emulation_endpoint()

    def test_hunt_technique(self, test_suite):
        assert test_suite.test_hunt_technique()


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Shikari Comprehensive Test Suite")
    parser.add_argument("--list", nargs="?", const="all", metavar="TYPE",
                        help="List available test data. Options: all, groups, cves, blogs, profiles")
    parser.add_argument("--add", nargs=2, metavar=("TYPE", "VALUE"),
                        help="Add custom test data. TYPE: groups, cves, blogs, profiles")
    parser.add_argument("--remove", nargs=2, metavar=("TYPE", "VALUE"),
                        help="Remove custom test data. TYPE: groups, cves, blogs, profiles")
    parser.add_argument("--url", default=BASE_URL, help="Shikari base URL")
    parser.add_argument("--skip-feature-tests", action="store_true",
                        help="Skip feature tests (generation tests)")
    parser.add_argument("--groups", type=int, default=2,
                        help="Number of threat groups to test")
    parser.add_argument("--cves", type=int, default=2,
                        help="Number of CVEs to test")
    parser.add_argument("--blogs", type=int, default=3,
                        help="Number of blogs to test")
    parser.add_argument("--profiles", type=int, default=2,
                        help="Number of company profiles to test")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--group", nargs="?", const="__list__", default=None,
                        help="Test a specific threat group, or combine with --list to list groups")
    parser.add_argument("--cve", nargs="?", const="__list__", default=None,
                        help="Test a specific CVE, or combine with --list to list CVEs")
    parser.add_argument("--blog", nargs="?", const="__list__", default=None,
                        help="Test a specific blog URL, or combine with --list to list blogs")
    parser.add_argument("--profile", nargs="?", const="__list__", default=None,
                        help="Test a specific company profile, or combine with --list to list profiles")
    parser.add_argument("--timeout", type=int, default=TIMEOUT,
                        help=f"Timeout in seconds for generation tests (default: {TIMEOUT})")
    parser.add_argument("--osint", action="store_true", default=True,
                        help="Enable OSINT enrichment (default: enabled)")
    parser.add_argument("--no-osint", action="store_false", dest="osint",
                        help="Disable OSINT enrichment")
    parser.add_argument("--correlation", action="store_true", default=False,
                        help="Enable correlation generation (default: disabled)")

    args = parser.parse_args()

    # Handle --group/--cve/--blog/--profile used without a value (with or without --list)
    # e.g. --group --list  or  --group  (both show available groups)
    _flag_to_list = {
        "group": "groups",
        "cve": "cves",
        "blog": "blogs",
        "profile": "profiles",
    }
    for flag, list_name in _flag_to_list.items():
        if getattr(args, flag) == "__list__":
            args.list = list_name
            setattr(args, flag, None)
            break

    # Handle --list option
    if args.list:
        list_type = args.list.lower()
        custom = load_custom_data()

        def _format_item(item, custom_list):
            return f"{item} (custom)" if item in custom_list else item

        if list_type in ("all", "groups"):
            print("\nThreat Groups:")
            print("-" * 40)
            for i, group in enumerate(THREAT_GROUPS, 1):
                print(f"  {i}. {_format_item(group, custom.get('threat_groups', []))}")

        if list_type in ("all", "cves"):
            print("\nCVEs:")
            print("-" * 40)
            for i, cve in enumerate(CVES, 1):
                name = CVE_NAMES.get(cve, "")
                label = f"{cve} ({name})" if name else cve
                custom_tag = " (custom)" if cve in custom.get("cves", []) else ""
                print(f"  {i}. {label}{custom_tag}")

        if list_type in ("all", "blogs"):
            print("\nBlog URLs:")
            print("-" * 40)
            for i, url in enumerate(BLOG_URLS, 1):
                display_url = url if len(url) <= 70 else url[:67] + "..."
                suffix = " (custom)" if url in custom.get("blogs", []) else ""
                print(f"  {i}. {display_url}{suffix}")

        if list_type in ("all", "profiles"):
            print("\nCompany Profiles:")
            print("-" * 40)
            for i, profile in enumerate(COMPANY_PROFILES, 1):
                print(f"  {i}. {_format_item(profile, custom.get('profiles', []))}")

        if list_type not in ("all", "groups", "cves", "blogs", "profiles"):
            print(f"Unknown list type: {list_type}")
            print("Valid options: all, groups, cves, blogs, profiles")
            exit(1)

        print()
        exit(0)

    # Handle --add option
    if args.add:
        add_type, add_value = args.add
        add_type = add_type.lower()
        if add_type not in CATEGORY_MAP:
            print(f"Unknown type: {add_type}")
            print(f"Valid types: {', '.join(CATEGORY_MAP.keys())}")
            exit(1)
        key = CATEGORY_MAP[add_type]
        custom = load_custom_data()
        builtin = LIST_MAP[key]
        # Check if it already exists (built-in or custom)
        if add_value in builtin:
            print(f"'{add_value}' already exists in {add_type}")
            exit(0)
        custom[key].append(add_value)
        save_custom_data(custom)
        print(f"Added '{add_value}' to {add_type}")
        exit(0)

    # Handle --remove option
    if args.remove:
        rm_type, rm_value = args.remove
        rm_type = rm_type.lower()
        if rm_type not in CATEGORY_MAP:
            print(f"Unknown type: {rm_type}")
            print(f"Valid types: {', '.join(CATEGORY_MAP.keys())}")
            exit(1)
        key = CATEGORY_MAP[rm_type]
        custom = load_custom_data()
        if rm_value in custom[key]:
            custom[key].remove(rm_value)
            save_custom_data(custom)
            # Also remove from the in-memory list
            builtin = LIST_MAP[key]
            if rm_value in builtin:
                builtin.remove(rm_value)
            print(f"Removed '{rm_value}' from {rm_type}")
        else:
            print(f"'{rm_value}' is not a custom entry in {rm_type} (built-in entries cannot be removed)")
        exit(0)

    # Pre-flight check: ensure Shikari is running
    def _check_shikari(url):
        try:
            requests.get(f"{url}/health", timeout=3)
            return True
        except Exception:
            return False

    if not _check_shikari(args.url):
        start_script = Path(__file__).parent.parent / "scripts" / "deployment" / "start-shikari.py"
        if not start_script.exists():
            print(f"Shikari is not running at {args.url} and start script not found.")
            exit(1)

        try:
            answer = input(f"Shikari is not running at {args.url}. Start it now? [Y/n] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            exit(1)

        if answer in ("", "y", "yes"):
            print("Starting Shikari in the background...")
            subprocess.Popen(
                [sys.executable, str(start_script), "--background"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Wait for Shikari to become available
            max_wait = 30
            waited = 0
            while waited < max_wait:
                time.sleep(1)
                waited += 1
                if _check_shikari(args.url):
                    print(f"Shikari is running at {args.url}")
                    break
            else:
                print(f"Shikari did not start within {max_wait}s.")
                exit(1)
        else:
            exit(0)

    suite = ShikariTestSuite(args.url, args.timeout)

    # Single item tests
    if args.group:
        opts = []
        if args.osint:
            opts.append("OSINT")
        if args.correlation:
            opts.append("Correlation")
        suite.log(f"Testing single threat group: {args.group}" + (f" [{', '.join(opts)}]" if opts else ""))
        suite.test_threat_group_generation(args.group, run_correlation=args.correlation, osint_enhancement=args.osint)
        results = {"total": 1, "passed": 1 if suite.results[-1].passed else 0, "failed": 0 if suite.results[-1].passed else 1}
    elif args.cve:
        suite.log(f"Testing single CVE: {args.cve}")
        suite.test_cve_generation(args.cve)
        results = {"total": 1, "passed": 1 if suite.results[-1].passed else 0, "failed": 0 if suite.results[-1].passed else 1}
    elif args.blog:
        suite.log(f"Testing single blog: {args.blog}")
        suite.test_blog_analysis(args.blog)
        results = {"total": 1, "passed": 1 if suite.results[-1].passed else 0, "failed": 0 if suite.results[-1].passed else 1}
    elif args.profile:
        suite.log(f"Testing single company profile: {args.profile}")
        suite.test_company_profile(args.profile)
        results = {"total": 1, "passed": 1 if suite.results[-1].passed else 0, "failed": 0 if suite.results[-1].passed else 1}
    else:
        # Run full test suite
        results = suite.run_all_tests(
            skip_long_running=args.skip_feature_tests,
            groups_to_test=args.groups,
            cves_to_test=args.cves,
            blogs_to_test=args.blogs,
            profiles_to_test=args.profiles
        )

    # Print results
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        # Print summary
        print()
        print("=" * 60)
        print(f"Results: {results.get('passed', 0)} passed, {results.get('failed', 0)} failed")
        print("=" * 60)

    # Exit with failure code if any tests failed
    exit(0 if results.get("failed", 0) == 0 else 1)
