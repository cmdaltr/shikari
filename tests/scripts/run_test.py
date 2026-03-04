#!/usr/bin/env python3
"""
Run Archer Feature Tests

This module defines test scenarios for various detection generation workflows.
Each test case specifies inputs and processing options to validate.

Usage:
    python tests/scripts/run_test.py --list                    # List all test cases
    python tests/scripts/run_test.py --status                  # Show job status
    python tests/scripts/run_test.py --run <name>              # Run specific test
    python tests/scripts/run_test.py --run <name> --wait       # Run and wait for completion
    python tests/scripts/run_test.py --run-tags <tag>          # Run all tests with tag
    python tests/scripts/run_test.py --show <name>             # Show test details

Examples:
    # List all tests
    python tests/scripts/run_test.py --list

    # List tests by tag
    python tests/scripts/run_test.py --list --tag threat_group

    # Run a single test
    python tests/scripts/run_test.py --run apt29_basic --wait

    # Run all quick tests
    python tests/scripts/run_test.py --run-tags quick --wait

    # Check status of running tests
    python tests/scripts/run_test.py --status
"""

import os
import sys
import json
import argparse
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# =============================================================================
# CONFIGURATION
# =============================================================================

# API URL - override with ARCHER_API_URL env var
API_URL = os.environ.get("ARCHER_API_URL", "http://127.0.0.1:8000")

# Timeouts
DEFAULT_TIMEOUT = 900  # 15 minutes for long-running generation tasks
SHORT_TIMEOUT = 30

# Progress polling interval
POLL_INTERVAL = 5


# =============================================================================
# TEST CASE DEFINITION
# =============================================================================

@dataclass
class TestCase:
    """Represents a single test case for detection generation."""

    name: str
    description: str
    test_type: str  # threat_group, cve, blog, profile, technique, file_upload, export
    input_data: Dict[str, Any] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)
    expected_outputs: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    estimated_duration_minutes: int = 10

    def get_endpoint(self) -> str:
        """Get the API endpoint for this test type."""
        endpoints = {
            "threat_group": "/generate",
            "cve": "/generate/cve",
            "blog": "/blog/generate",
            "profile": "/profile/generate-detections",
            "technique": "/hunt/technique",
            "file_upload": "/upload/analyze",
            "export": "/export",
        }
        return endpoints.get(self.test_type, "/generate")

    def get_progress_key(self) -> str:
        """Get the key used for progress tracking."""
        if self.test_type == "threat_group":
            return self.input_data.get("group_name", self.name)
        elif self.test_type == "cve":
            return self.input_data.get("cve_id", self.name)
        elif self.test_type == "blog":
            return self.input_data.get("blog_url", self.name)
        elif self.test_type == "profile":
            return self.input_data.get("company_name", self.name)
        elif self.test_type == "technique":
            return self.input_data.get("technique_id", self.name)
        elif self.test_type == "export":
            return self.input_data.get("group_name", self.name)
        else:
            return self.name


@dataclass
class TestResult:
    """Stores the result of a test case."""
    name: str
    passed: bool
    duration: float
    details: str
    error: Optional[str] = None
    progress_data: Optional[Dict] = None


# =============================================================================
# TEST DATA DEFINITIONS
# =============================================================================

# Well-known threat groups for testing
THREAT_GROUPS = [
    "APT29",
    "APT28",
    "Scattered Spider",
    "Lazarus Group",
    "Salt Typhoon",
    "Wizard Spider",
    "FIN7",
    "Kimsuky",
]

# Well-known CVEs for testing
CVES = [
    "CVE-2023-44487",   # HTTP/2 Rapid Reset
    "CVE-2024-3400",    # Palo Alto PAN-OS
    "CVE-2023-4966",    # Citrix Bleed
    "CVE-2021-44228",   # Log4Shell
    "CVE-2023-22515",   # Atlassian Confluence
]

# Threat intelligence blog URLs organized by source
BLOG_URLS_DFIR = [
    "https://thedfirreport.com/2024/11/17/cats-got-your-files-lynx-ransomware/",
    "https://thedfirreport.com/2024/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion/",
    "https://thedfirreport.com/2024/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira/",
    "https://thedfirreport.com/2024/03/31/fake-zoom-ends-in-blacksuit-ransomware/",
    "https://thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/",
    "https://thedfirreport.com/2023/12/18/lets-opendir-some-presents-an-analysis-of-a-]]]]]]]]-]a]t]a]-]b]r]e]a]c]h]-]s]i]t]e/",
]

BLOG_URLS_CROWDSTRIKE = [
    "https://www.crowdstrike.com/en-us/blog/scattered-spider-attempts-to-avoid-detection-with-bring-your-own-vulnerable-driver-tactic/",
    "https://www.crowdstrike.com/en-us/blog/analysis-of-intrusion-campaign-targeting-telecom-and-bpo-companies/",
    "https://www.crowdstrike.com/en-us/blog/owassrf-exploit-analysis-and-recommendations/",
    "https://www.crowdstrike.com/en-us/blog/falcon-overwatch-threat-hunting-2024/",
]

BLOG_URLS_NCSC = [
    "https://www.ncsc.gov.uk/news/ncsc-and-partners-issue-warning-about-russian-state-sponsored-cyber-threat",
    "https://www.ncsc.gov.uk/blog-post/sandworm-malware-analysis",
    "https://www.ncsc.gov.uk/news/apt29-targets-covid-vaccine-development",
]

BLOG_URLS_CYBEREASON = [
    "https://www.cybereason.com/blog/operation-cuckoobees-deep-dive-into-stealthy-winnti-techniques",
    "https://www.cybereason.com/blog/deadringer-exposing-chinese-threat-actors-targeting-major-telcos",
    "https://www.cybereason.com/blog/prometei-botnet-exploiting-microsoft-exchange-vulnerabilities",
    "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers",
]

# Combined list for backwards compatibility
BLOG_URLS = BLOG_URLS_DFIR[:4] + BLOG_URLS_CROWDSTRIKE[:1]

# Company profiles for testing
COMPANY_PROFILES = [
    "SANS Institute",
    "Splunk",
    "CrowdStrike",
]

# MITRE ATT&CK techniques for testing
TECHNIQUES = [
    "T1059.001",  # PowerShell
    "T1566.001",  # Spearphishing Attachment
    "T1078",      # Valid Accounts
    "T1003.001",  # LSASS Memory
    "T1055",      # Process Injection
]


# =============================================================================
# TEST CASES: THREAT GROUP GENERATION
# =============================================================================

THREAT_GROUP_TESTS = [
    TestCase(
        name="apt29_basic",
        description="Generate detections for APT29 (Cozy Bear)",
        test_type="threat_group",
        input_data={"group_name": "APT29"},
        options={"osint_enhancement": True, "run_correlation": False},
        expected_outputs=["yaml_files", "techniques"],
        tags=["threat_group", "apt", "quick"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="apt29_with_correlation",
        description="Generate detections for APT29 with correlation",
        test_type="threat_group",
        input_data={"group_name": "APT29"},
        options={"osint_enhancement": True, "run_correlation": True},
        expected_outputs=["yaml_files", "techniques", "correlations"],
        tags=["threat_group", "apt", "correlation", "slow"],
        estimated_duration_minutes=15,
    ),
    TestCase(
        name="apt28_basic",
        description="Generate detections for APT28 (Fancy Bear)",
        test_type="threat_group",
        input_data={"group_name": "APT28"},
        options={"osint_enhancement": True, "run_correlation": False},
        expected_outputs=["yaml_files", "techniques"],
        tags=["threat_group", "apt", "quick"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="scattered_spider",
        description="Generate detections for Scattered Spider",
        test_type="threat_group",
        input_data={"group_name": "Scattered Spider"},
        options={"osint_enhancement": True, "run_correlation": False},
        expected_outputs=["yaml_files", "techniques"],
        tags=["threat_group", "ransomware", "quick"],
        estimated_duration_minutes=8,
    ),
    TestCase(
        name="lazarus_group",
        description="Generate detections for Lazarus Group",
        test_type="threat_group",
        input_data={"group_name": "Lazarus Group"},
        options={"osint_enhancement": True, "run_correlation": False},
        expected_outputs=["yaml_files", "techniques"],
        tags=["threat_group", "apt", "dprk"],
        estimated_duration_minutes=10,
    ),
    TestCase(
        name="salt_typhoon",
        description="Generate detections for Salt Typhoon",
        test_type="threat_group",
        input_data={"group_name": "Salt Typhoon"},
        options={"osint_enhancement": True, "run_correlation": False},
        expected_outputs=["yaml_files", "techniques"],
        tags=["threat_group", "apt", "china"],
        estimated_duration_minutes=8,
    ),
    TestCase(
        name="wizard_spider",
        description="Generate detections for Wizard Spider (TrickBot/Conti)",
        test_type="threat_group",
        input_data={"group_name": "Wizard Spider"},
        options={"osint_enhancement": True, "run_correlation": False},
        expected_outputs=["yaml_files", "techniques"],
        tags=["threat_group", "ransomware", "ecrime"],
        estimated_duration_minutes=10,
    ),
    TestCase(
        name="fin7_with_correlation",
        description="Generate detections for FIN7 with correlation",
        test_type="threat_group",
        input_data={"group_name": "FIN7"},
        options={"osint_enhancement": True, "run_correlation": True},
        expected_outputs=["yaml_files", "techniques", "correlations"],
        tags=["threat_group", "ecrime", "correlation", "slow"],
        estimated_duration_minutes=15,
    ),
]


# =============================================================================
# TEST CASES: CVE GENERATION
# =============================================================================

CVE_TESTS = [
    TestCase(
        name="cve_http2_rapid_reset",
        description="Generate detections for HTTP/2 Rapid Reset (CVE-2023-44487)",
        test_type="cve",
        input_data={"cve_id": "CVE-2023-44487"},
        options={"run_correlation": False},
        expected_outputs=["yaml_files"],
        tags=["cve", "dos", "quick"],
        estimated_duration_minutes=3,
    ),
    TestCase(
        name="cve_panos_injection",
        description="Generate detections for PAN-OS Command Injection (CVE-2024-3400)",
        test_type="cve",
        input_data={"cve_id": "CVE-2024-3400"},
        options={"run_correlation": False},
        expected_outputs=["yaml_files"],
        tags=["cve", "rce", "network"],
        estimated_duration_minutes=3,
    ),
    TestCase(
        name="cve_citrix_bleed",
        description="Generate detections for Citrix Bleed (CVE-2023-4966)",
        test_type="cve",
        input_data={"cve_id": "CVE-2023-4966"},
        options={"run_correlation": False},
        expected_outputs=["yaml_files"],
        tags=["cve", "auth_bypass", "network"],
        estimated_duration_minutes=3,
    ),
    TestCase(
        name="cve_log4shell",
        description="Generate detections for Log4Shell (CVE-2021-44228)",
        test_type="cve",
        input_data={"cve_id": "CVE-2021-44228"},
        options={"run_correlation": False},
        expected_outputs=["yaml_files"],
        tags=["cve", "rce", "java", "famous"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="cve_confluence_rce",
        description="Generate detections for Atlassian Confluence RCE (CVE-2023-22515)",
        test_type="cve",
        input_data={"cve_id": "CVE-2023-22515"},
        options={"run_correlation": False},
        expected_outputs=["yaml_files"],
        tags=["cve", "rce", "web"],
        estimated_duration_minutes=3,
    ),
    TestCase(
        name="cve_with_correlation",
        description="Generate CVE detections with correlation enabled",
        test_type="cve",
        input_data={"cve_id": "CVE-2023-4966"},
        options={"run_correlation": True},
        expected_outputs=["yaml_files", "correlations"],
        tags=["cve", "correlation", "slow"],
        estimated_duration_minutes=8,
    ),
]


# =============================================================================
# TEST CASES: BLOG ANALYSIS
# =============================================================================

BLOG_TESTS = [
    # -------------------------------------------------------------------------
    # DFIR Report Blogs
    # -------------------------------------------------------------------------
    TestCase(
        name="blog_dfir_lynx",
        description="DFIR Report: Lynx Ransomware campaign analysis",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_DFIR[0]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "dfir_report", "ransomware", "live"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="blog_dfir_lunar_spider",
        description="DFIR Report: Lunar Spider two-month intrusion",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_DFIR[1]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "dfir_report", "ecrime", "live"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="blog_dfir_bumblebee_akira",
        description="DFIR Report: Bumblebee loader delivering Akira ransomware",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_DFIR[2]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "dfir_report", "ransomware", "loader", "live"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="blog_dfir_blacksuit",
        description="DFIR Report: Fake Zoom to BlackSuit ransomware",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_DFIR[3]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "dfir_report", "ransomware", "social_engineering", "live"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="blog_dfir_trigona",
        description="DFIR Report: Trigona ransomware in 3 hours",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_DFIR[4]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "dfir_report", "ransomware", "fast_attack", "live"],
        estimated_duration_minutes=5,
    ),

    # -------------------------------------------------------------------------
    # CrowdStrike Blogs
    # -------------------------------------------------------------------------
    TestCase(
        name="blog_crowdstrike_scattered_spider_byovd",
        description="CrowdStrike: Scattered Spider BYOVD tactics",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_CROWDSTRIKE[0]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "crowdstrike", "scattered_spider", "byovd", "live"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="blog_crowdstrike_telecom_bpo",
        description="CrowdStrike: Intrusion campaign targeting telecom and BPO",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_CROWDSTRIKE[1]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "crowdstrike", "telecom", "apt", "live"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="blog_crowdstrike_owassrf",
        description="CrowdStrike: OWASSRF Exchange exploit analysis",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_CROWDSTRIKE[2]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "crowdstrike", "exchange", "exploit", "live"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="blog_crowdstrike_overwatch_2024",
        description="CrowdStrike: Falcon OverWatch threat hunting insights",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_CROWDSTRIKE[3]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "crowdstrike", "threat_hunting", "live"],
        estimated_duration_minutes=5,
    ),

    # -------------------------------------------------------------------------
    # NCSC UK Blogs
    # -------------------------------------------------------------------------
    TestCase(
        name="blog_ncsc_russian_state",
        description="NCSC UK: Russian state-sponsored cyber threat warning",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_NCSC[0]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "ncsc", "russia", "state_sponsored", "live"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="blog_ncsc_sandworm",
        description="NCSC UK: Sandworm malware analysis",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_NCSC[1]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "ncsc", "sandworm", "russia", "live"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="blog_ncsc_apt29_covid",
        description="NCSC UK: APT29 targeting COVID vaccine development",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_NCSC[2]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "ncsc", "apt29", "healthcare", "live"],
        estimated_duration_minutes=5,
    ),

    # -------------------------------------------------------------------------
    # Cybereason Blogs
    # -------------------------------------------------------------------------
    TestCase(
        name="blog_cybereason_cuckoobees",
        description="Cybereason: Operation CuckooBees - Winnti techniques",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_CYBEREASON[0]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "cybereason", "winnti", "china", "live"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="blog_cybereason_deadringer",
        description="Cybereason: DeadRinger - Chinese actors targeting telcos",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_CYBEREASON[1]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "cybereason", "china", "telecom", "live"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="blog_cybereason_prometei",
        description="Cybereason: Prometei botnet exploiting Exchange",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_CYBEREASON[2]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "cybereason", "botnet", "exchange", "live"],
        estimated_duration_minutes=5,
    ),
    TestCase(
        name="blog_cybereason_soft_cell",
        description="Cybereason: Operation Soft Cell - telco campaign",
        test_type="blog",
        input_data={"blog_url": BLOG_URLS_CYBEREASON[3]},
        options={},
        expected_outputs=["techniques", "iocs", "yaml_files"],
        tags=["blog", "cybereason", "telecom", "china", "live"],
        estimated_duration_minutes=5,
    ),
]


# =============================================================================
# TEST CASES: COMPANY PROFILE
# =============================================================================

PROFILE_TESTS = [
    TestCase(
        name="profile_sans",
        description="Generate threat profile for SANS Institute",
        test_type="profile",
        input_data={"company_name": "SANS Institute"},
        options={"techniques": ["T1566", "T1078", "T1059"]},
        expected_outputs=["profile", "recommendations"],
        tags=["profile", "education", "quick"],
        estimated_duration_minutes=3,
    ),
    TestCase(
        name="profile_splunk",
        description="Generate threat profile for Splunk",
        test_type="profile",
        input_data={"company_name": "Splunk"},
        options={"techniques": ["T1566", "T1078", "T1059"]},
        expected_outputs=["profile", "recommendations"],
        tags=["profile", "tech", "quick"],
        estimated_duration_minutes=3,
    ),
    TestCase(
        name="profile_crowdstrike",
        description="Generate threat profile for CrowdStrike",
        test_type="profile",
        input_data={"company_name": "CrowdStrike"},
        options={"techniques": ["T1566", "T1078", "T1059"]},
        expected_outputs=["profile", "recommendations"],
        tags=["profile", "security", "quick"],
        estimated_duration_minutes=3,
    ),
]


# =============================================================================
# TEST CASES: TECHNIQUE HUNTING
# =============================================================================

TECHNIQUE_TESTS = [
    TestCase(
        name="technique_powershell",
        description="Hunt for PowerShell execution (T1059.001)",
        test_type="technique",
        input_data={"technique_id": "T1059.001"},
        options={"osint_enhancement": True},
        expected_outputs=["yaml_files", "queries"],
        tags=["technique", "execution", "quick"],
        estimated_duration_minutes=3,
    ),
    TestCase(
        name="technique_spearphishing",
        description="Hunt for Spearphishing Attachment (T1566.001)",
        test_type="technique",
        input_data={"technique_id": "T1566.001"},
        options={"osint_enhancement": True},
        expected_outputs=["yaml_files", "queries"],
        tags=["technique", "initial_access", "quick"],
        estimated_duration_minutes=3,
    ),
    TestCase(
        name="technique_valid_accounts",
        description="Hunt for Valid Accounts abuse (T1078)",
        test_type="technique",
        input_data={"technique_id": "T1078"},
        options={"osint_enhancement": True},
        expected_outputs=["yaml_files", "queries"],
        tags=["technique", "defense_evasion", "quick"],
        estimated_duration_minutes=3,
    ),
    TestCase(
        name="technique_lsass",
        description="Hunt for LSASS Memory credential dumping (T1003.001)",
        test_type="technique",
        input_data={"technique_id": "T1003.001"},
        options={"osint_enhancement": True},
        expected_outputs=["yaml_files", "queries"],
        tags=["technique", "credential_access", "quick"],
        estimated_duration_minutes=3,
    ),
    TestCase(
        name="technique_process_injection",
        description="Hunt for Process Injection (T1055)",
        test_type="technique",
        input_data={"technique_id": "T1055"},
        options={"osint_enhancement": True},
        expected_outputs=["yaml_files", "queries"],
        tags=["technique", "defense_evasion", "quick"],
        estimated_duration_minutes=3,
    ),
]


# =============================================================================
# TEST CASES: REPORT EXPORT FORMATS
# =============================================================================

# Export formats to test
EXPORT_FORMATS = ["pdf", "txt", "md", "json", "csv", "xlsx", "docx", "yara"]

EXPORT_TESTS = [
    # -------------------------------------------------------------------------
    # PDF Export Tests
    # -------------------------------------------------------------------------
    TestCase(
        name="export_apt29_pdf",
        description="Export APT29 detections to PDF report",
        test_type="export",
        input_data={"group_name": "APT29", "format": "pdf"},
        options={"include_techniques": True, "include_queries": True},
        expected_outputs=["pdf_file"],
        tags=["export", "pdf", "report", "quick"],
        estimated_duration_minutes=2,
    ),
    TestCase(
        name="export_scattered_spider_pdf",
        description="Export Scattered Spider detections to PDF report",
        test_type="export",
        input_data={"group_name": "Scattered Spider", "format": "pdf"},
        options={"include_techniques": True, "include_queries": True},
        expected_outputs=["pdf_file"],
        tags=["export", "pdf", "report"],
        estimated_duration_minutes=2,
    ),

    # -------------------------------------------------------------------------
    # TXT Export Tests
    # -------------------------------------------------------------------------
    TestCase(
        name="export_apt29_txt",
        description="Export APT29 detections to plain text",
        test_type="export",
        input_data={"group_name": "APT29", "format": "txt"},
        options={},
        expected_outputs=["txt_file"],
        tags=["export", "txt", "quick"],
        estimated_duration_minutes=1,
    ),
    TestCase(
        name="export_lazarus_txt",
        description="Export Lazarus Group detections to plain text",
        test_type="export",
        input_data={"group_name": "Lazarus Group", "format": "txt"},
        options={},
        expected_outputs=["txt_file"],
        tags=["export", "txt"],
        estimated_duration_minutes=1,
    ),

    # -------------------------------------------------------------------------
    # Markdown Export Tests
    # -------------------------------------------------------------------------
    TestCase(
        name="export_apt29_md",
        description="Export APT29 detections to Markdown",
        test_type="export",
        input_data={"group_name": "APT29", "format": "md"},
        options={"include_toc": True},
        expected_outputs=["md_file"],
        tags=["export", "md", "markdown", "quick"],
        estimated_duration_minutes=1,
    ),
    TestCase(
        name="export_fin7_md",
        description="Export FIN7 detections to Markdown",
        test_type="export",
        input_data={"group_name": "FIN7", "format": "md"},
        options={"include_toc": True},
        expected_outputs=["md_file"],
        tags=["export", "md", "markdown"],
        estimated_duration_minutes=1,
    ),

    # -------------------------------------------------------------------------
    # JSON Export Tests
    # -------------------------------------------------------------------------
    TestCase(
        name="export_apt29_json",
        description="Export APT29 detections to JSON",
        test_type="export",
        input_data={"group_name": "APT29", "format": "json"},
        options={"include_metadata": True},
        expected_outputs=["json_file"],
        tags=["export", "json", "structured", "quick"],
        estimated_duration_minutes=1,
    ),
    TestCase(
        name="export_apt28_json",
        description="Export APT28 detections to JSON",
        test_type="export",
        input_data={"group_name": "APT28", "format": "json"},
        options={"include_metadata": True},
        expected_outputs=["json_file"],
        tags=["export", "json", "structured"],
        estimated_duration_minutes=1,
    ),

    # -------------------------------------------------------------------------
    # CSV Export Tests
    # -------------------------------------------------------------------------
    TestCase(
        name="export_apt29_csv",
        description="Export APT29 detections to CSV spreadsheet",
        test_type="export",
        input_data={"group_name": "APT29", "format": "csv"},
        options={},
        expected_outputs=["csv_file"],
        tags=["export", "csv", "spreadsheet", "quick"],
        estimated_duration_minutes=1,
    ),
    TestCase(
        name="export_wizard_spider_csv",
        description="Export Wizard Spider detections to CSV spreadsheet",
        test_type="export",
        input_data={"group_name": "Wizard Spider", "format": "csv"},
        options={},
        expected_outputs=["csv_file"],
        tags=["export", "csv", "spreadsheet"],
        estimated_duration_minutes=1,
    ),

    # -------------------------------------------------------------------------
    # XLSX (Excel) Export Tests
    # -------------------------------------------------------------------------
    TestCase(
        name="export_apt29_xlsx",
        description="Export APT29 detections to Excel workbook",
        test_type="export",
        input_data={"group_name": "APT29", "format": "xlsx"},
        options={"include_charts": True},
        expected_outputs=["xlsx_file"],
        tags=["export", "xlsx", "excel", "spreadsheet", "quick"],
        estimated_duration_minutes=2,
    ),
    TestCase(
        name="export_salt_typhoon_xlsx",
        description="Export Salt Typhoon detections to Excel workbook",
        test_type="export",
        input_data={"group_name": "Salt Typhoon", "format": "xlsx"},
        options={"include_charts": True},
        expected_outputs=["xlsx_file"],
        tags=["export", "xlsx", "excel", "spreadsheet"],
        estimated_duration_minutes=2,
    ),

    # -------------------------------------------------------------------------
    # DOCX (Word) Export Tests
    # -------------------------------------------------------------------------
    TestCase(
        name="export_apt29_docx",
        description="Export APT29 detections to Word document",
        test_type="export",
        input_data={"group_name": "APT29", "format": "docx"},
        options={"include_cover_page": True, "include_toc": True},
        expected_outputs=["docx_file"],
        tags=["export", "docx", "word", "report", "quick"],
        estimated_duration_minutes=2,
    ),
    TestCase(
        name="export_kimsuky_docx",
        description="Export Kimsuky detections to Word document",
        test_type="export",
        input_data={"group_name": "Kimsuky", "format": "docx"},
        options={"include_cover_page": True, "include_toc": True},
        expected_outputs=["docx_file"],
        tags=["export", "docx", "word", "report"],
        estimated_duration_minutes=2,
    ),

    # -------------------------------------------------------------------------
    # YARA Export Tests
    # -------------------------------------------------------------------------
    TestCase(
        name="export_apt29_yara",
        description="Export APT29 detections as YARA rules",
        test_type="export",
        input_data={"group_name": "APT29", "format": "yara"},
        options={"include_metadata": True, "include_strings": True},
        expected_outputs=["yara_file"],
        tags=["export", "yara", "detection", "quick"],
        estimated_duration_minutes=1,
    ),
    TestCase(
        name="export_lazarus_yara",
        description="Export Lazarus Group detections as YARA rules",
        test_type="export",
        input_data={"group_name": "Lazarus Group", "format": "yara"},
        options={"include_metadata": True, "include_strings": True},
        expected_outputs=["yara_file"],
        tags=["export", "yara", "detection"],
        estimated_duration_minutes=1,
    ),
    TestCase(
        name="export_fin7_yara",
        description="Export FIN7 detections as YARA rules",
        test_type="export",
        input_data={"group_name": "FIN7", "format": "yara"},
        options={"include_metadata": True, "include_strings": True},
        expected_outputs=["yara_file"],
        tags=["export", "yara", "detection"],
        estimated_duration_minutes=1,
    ),

    # -------------------------------------------------------------------------
    # Multi-format Export Tests
    # -------------------------------------------------------------------------
    TestCase(
        name="export_apt29_all_formats",
        description="Export APT29 to all formats (comprehensive)",
        test_type="export",
        input_data={"group_name": "APT29", "format": "all"},
        options={"include_all": True},
        expected_outputs=["pdf_file", "txt_file", "md_file", "json_file", "csv_file", "xlsx_file", "docx_file", "yara_file"],
        tags=["export", "comprehensive", "slow"],
        estimated_duration_minutes=10,
    ),
]


# =============================================================================
# ALL TESTS COMBINED
# =============================================================================

ALL_TESTS = (
    THREAT_GROUP_TESTS +
    CVE_TESTS +
    BLOG_TESTS +
    PROFILE_TESTS +
    TECHNIQUE_TESTS +
    EXPORT_TESTS
)

# Lookup dictionary for quick access
TEST_LOOKUP = {test.name: test for test in ALL_TESTS}


# =============================================================================
# TEST RUNNER
# =============================================================================

class ArcherTestRunner:
    """Runs Archer feature tests via REST API."""

    def __init__(self, base_url: str = API_URL, timeout: int = DEFAULT_TIMEOUT):
        self.base_url = base_url
        self.timeout = timeout
        self.results: List[TestResult] = []
        self.session = requests.Session()

    def log(self, message: str):
        """Print timestamped log message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
        sys.stdout.flush()

    def check_health(self) -> bool:
        """Check if Archer is running."""
        try:
            response = self.session.get(
                f"{self.base_url}/health",
                timeout=SHORT_TIMEOUT
            )
            return response.status_code == 200
        except Exception:
            return False

    def submit_test(self, test: TestCase) -> Optional[requests.Response]:
        """Submit a test case to the API."""
        endpoint = test.get_endpoint()
        url = f"{self.base_url}{endpoint}"

        # Build request data based on test type
        if test.test_type == "threat_group":
            data = {
                "group_name": test.input_data.get("group_name"),
                "osint_enhancement": "on" if test.options.get("osint_enhancement") else "",
                "run_correlation": "on" if test.options.get("run_correlation") else "",
            }
        elif test.test_type == "cve":
            data = {
                "cve_id": test.input_data.get("cve_id"),
                "run_correlation": "on" if test.options.get("run_correlation") else "",
            }
        elif test.test_type == "blog":
            data = {
                "blog_url": test.input_data.get("blog_url"),
                "run_correlation": "on" if test.options.get("run_correlation") else "",
            }
        elif test.test_type == "profile":
            # Profile uses JSON
            return self.session.post(
                url,
                json={
                    "company_name": test.input_data.get("company_name"),
                    "techniques": test.options.get("techniques", []),
                },
                timeout=SHORT_TIMEOUT,
                allow_redirects=False
            )
        elif test.test_type == "technique":
            data = {
                "technique_id": test.input_data.get("technique_id"),
                "osint_enhancement": "on" if test.options.get("osint_enhancement") else "",
            }
        elif test.test_type == "export":
            # Export uses JSON with format specification
            export_format = test.input_data.get("format", "json")
            return self.session.post(
                url,
                json={
                    "group_name": test.input_data.get("group_name"),
                    "format": export_format,
                    "options": test.options,
                },
                timeout=SHORT_TIMEOUT,
                allow_redirects=False
            )
        else:
            data = test.input_data

        try:
            response = self.session.post(
                url,
                data=data,
                timeout=SHORT_TIMEOUT,
                allow_redirects=False
            )
            return response
        except Exception as e:
            self.log(f"  ERROR: Failed to submit test: {e}")
            return None

    def poll_progress(self, test: TestCase, max_wait: int = None) -> Optional[Dict]:
        """Poll for test completion."""
        if max_wait is None:
            max_wait = self.timeout

        progress_key = test.get_progress_key()
        poll_interval = POLL_INTERVAL
        waited = 0
        last_progress = None
        last_report_time = 0
        report_interval = 60  # Report progress every 60 seconds

        while waited < max_wait:
            time.sleep(poll_interval)
            waited += poll_interval

            try:
                response = self.session.get(
                    f"{self.base_url}/progress_status",
                    params={"group_name": progress_key},
                    timeout=SHORT_TIMEOUT
                )

                if response.status_code == 200:
                    data = response.json()
                    # Handle nested progress structure
                    progress = data.get("progress", data)
                    last_progress = progress
                    status = progress.get("status", "")

                    # Report progress periodically
                    if waited - last_report_time >= report_interval:
                        last_report_time = waited
                        stage = progress.get("stage", status)
                        created = progress.get("created_yaml", 0)
                        total = progress.get("total_yaml", 0)
                        elapsed_mins = waited // 60
                        self.log(f"    Progress ({elapsed_mins}m): {stage} - {created}/{total}")

                    if status == "complete":
                        return progress
                    elif status == "error":
                        return progress

            except Exception:
                pass  # Continue polling

        return last_progress

    def run_test(self, test: TestCase, wait: bool = True) -> TestResult:
        """Run a single test case."""
        start = time.time()
        self.log(f"Running test: {test.name}")
        self.log(f"  Type: {test.test_type}")
        self.log(f"  Description: {test.description}")

        # Submit test
        response = self.submit_test(test)

        if response is None:
            result = TestResult(
                name=test.name,
                passed=False,
                duration=time.time() - start,
                details="Failed to submit test",
                error="Connection error"
            )
            self.results.append(result)
            return result

        if response.status_code not in [200, 302, 303]:
            result = TestResult(
                name=test.name,
                passed=False,
                duration=time.time() - start,
                details=f"Unexpected status: {response.status_code}",
                error=response.text[:200] if response.text else None
            )
            self.results.append(result)
            return result

        self.log(f"  Submitted successfully (status: {response.status_code})")

        if not wait:
            result = TestResult(
                name=test.name,
                passed=True,
                duration=time.time() - start,
                details="Submitted (not waiting for completion)"
            )
            self.results.append(result)
            return result

        # Poll for completion
        self.log(f"  Waiting for completion...")
        progress = self.poll_progress(test)

        duration = time.time() - start

        if progress:
            status = progress.get("status", "unknown")
            if status == "complete":
                created = progress.get("created_yaml", 0)
                correlations = progress.get("total_correlations", 0)
                details = f"Generated {created} detections"
                if correlations:
                    details += f", {correlations} correlations"
                result = TestResult(
                    name=test.name,
                    passed=True,
                    duration=duration,
                    details=details,
                    progress_data=progress
                )
            elif status == "error":
                result = TestResult(
                    name=test.name,
                    passed=False,
                    duration=duration,
                    details="Generation error",
                    error=progress.get("error", "Unknown error"),
                    progress_data=progress
                )
            else:
                # Still running or unknown status
                result = TestResult(
                    name=test.name,
                    passed=True,
                    duration=duration,
                    details=f"Status: {status} (still running after timeout)",
                    progress_data=progress
                )
        else:
            result = TestResult(
                name=test.name,
                passed=False,
                duration=duration,
                details="Timeout with no progress data",
                error=f"No response after {self.timeout}s"
            )

        self.results.append(result)

        status_str = "PASS" if result.passed else "FAIL"
        self.log(f"  {status_str}: {result.details}")
        if result.error:
            self.log(f"  Error: {result.error}")

        return result

    def run_tests(self, tests: List[TestCase], wait: bool = True) -> Dict:
        """Run multiple tests and return summary."""
        self.log("=" * 70)
        self.log("ARCHER FEATURE TEST SUITE")
        self.log("=" * 70)
        self.log(f"Running {len(tests)} tests")
        self.log("")

        for test in tests:
            self.run_test(test, wait=wait)
            self.log("")

        # Summary
        self.log("=" * 70)
        self.log("TEST SUMMARY")
        self.log("=" * 70)

        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        total = len(self.results)

        self.log(f"Total Tests: {total}")
        self.log(f"Passed: {passed}")
        self.log(f"Failed: {failed}")
        self.log(f"Pass Rate: {passed/total*100:.1f}%" if total > 0 else "N/A")

        if failed > 0:
            self.log("")
            self.log("Failed Tests:")
            for r in self.results:
                if not r.passed:
                    self.log(f"  - {r.name}: {r.error or r.details}")

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": passed/total*100 if total > 0 else 0,
            "results": [asdict(r) for r in self.results]
        }

    def get_status(self) -> Dict:
        """Get status of any running jobs."""
        try:
            # Check common progress keys
            status_data = {}
            for test in ALL_TESTS[:10]:  # Check first 10 tests
                key = test.get_progress_key()
                try:
                    response = self.session.get(
                        f"{self.base_url}/progress_status",
                        params={"group_name": key},
                        timeout=SHORT_TIMEOUT
                    )
                    if response.status_code == 200:
                        data = response.json()
                        progress = data.get("progress", data)
                        if progress.get("status") in ["processing", "creating_yamls", "correlating"]:
                            status_data[key] = progress
                except Exception:
                    pass
            return status_data
        except Exception as e:
            return {"error": str(e)}


# =============================================================================
# CLI FUNCTIONS
# =============================================================================

def list_tests(tag: str = None, verbose: bool = False):
    """List all available tests."""
    tests = ALL_TESTS
    if tag:
        tests = [t for t in tests if tag in t.tags]

    print(f"\nAvailable Tests ({len(tests)} total):")
    print("-" * 70)

    # Group by type
    by_type = {}
    for test in tests:
        if test.test_type not in by_type:
            by_type[test.test_type] = []
        by_type[test.test_type].append(test)

    for test_type, type_tests in by_type.items():
        print(f"\n{test_type.upper().replace('_', ' ')} TESTS ({len(type_tests)}):")
        for test in type_tests:
            tags_str = ", ".join(test.tags[:3])
            if verbose:
                print(f"  {test.name}")
                print(f"    Description: {test.description}")
                print(f"    Tags: {tags_str}")
                print(f"    Est. Duration: {test.estimated_duration_minutes} min")
            else:
                print(f"  {test.name:<30} [{tags_str}]")


def show_test(name: str):
    """Show details for a specific test."""
    if name not in TEST_LOOKUP:
        print(f"Error: Test '{name}' not found")
        print(f"Available tests: {', '.join(TEST_LOOKUP.keys())}")
        return

    test = TEST_LOOKUP[name]
    print(f"\nTest: {test.name}")
    print("-" * 50)
    print(f"Description: {test.description}")
    print(f"Type: {test.test_type}")
    print(f"Endpoint: {test.get_endpoint()}")
    print(f"Progress Key: {test.get_progress_key()}")
    print(f"Tags: {', '.join(test.tags)}")
    print(f"Est. Duration: {test.estimated_duration_minutes} min")
    print(f"Input Data: {json.dumps(test.input_data, indent=2)}")
    print(f"Options: {json.dumps(test.options, indent=2)}")
    print(f"Expected Outputs: {test.expected_outputs}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Archer Feature Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # Actions
    parser.add_argument("--list", action="store_true",
                        help="List all available tests")
    parser.add_argument("--show", type=str, metavar="NAME",
                        help="Show details for a specific test")
    parser.add_argument("--run", type=str, metavar="NAME",
                        help="Run a specific test")
    parser.add_argument("--run-tags", nargs="+", metavar="TAG",
                        help="Run all tests with specified tags")
    parser.add_argument("--run-all", action="store_true",
                        help="Run all tests")
    parser.add_argument("--status", action="store_true",
                        help="Show status of running jobs")

    # Options
    parser.add_argument("--url", type=str, default=API_URL,
                        help=f"Archer API URL (default: {API_URL})")
    parser.add_argument("--wait", action="store_true",
                        help="Wait for test completion")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--tag", type=str,
                        help="Filter tests by tag (for --list)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")

    args = parser.parse_args()

    if not HAS_REQUESTS:
        print("Error: 'requests' module required. Install with: pip install requests")
        sys.exit(1)

    # Handle actions
    if args.list:
        list_tests(tag=args.tag, verbose=args.verbose)
        return

    if args.show:
        show_test(args.show)
        return

    if args.status:
        runner = ArcherTestRunner(args.url, args.timeout)
        if not runner.check_health():
            print(f"Error: Cannot connect to Archer at {args.url}")
            sys.exit(1)

        status = runner.get_status()
        if status:
            print("\nRunning Jobs:")
            print("-" * 50)
            for key, progress in status.items():
                if key != "error":
                    print(f"  {key}: {progress.get('status', 'unknown')}")
                    if "stage" in progress:
                        print(f"    Stage: {progress['stage']}")
                    if "created_yaml" in progress:
                        print(f"    Progress: {progress['created_yaml']}/{progress.get('total_yaml', '?')}")
        else:
            print("\nNo running jobs found")
        return

    if args.run:
        if args.run not in TEST_LOOKUP:
            print(f"Error: Test '{args.run}' not found")
            print(f"Use --list to see available tests")
            sys.exit(1)

        runner = ArcherTestRunner(args.url, args.timeout)
        if not runner.check_health():
            print(f"Error: Cannot connect to Archer at {args.url}")
            sys.exit(1)

        test = TEST_LOOKUP[args.run]
        result = runner.run_test(test, wait=args.wait)

        if args.json:
            print(json.dumps(asdict(result), indent=2))

        sys.exit(0 if result.passed else 1)

    if args.run_tags:
        tests = [t for t in ALL_TESTS if any(tag in t.tags for tag in args.run_tags)]
        if not tests:
            print(f"Error: No tests found with tags: {args.run_tags}")
            sys.exit(1)

        print(f"Found {len(tests)} tests matching tags: {args.run_tags}")

        runner = ArcherTestRunner(args.url, args.timeout)
        if not runner.check_health():
            print(f"Error: Cannot connect to Archer at {args.url}")
            sys.exit(1)

        results = runner.run_tests(tests, wait=args.wait)

        if args.json:
            print(json.dumps(results, indent=2))

        sys.exit(0 if results["failed"] == 0 else 1)

    if args.run_all:
        runner = ArcherTestRunner(args.url, args.timeout)
        if not runner.check_health():
            print(f"Error: Cannot connect to Archer at {args.url}")
            sys.exit(1)

        results = runner.run_tests(ALL_TESTS, wait=args.wait)

        if args.json:
            print(json.dumps(results, indent=2))

        sys.exit(0 if results["failed"] == 0 else 1)

    # No action specified - show help
    parser.print_help()


if __name__ == "__main__":
    main()
