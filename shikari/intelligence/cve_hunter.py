"""
CVE Hunting Module

Researches CVEs, finds PoCs, analyzes exploit techniques, and generates detection queries.
"""

import os
import re
import json
import requests
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

from shikari.intelligence.cve_label import exploit_name


class CVEHunter:
    """
    CVE research and hunting query generation.

    Workflow:
    1. Research CVE (NVD API, MITRE, exploit-db)
    2. Find Proof-of-Concept exploits (GitHub, exploit-db, Packet Storm)
    3. Analyze exploit techniques and IOCs
    4. Map to MITRE ATT&CK techniques
    5. Generate detection queries (Splunk, MDE)
    """

    def __init__(self):
        self.nvd_api_key = os.getenv("NVD_API_KEY")  # Optional: increases rate limit
        self.github_token = os.getenv("GITHUB_TOKEN")  # Optional: for PoC search
        from ..config import CVE_CACHE_DIR
        self.cache_dir = CVE_CACHE_DIR
        os.makedirs(self.cache_dir, exist_ok=True)

    @staticmethod
    def cache_location() -> str:
        """Where researched CVEs are cached, one JSON file each."""
        from ..config import CVE_CACHE_DIR

        return CVE_CACHE_DIR

    # The steps research_cve reports to on_step, for the progress page's Research card
    STEPS = ("Reading the NVD record", "Searching for proofs of concept", "Mapping to ATT&CK",
             "Reading the advisories and write-ups", "Reading the exploit requests", "Drafting queries")

    def research_cve(self, cve_id: str, on_step=None) -> Dict[str, Any]:
        """
        Research a CVE from multiple sources.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")
            on_step: called with (index, label) as each of STEPS starts; a cached CVE skips them

        Returns:
            Dictionary containing CVE details, PoCs, and techniques
        """
        cve_id = self._normalize_cve_id(cve_id)

        step = on_step or (lambda i, label: None)

        # Check cache first
        cached = self._get_cached_research(cve_id)
        if cached:
            step(len(self.STEPS) - 1, "Cached research")
            # Re-derived each time (no network): a cache written by an older extractor
            # still carries its guessed indicators
            cached["iocs"] = self._extract_iocs(cached)
            # Cached before references were read, or under older extraction rules
            if (cached.get("reference_iocs") or {}).get("version") != self.REFERENCE_IOCS_VERSION:
                cached["reference_iocs"] = self._reference_iocs(cached.get("nvd_data") or {})
                self._cache_research(cve_id, cached)
            if "exploit" not in cached:  # cached before exploit requests were read
                cached["exploit"] = self._exploit(cached.get("nvd_data") or {}, cached.get("pocs") or [])
                self._cache_research(cve_id, cached)
            # Re-derived too (shikari.intelligence.cve_label): the PoCs and references are cached
            cached["exploit_name"] = exploit_name(cached.get("nvd_data") or {}, cached.get("pocs") or [])
            return cached

        result = {
            "cve_id": cve_id,
            "timestamp": datetime.now().isoformat(),
            "nvd_data": {},
            "pocs": [],
            "techniques": [],
            "iocs": {
                "cmd": [],
                "file": [],
                "reg": [],
                "network": [],
                "hash": [],
                "ip": [],
                "domain": []
            },
            "detection_queries": {
                "splunk": [],
                "mde": []
            }
        }

        # 1. Get CVE details from NVD
        step(0, self.STEPS[0])
        result["nvd_data"] = self._fetch_nvd_data(cve_id)

        # 2. Search for existing PoCs
        step(1, self.STEPS[1])
        result["pocs"] = self._find_pocs(cve_id)

        # No public PoC: carry on from the NVD record, the CWE and the advisories. An AI-written
        # exploit here would run unasked for every CVE pre-researched in the background
        # 4. Analyze techniques and extract IOCs
        step(2, self.STEPS[2])
        result["techniques"] = self._map_to_attack(result)
        result["iocs"] = self._extract_iocs(result)
        step(3, self.STEPS[3])
        result["reference_iocs"] = self._reference_iocs(result["nvd_data"])
        step(4, self.STEPS[4])
        result["exploit"] = self._exploit(result["nvd_data"], result["pocs"])
        result["exploit_name"] = exploit_name(result["nvd_data"], result["pocs"])  # PHP2Shell, or None

        # 5. Generate detection queries
        step(5, self.STEPS[5])
        result["detection_queries"] = self._generate_detection_queries(result)

        # Cache results
        self._cache_research(cve_id, result)

        return result

    def _normalize_cve_id(self, cve_id: str) -> str:
        """Normalize CVE ID format."""
        cve_id = cve_id.upper().strip()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        # Validate format
        if not re.match(r"CVE-\d{4}-\d+", cve_id):
            raise ValueError(f"Invalid CVE ID format: {cve_id}")

        return cve_id

    def _fetch_nvd_data(self, cve_id: str) -> Dict[str, Any]:
        """
        Fetch CVE data from NVD API.

        API: https://nvd.nist.gov/developers/vulnerabilities
        """
        # A CVE of the last 30 days is in the recent-CVE cache (shikari.intelligence.cve_feed)
        from shikari.intelligence.cve_feed import record

        cached = record(cve_id)
        if cached:
            return {k: v for k, v in cached.items() if k != "kev"}

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cveId": cve_id}
        headers = {}

        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        try:
            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            if not data.get("vulnerabilities"):
                return {"error": "CVE not found in NVD"}

            return self.parse_nvd(data["vulnerabilities"][0]["cve"])

        except Exception as e:
            print(f"Error fetching NVD data for {cve_id}: {e}")
            return {"error": str(e)}

    @classmethod
    def parse_nvd(cls, vuln: Dict) -> Dict[str, Any]:
        """The fields Shikari keeps from an NVD API 2.0 cve object."""
        return {
            "cve_id": vuln.get("id"),
            "description": vuln.get("descriptions", [{}])[0].get("value", ""),
            "published": vuln.get("published"),
            "modified": vuln.get("lastModified"),
            "cvss_v3": cls._extract_cvss(vuln, "cvssMetricV31"),
            "cvss_v2": cls._extract_cvss(vuln, "cvssMetricV2"),
            "cwe": cls._extract_cwe(vuln),
            "references": [ref.get("url") for ref in vuln.get("references", [])],
            "vendor": cls._extract_vendor(vuln),
            "product": cls._extract_product(vuln),
            # Every vulnerable CPE (not the platforms they run on): Profile → Technology stack
            "cpes": sorted({m.get("criteria", "") for c in vuln.get("configurations", [])
                            for node in c.get("nodes", []) for m in node.get("cpeMatch", [])
                            if m.get("vulnerable") and m.get("criteria")})[:200],
        }

    @staticmethod
    def _extract_cvss(vuln: Dict, metric_type: str) -> Optional[Dict]:
        """Extract CVSS metrics."""
        metrics = vuln.get("metrics", {}).get(metric_type, [])
        if not metrics:
            return None

        metric = metrics[0].get("cvssData", {})
        return {
            "score": metric.get("baseScore"),
            "severity": metric.get("baseSeverity"),
            "vector": metric.get("vectorString")
        }

    @staticmethod
    def _extract_cwe(vuln: Dict) -> List[str]:
        """Extract CWE IDs."""
        weaknesses = vuln.get("weaknesses", [])
        cwes = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwes.append(desc["value"])
        return cwes

    @staticmethod
    def _extract_vendor(vuln: Dict) -> Optional[str]:
        """Extract vendor name from CPE."""
        configs = vuln.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    # CPE format: cpe:2.3:a:vendor:product:version...
                    parts = cpe.split(":")
                    if len(parts) > 3:
                        return parts[3]
        return None

    @staticmethod
    def _extract_product(vuln: Dict) -> Optional[str]:
        """Extract product name from CPE."""
        configs = vuln.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) > 4:
                        return parts[4]
        return None

    def _find_pocs(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Search for PoC exploits from multiple sources.

        Sources:
        1. GitHub (public repos with PoC code)
        2. Exploit-DB
        3. Packet Storm
        4. PoC-in-GitHub curated list
        """
        pocs = []

        # 1. Search GitHub
        github_pocs = self._search_github_pocs(cve_id)
        pocs.extend(github_pocs)

        # 2. Search Exploit-DB
        exploitdb_pocs = self._search_exploitdb(cve_id)
        pocs.extend(exploitdb_pocs)

        # 3. Check PoC-in-GitHub curated list
        curated_pocs = self._search_poc_in_github(cve_id)
        pocs.extend(curated_pocs)

        return pocs

    def _search_github_pocs(self, cve_id: str) -> List[Dict]:
        """Search GitHub for PoC repositories."""
        pocs = []

        # GitHub Code Search API
        search_query = f"{cve_id} PoC OR exploit"
        url = "https://api.github.com/search/repositories"
        params = {
            "q": search_query,
            "sort": "stars",
            "order": "desc",
            "per_page": 5
        }
        headers = {}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        try:
            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            for repo in data.get("items", []):
                pocs.append({
                    "type": "github",
                    "source": repo.get("full_name"),
                    "url": repo.get("html_url"),
                    # GitHub returns "description": null for repos without one
                    "description": repo.get("description") or "",
                    "stars": repo.get("stargazers_count", 0),
                    "language": repo.get("language")
                })

        except Exception as e:
            print(f"Error searching GitHub for {cve_id}: {e}")

        return pocs

    def _search_exploitdb(self, cve_id: str) -> List[Dict]:
        """Search Exploit-DB."""
        # Exploit-DB search (web scraping or API if available)
        # For now, return placeholder - would need proper implementation
        return []

    def _search_poc_in_github(self, cve_id: str) -> List[Dict]:
        """Check PoC-in-GitHub curated database."""
        # https://github.com/nomi-sec/PoC-in-GitHub
        # Would need to clone/access this repo
        return []

    def _map_to_attack(self, research_data: Dict) -> List[str]:
        """
        Map CVE exploitation to MITRE ATT&CK techniques.

        Analyzes:
        - CVE description
        - PoC code/steps
        - CWE mapping
        - Exploit type
        """
        techniques = []

        # CWE to ATT&CK mapping (common patterns)
        cwe_attack_map = {
            "CWE-79": ["T1189"],   # XSS → Drive-by Compromise
            "CWE-89": ["T1190"],   # SQLi → Exploit Public-Facing Application
            "CWE-78": ["T1059"],   # Command Injection → Command and Scripting Interpreter
            "CWE-94": ["T1059"],   # Code Injection → Command and Scripting Interpreter
            "CWE-22": ["T1083"],   # Path Traversal → File and Directory Discovery
            "CWE-434": ["T1105"],  # File Upload → Ingress Tool Transfer
            "CWE-502": ["T1059"],  # Deserialization → Command Execution
        }

        cwes = research_data.get("nvd_data", {}).get("cwe", [])
        for cwe in cwes:
            if cwe in cwe_attack_map:
                techniques.extend(cwe_attack_map[cwe])

        # Always include Initial Access for exploits
        if "T1190" not in techniques:  # Exploit Public-Facing Application
            techniques.append("T1190")

        return list(set(techniques))  # Deduplicate

    def _extract_iocs(self, research_data: Dict) -> Dict[str, List[str]]:
        """Extract IOCs from CVE data and PoCs."""
        iocs = {
            "cmd": [],
            "file": [],
            "reg": [],
            "network": [],
            "hash": [],
            "ip": [],
            "domain": []
        }

        # Extract from NVD description and references
        nvd_data = research_data.get("nvd_data", {})
        description = (nvd_data.get("description") or "").lower()
        cve_id = research_data.get("cve_id", "")

        # Extract CVE-specific patterns from description
        iocs = self._extract_cve_specific_patterns(cve_id, description, nvd_data, iocs)

        # Extract from PoC descriptions/URLs
        for poc in research_data.get("pocs", []):
            poc_desc = ((poc.get("description") or "") + " " + (poc.get("source") or "")).lower()
            poc_url = poc.get("url") or ""

            # Extract patterns from PoC metadata
            iocs = self._extract_from_text(poc_desc, iocs)
            iocs = self._extract_from_text(poc_url, iocs)

        # Deduplicate
        for key in iocs:
            iocs[key] = list(set(iocs[key]))

        return iocs

    def _extract_cve_specific_patterns(self, cve_id: str, description: str, nvd_data: Dict, iocs: Dict) -> Dict:
        """Extract CVE-specific patterns like vulnerable file names, commands, protocols."""

        # Common exploit patterns
        exploit_patterns = {
            "cmd": [
                r'\$\{[^}]+\}',  # Template injection patterns (e.g., ${jndi:ldap://...})
                r'jndi:[^"\s]+',  # JNDI lookup strings
                r'ldap://[^\s"\']+',  # LDAP URLs
                r'rmi://[^\s"\']+',  # RMI URLs
                r'dns://[^\s"\']+',  # DNS URLs
                r'http://[^\s"\']+\.class',  # Remote class loading
            ],
            "file": [
                r'[\w\-]+\.jar',  # JAR files
                r'[\w\-]+\.war',  # WAR files
                r'[\w\-]+\.class',  # Class files
                r'[\w\-]+\.dll',  # DLL files
                r'[\w\-]+\.so',  # Shared objects
                r'[\w\-]+\.exe',  # Executables
                r'/etc/passwd',  # Common paths
                r'/etc/shadow',
                r'C:\\\\Windows\\\\[^\s"\']+',  # Windows paths
            ],
            "network": [
                r'(?:ldap|rmi|dns|jndi)://[^\s"\']+',  # Protocol URLs
            ]
        }

        # Extract patterns from description
        # vendor/product are None when NVD has no CPE configuration yet (common for new CVEs)
        full_text = " ".join([description, nvd_data.get("product") or "", nvd_data.get("vendor") or ""])

        for ioc_type, patterns in exploit_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, full_text, re.IGNORECASE)
                iocs[ioc_type].extend(matches)

        # A product name is a file indicator only when it is a file name. Guessed variants
        # ("pan-os-core.jar", "libpan-os.so" for a firewall OS) matched nothing real.
        product = nvd_data.get("product") or ""
        if any(product.lower().endswith(ext) for ext in ['.jar', '.war', '.dll', '.so', '.exe']):
            iocs["file"].append(product)

        # Extract version-specific patterns for Log4j (CVE-2021-44228)
        if "log4j" in description or "log4j" in cve_id.lower():
            iocs["cmd"].extend([
                "${jndi:ldap://",
                "${jndi:rmi://",
                "${jndi:dns://",
                "${jndi:nis://",
                "${jndi:nds://",
                "${jndi:corba://",
                "${jndi:iiop://",
                "jndi:ldap",
                "jndi:rmi",
            ])
            iocs["file"].extend([
                "log4j-core.jar",
                "log4j-api.jar",
                "log4j2.xml",
                "log4j.properties",
                "JndiLookup.class",
                "JndiManager.class"
            ])
            iocs["network"].extend([
                "ldap://",
                "rmi://",
                "ldaps://",
            ])

        return iocs

    # Catalogues, trackers and code hosts: no indicators in the page itself
    _NO_INDICATOR_HOSTS = ("nvd.nist.gov", "cve.org", "cve.mitre.org", "cisa.gov/known-exploited",
                           "github.com", "twitter.com", "x.com", "exploit-db.com", "packetstormsecurity")
    MAX_REFERENCE_PAGES = 6
    REFERENCE_IOCS_VERSION = 2  # 2: a domain only seen in addresses isn't one (oss-security Message-IDs)

    def _reference_iocs(self, nvd_data: Dict) -> Dict[str, Any]:
        """
        Atomic indicators (IPs, domains, hashes) from the CVE's reference pages.

        The advisories and research write-ups NVD links to (Volexity, Unit 42 and the like)
        carry the exploitation indicators. For a network appliance they are the only thing
        an endpoint or SecOps rule can hunt for: the exploit runs where no EDR does.
        File names are left out: write-ups cite web paths like /css/bootstrap.min.css.
        """
        from shikari.parsers.blog_analyzer import analyze_blog_post

        from shikari.build.ioc_flow import merge_mentions

        merged: Dict[str, List[str]] = {"ip": [], "domain": [], "hash": []}
        sources = []
        mentions: Dict[str, List[str]] = {}
        read = 0
        for url in dict.fromkeys(nvd_data.get("references") or []):
            if read >= self.MAX_REFERENCE_PAGES:
                break
            if not url or any(h in url.lower() for h in self._NO_INDICATOR_HOSTS):
                continue
            read += 1
            try:
                page = analyze_blog_post(url)
            except Exception as e:
                print(f"Could not read CVE reference {url}: {e}")
                continue
            if not page.get("success"):
                continue
            found = False
            for kind, values in merged.items():
                for v in (page.get("iocs") or {}).get(kind) or []:
                    if v not in values:
                        values.append(v)
                        found = True
            if found:
                sources.append(url)
                mentions = merge_mentions(mentions, page.get("ioc_mentions"))
        return {"iocs": merged, "sources": sources, "mentions": mentions, "version": self.REFERENCE_IOCS_VERSION}

    MAX_POC_READMES = 5

    def _exploit(self, nvd_data: Dict, pocs: List[Dict]) -> Dict[str, Any]:
        """
        The exploit request (from PoC READMEs) and the shell run after it (from the
        write-ups' code blocks): see shikari.build.exploit_detection.
        """
        from bs4 import BeautifulSoup

        from shikari.build.exploit_detection import exploit_indicators
        from shikari.parsers.blog_analyzer import _fetch_public_url

        headers = {"Accept": "application/vnd.github.raw"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        poc_texts, sources = [], []
        repos = [p for p in pocs if p.get("type") == "github" and p.get("source")]
        for poc in sorted(repos, key=lambda p: -(p.get("stars") or 0))[: self.MAX_POC_READMES]:
            try:
                r = requests.get(f"https://api.github.com/repos/{poc['source']}/readme", headers=headers, timeout=10)
                if r.ok:
                    poc_texts.append(r.text)
                    sources.append(poc.get("url") or poc["source"])
            except Exception as e:
                print(f"Could not read PoC README {poc['source']}: {e}")
        code, read = [], 0
        for url in dict.fromkeys(nvd_data.get("references") or []):
            if read >= self.MAX_REFERENCE_PAGES:
                break
            if not url or any(h in url.lower() for h in self._NO_INDICATOR_HOSTS):
                continue
            read += 1
            try:
                soup = BeautifulSoup(_fetch_public_url(url, timeout=20).text, "html.parser")
            except Exception:
                continue
            # <pre>, or a <code> long enough to be a command rather than a name in prose
            blocks = [b.get_text("\n") for b in soup.find_all(["pre", "code"])
                      if b.name == "pre" or len(b.get_text()) > 40]
            # Write-ups also show requests in their code blocks
            poc_texts.extend(blocks)
            code.extend(blocks)
        found = exploit_indicators(poc_texts, code)
        return {"indicators": found, "sources": sources if found.get("paths") else []}

    def _extract_from_text(self, text: str, iocs: Dict) -> Dict:
        """Extract IOCs from arbitrary text."""
        if not text:
            return iocs

        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        iocs["ip"].extend(ips)

        # Domains
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        domains = re.findall(domain_pattern, text, re.IGNORECASE)
        iocs["domain"].extend([d for d in domains if d not in ['github.com', 'exploit-db.com', 'packetstormsecurity.com']])

        # File paths
        file_patterns = [
            r'[/\\][\w/\\.-]+\.(exe|dll|jar|war|class|sh|bat|ps1|so)',
            r'C:\\[\w\\.-]+',
            r'/(?:usr|etc|var|tmp|home)/[\w/.-]+'
        ]
        for pattern in file_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            iocs["file"].extend(matches)

        return iocs

    def _generate_detection_queries(self, research_data: Dict) -> Dict[str, List[Dict]]:
        """
        Generate detection queries for Splunk and MDE.

        Uses the same query generation engine as threat groups,
        but focuses on CVE-specific IOCs and techniques.
        """
        from shikari.build import queries_enhanced

        queries = {
            "splunk": [],
            "mde": []
        }

        # Generate queries for each technique
        techniques = research_data.get("techniques", [])
        iocs = research_data.get("iocs", {})
        cve_id = research_data.get("cve_id")

        for technique in techniques:
            # Generate Splunk query
            splunk_query = self._generate_splunk_query(technique, iocs, cve_id)
            if splunk_query:
                queries["splunk"].append(splunk_query)

            # Generate MDE query
            mde_query = self._generate_mde_query(technique, iocs, cve_id)
            if mde_query:
                queries["mde"].append(mde_query)

        return queries

    def _generate_splunk_query(self, technique: str, iocs: Dict, cve_id: str) -> Optional[Dict]:
        """Generate Splunk detection query."""
        # Use existing query generation with CVE-specific IOCs
        # This would integrate with shikari/build/queries_enhanced.py
        return None  # Placeholder

    def _generate_mde_query(self, technique: str, iocs: Dict, cve_id: str) -> Optional[Dict]:
        """Generate MDE detection query."""
        # Use existing query generation with CVE-specific IOCs
        return None  # Placeholder

    def _get_cached_research(self, cve_id: str) -> Optional[Dict]:
        """Retrieve cached CVE research."""
        cache_file = os.path.join(self.cache_dir, f"{cve_id}.json")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return None

    def _cache_research(self, cve_id: str, data: Dict):
        """Cache CVE research results."""
        cache_file = os.path.join(self.cache_dir, f"{cve_id}.json")
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error caching CVE research: {e}")


def research_and_hunt(cve_id: str, on_step=None) -> Dict[str, Any]:
    """
    Main entry point for CVE hunting.

    Args:
        cve_id: CVE identifier
        on_step: called with (index, label) as each research step starts (CVEHunter.STEPS)

    Returns:
        Complete research and detection package
    """
    hunter = CVEHunter()
    return hunter.research_cve(cve_id, on_step=on_step)
