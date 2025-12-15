"""
CVE Enrichment Pipeline

Enriches CVE data with technical analysis from blog posts, security research,
and exploit analyses to generate high-fidelity detections for ITW exploits and POCs.
"""

import json
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime
import requests

from ..config import CVE_DATA_DIR, BLOG_POSTS_DIR, THREAT_REPORTS_DIR


class CVEEnrichmentPipeline:
    """
    Enriches CVE data with technical context and generates detection-ready datasets.

    Workflow:
    1. Fetch CVE data from NVD
    2. Search for related blog posts, research, and analyses
    3. Extract technical indicators (commands, files, registry keys, network activity)
    4. Map to MITRE ATT&CK techniques
    5. Generate detection training examples
    """

    def __init__(self):
        self.cve_cache = CVE_DATA_DIR / "cache"
        self.enriched_dir = CVE_DATA_DIR / "enriched"
        self.cve_cache.mkdir(parents=True, exist_ok=True)
        self.enriched_dir.mkdir(parents=True, exist_ok=True)

    def enrich_cve(
        self,
        cve_id: str,
        include_exploits: bool = True,
        include_blog_posts: bool = True,
        include_threat_reports: bool = True,
    ) -> Dict:
        """
        Enrich a CVE with technical analysis and detection context.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")
            include_exploits: Include exploit POCs and ITW samples
            include_blog_posts: Include security research blog posts
            include_threat_reports: Include vendor threat reports

        Returns:
            Enriched CVE dictionary with technical analysis
        """
        print(f"Enriching {cve_id}...")

        # Step 1: Fetch base CVE data
        cve_data = self._fetch_cve_data(cve_id)

        # Step 2: Search for related content
        related_content = self._search_related_content(
            cve_id,
            include_exploits=include_exploits,
            include_blog_posts=include_blog_posts,
            include_threat_reports=include_threat_reports,
        )

        # Step 3: Extract technical indicators
        indicators = self._extract_indicators(cve_data, related_content)

        # Step 4: Map to ATT&CK techniques
        attack_techniques = self._map_to_attack(cve_data, indicators)

        # Step 5: Generate detection context
        detection_context = self._build_detection_context(
            cve_data, related_content, indicators, attack_techniques
        )

        # Step 6: Build enriched CVE package
        enriched_cve = {
            "cve_id": cve_id,
            "cve_data": cve_data,
            "related_content": related_content,
            "indicators": indicators,
            "attack_techniques": attack_techniques,
            "detection_context": detection_context,
            "enrichment_timestamp": datetime.utcnow().isoformat(),
        }

        # Save enriched CVE
        output_file = self.enriched_dir / f"{cve_id}.json"
        with open(output_file, "w") as f:
            json.dump(enriched_cve, f, indent=2)

        print(f"✓ Enriched {cve_id} → {output_file}")
        return enriched_cve

    def _fetch_cve_data(self, cve_id: str) -> Dict:
        """Fetch CVE data from NVD or cache"""
        cache_file = self.cve_cache / f"{cve_id}.json"

        # Check cache first
        if cache_file.exists():
            with open(cache_file, "r") as f:
                return json.load(f)

        # Fetch from NVD API
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=30)

        if response.status_code != 200:
            raise Exception(f"Failed to fetch {cve_id}: {response.status_code}")

        data = response.json()

        if not data.get("vulnerabilities"):
            raise Exception(f"CVE {cve_id} not found in NVD")

        cve_item = data["vulnerabilities"][0]["cve"]

        # Parse CVE data
        cve_data = {
            "id": cve_id,
            "description": cve_item.get("descriptions", [{}])[0].get("value", ""),
            "cvss_score": self._extract_cvss_score(cve_item),
            "published_date": cve_item.get("published", ""),
            "modified_date": cve_item.get("lastModified", ""),
            "references": [ref.get("url") for ref in cve_item.get("references", [])],
            "cpe": self._extract_cpe(cve_item),
            "weakness": self._extract_cwe(cve_item),
        }

        # Cache it
        with open(cache_file, "w") as f:
            json.dump(cve_data, f, indent=2)

        return cve_data

    def _search_related_content(
        self,
        cve_id: str,
        include_exploits: bool = True,
        include_blog_posts: bool = True,
        include_threat_reports: bool = True,
    ) -> Dict[str, List[Dict]]:
        """
        Search for related technical content about the CVE.

        Sources:
        - ExploitDB for POCs
        - Security blogs (recorded future, mandiant, crowdstrike, etc.)
        - GitHub for exploit code
        - Threat reports mentioning the CVE
        """
        related_content = {
            "exploits": [],
            "blog_posts": [],
            "threat_reports": [],
            "github_repos": [],
        }

        # Search ExploitDB
        if include_exploits:
            related_content["exploits"] = self._search_exploitdb(cve_id)
            related_content["github_repos"] = self._search_github_exploits(cve_id)

        # Search security blogs
        if include_blog_posts:
            related_content["blog_posts"] = self._search_security_blogs(cve_id)

        # Search threat reports
        if include_threat_reports:
            related_content["threat_reports"] = self._search_threat_reports(cve_id)

        return related_content

    def _search_exploitdb(self, cve_id: str) -> List[Dict]:
        """Search ExploitDB for POCs"""
        # ExploitDB CSV: https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
        # For now, return placeholder - implement actual search
        return []

    def _search_github_exploits(self, cve_id: str) -> List[Dict]:
        """Search GitHub for exploit POCs"""
        # GitHub API search for CVE
        # Example: https://api.github.com/search/repositories?q=CVE-2024-1234
        return []

    def _search_security_blogs(self, cve_id: str) -> List[Dict]:
        """
        Search security blogs for technical analysis.

        Prioritize:
        - Google Project Zero
        - MSRC (Microsoft Security Response Center)
        - Recorded Future
        - Mandiant
        - CrowdStrike
        - Rapid7
        - Tenable
        - Qualys
        """
        blog_posts = []

        # Search local blog post cache
        for blog_file in BLOG_POSTS_DIR.glob("*.json"):
            with open(blog_file, "r") as f:
                blog_data = json.load(f)
                if cve_id in blog_data.get("content", ""):
                    blog_posts.append(blog_data)

        return blog_posts

    def _search_threat_reports(self, cve_id: str) -> List[Dict]:
        """Search threat reports mentioning the CVE"""
        reports = []

        # Search local threat reports
        for report_file in THREAT_REPORTS_DIR.glob("*.json"):
            with open(report_file, "r") as f:
                report_data = json.load(f)
                if cve_id in report_data.get("content", ""):
                    reports.append(report_data)

        return reports

    def _extract_indicators(
        self,
        cve_data: Dict,
        related_content: Dict,
    ) -> Dict[str, List[str]]:
        """
        Extract technical indicators from CVE data and related content.

        Indicators:
        - Commands (cmd): Exploit commands, PowerShell, bash
        - Files (file): Created/modified files, DLLs, executables
        - Registry keys (reg): Windows registry modifications
        - Network (net): URLs, IPs, domains, ports, protocols
        - Processes (proc): Process names, services
        - Hashes (hash): File hashes from samples
        """
        indicators = {
            "cmd": set(),
            "file": set(),
            "reg": set(),
            "net": set(),
            "proc": set(),
            "hash": set(),
        }

        # Extract from CVE description
        self._extract_from_text(cve_data.get("description", ""), indicators)

        # Extract from exploits
        for exploit in related_content.get("exploits", []):
            self._extract_from_text(exploit.get("code", ""), indicators)
            self._extract_from_text(exploit.get("description", ""), indicators)

        # Extract from blog posts
        for blog in related_content.get("blog_posts", []):
            self._extract_from_text(blog.get("content", ""), indicators)

        # Extract from threat reports
        for report in related_content.get("threat_reports", []):
            self._extract_from_text(report.get("content", ""), indicators)

        # Convert sets to sorted lists
        return {k: sorted(list(v)) for k, v in indicators.items()}

    def _extract_from_text(self, text: str, indicators: Dict):
        """Extract indicators from text using regex patterns"""

        # Command patterns
        cmd_patterns = [
            r'powershell[.\s]+(?:-[a-z]+\s+)?["\']?([^"\';\n]+)',  # PowerShell
            r'cmd[.\s]+/[a-z]\s+["\']?([^"\';\n]+)',  # cmd.exe
            r'bash\s+-c\s+["\']([^"\']+)',  # bash
            r'curl\s+[^\s]+',  # curl commands
            r'wget\s+[^\s]+',  # wget commands
        ]

        for pattern in cmd_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            indicators["cmd"].update(m.strip() for m in matches if m.strip())

        # File patterns
        file_patterns = [
            r'(?:[A-Z]:\\|/(?:usr|etc|var|tmp)/)[^\s<>"|?*\n]+',  # File paths
            r'\b[\w-]+\.(?:exe|dll|sys|bat|ps1|sh|elf)\b',  # Executables
        ]

        for pattern in file_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            indicators["file"].update(m.strip() for m in matches if m.strip())

        # Registry patterns
        reg_patterns = [
            r'HKEY_[A-Z_]+\\[^\s\n]+',  # Registry keys
            r'HKLM\\[^\s\n]+',
            r'HKCU\\[^\s\n]+',
        ]

        for pattern in reg_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            indicators["reg"].update(m.strip() for m in matches if m.strip())

        # Network patterns
        net_patterns = [
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',  # IP addresses
            r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b',  # Domains
            r'https?://[^\s<>"]+',  # URLs
            r':\d{2,5}\b',  # Ports
        ]

        for pattern in net_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            indicators["net"].update(m.strip() for m in matches if m.strip())

        # Process patterns
        proc_patterns = [
            r'\b(?:lsass|winlogon|explorer|svchost|rundll32|regsvr32|mshta)\.exe\b',
            r'\bService:\s+([^\s\n]+)',
        ]

        for pattern in proc_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            indicators["proc"].update(m.strip() for m in matches if m.strip())

        # Hash patterns
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b',  # SHA256
        ]

        for pattern in hash_patterns:
            matches = re.findall(pattern, text)
            indicators["hash"].update(m.strip() for m in matches if m.strip())

    def _map_to_attack(self, cve_data: Dict, indicators: Dict) -> List[Dict]:
        """
        Map CVE to MITRE ATT&CK techniques based on CVE description and indicators.

        Uses heuristics and keyword matching:
        - Privilege escalation → T1068 (Exploitation for Privilege Escalation)
        - Remote code execution → T1210 (Exploitation of Remote Services)
        - Memory corruption → T1055 (Process Injection)
        - DLL hijacking → T1574 (Hijack Execution Flow)
        - Registry persistence → T1547 (Boot or Logon Autostart Execution)
        """
        techniques = []
        description = cve_data.get("description", "").lower()

        # Mapping rules
        mappings = [
            {
                "keywords": ["privilege escalation", "elevate", "elevation of privilege"],
                "technique_id": "T1068",
                "technique_name": "Exploitation for Privilege Escalation",
                "tactic": "Privilege Escalation",
            },
            {
                "keywords": ["remote code execution", "rce", "arbitrary code"],
                "technique_id": "T1210",
                "technique_name": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
            },
            {
                "keywords": ["memory corruption", "buffer overflow", "heap overflow"],
                "technique_id": "T1055",
                "technique_name": "Process Injection",
                "tactic": "Defense Evasion",
            },
            {
                "keywords": ["dll hijacking", "dll side-loading", "dll search order"],
                "technique_id": "T1574.001",
                "technique_name": "Hijack Execution Flow: DLL Search Order Hijacking",
                "tactic": "Persistence",
            },
            {
                "keywords": ["registry", "run key", "autostart"],
                "technique_id": "T1547",
                "technique_name": "Boot or Logon Autostart Execution",
                "tactic": "Persistence",
            },
            {
                "keywords": ["authentication bypass", "bypass authentication"],
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "tactic": "Defense Evasion",
            },
            {
                "keywords": ["credential", "password", "token", "ntlm"],
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "tactic": "Credential Access",
            },
        ]

        for mapping in mappings:
            if any(kw in description for kw in mapping["keywords"]):
                techniques.append({
                    "technique_id": mapping["technique_id"],
                    "technique_name": mapping["technique_name"],
                    "tactic": mapping["tactic"],
                    "confidence": "medium",
                })

        # If no mappings found, default to exploitation technique
        if not techniques:
            techniques.append({
                "technique_id": "T1203",
                "technique_name": "Exploitation for Client Execution",
                "tactic": "Execution",
                "confidence": "low",
            })

        return techniques

    def _build_detection_context(
        self,
        cve_data: Dict,
        related_content: Dict,
        indicators: Dict,
        attack_techniques: List[Dict],
    ) -> Dict:
        """
        Build detection context for LLM training.

        This creates a comprehensive context that the LLM can use to generate
        high-fidelity detections.
        """
        # Combine all text sources
        technical_analysis = []

        # Add CVE description
        technical_analysis.append({
            "source": "nvd",
            "type": "description",
            "content": cve_data.get("description", ""),
        })

        # Add exploit analyses
        for exploit in related_content.get("exploits", []):
            technical_analysis.append({
                "source": "exploitdb",
                "type": "exploit_code",
                "content": exploit.get("description", ""),
            })

        # Add blog post excerpts
        for blog in related_content.get("blog_posts", []):
            technical_analysis.append({
                "source": "blog",
                "type": "technical_analysis",
                "content": blog.get("content", "")[:2000],  # Truncate to 2000 chars
                "url": blog.get("url", ""),
            })

        # Add threat report excerpts
        for report in related_content.get("threat_reports", []):
            technical_analysis.append({
                "source": "threat_report",
                "type": "threat_analysis",
                "content": report.get("content", "")[:2000],
                "author": report.get("author", ""),
            })

        return {
            "cve_id": cve_data.get("id"),
            "severity": self._get_severity_label(cve_data.get("cvss_score", 0)),
            "affected_products": cve_data.get("cpe", []),
            "weakness": cve_data.get("weakness", ""),
            "technical_analysis": technical_analysis,
            "indicators": indicators,
            "attack_techniques": attack_techniques,
            "exploit_available": len(related_content.get("exploits", [])) > 0,
            "itw_exploitation": self._check_itw_exploitation(related_content),
        }

    def _check_itw_exploitation(self, related_content: Dict) -> bool:
        """Check if CVE has known in-the-wild exploitation"""
        # Check threat reports for ITW mentions
        for report in related_content.get("threat_reports", []):
            content = report.get("content", "").lower()
            if any(term in content for term in ["in the wild", "itw", "active exploitation"]):
                return True
        return False

    def _get_severity_label(self, cvss_score: float) -> str:
        """Convert CVSS score to severity label"""
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"

    def _extract_cvss_score(self, cve_item: Dict) -> float:
        """Extract CVSS score from CVE item"""
        metrics = cve_item.get("metrics", {})

        # Try CVSS v3.1 first
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)

        # Try CVSS v3.0
        if "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", 0.0)

        # Fallback to CVSS v2
        if "cvssMetricV2" in metrics:
            return metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)

        return 0.0

    def _extract_cpe(self, cve_item: Dict) -> List[str]:
        """Extract CPE (Common Platform Enumeration) from CVE"""
        cpes = []
        configurations = cve_item.get("configurations", [])

        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", True):
                        cpes.append(cpe_match.get("criteria", ""))

        return cpes

    def _extract_cwe(self, cve_item: Dict) -> str:
        """Extract CWE (Common Weakness Enumeration) from CVE"""
        weaknesses = cve_item.get("weaknesses", [])

        if weaknesses:
            descriptions = weaknesses[0].get("description", [])
            if descriptions:
                return descriptions[0].get("value", "")

        return ""

    def generate_training_example(self, enriched_cve: Dict) -> Dict:
        """
        Convert enriched CVE to training example for LLM.

        Output format matches the detection_generation task schema.
        """
        detection_context = enriched_cve["detection_context"]
        cve_data = enriched_cve["cve_data"]
        indicators = enriched_cve["indicators"]
        attack_techniques = enriched_cve["attack_techniques"]

        # Use primary technique for detection
        primary_technique = attack_techniques[0] if attack_techniques else {
            "technique_id": "T1203",
            "technique_name": "Exploitation for Client Execution",
        }

        # Build comprehensive input context
        input_context = {
            "technique_id": primary_technique["technique_id"],
            "technique_name": primary_technique["technique_name"],
            "description": self._build_technique_description(
                cve_data, detection_context, primary_technique
            ),
            "platforms": self._extract_platforms(cve_data),
            "threat_intel": self._build_threat_intel(detection_context),
            "related_cves": [cve_data["id"]],
        }

        # This will be used as training data - the LLM should learn to generate
        # detections from this enriched context
        training_example = {
            "task": "detection_generation",
            "input": input_context,
            "output": {
                "detections": [],  # To be filled by human expert or existing detections
                "indicators": indicators,
                "metadata": {
                    "cve_id": cve_data["id"],
                    "cvss_score": cve_data["cvss_score"],
                    "severity": detection_context["severity"],
                    "exploit_available": detection_context["exploit_available"],
                    "itw_exploitation": detection_context["itw_exploitation"],
                },
            },
        }

        return training_example

    def _build_technique_description(
        self,
        cve_data: Dict,
        detection_context: Dict,
        technique: Dict,
    ) -> str:
        """Build comprehensive technique description from all sources"""
        parts = [
            f"CVE {cve_data['id']} - {cve_data['description']}",
            f"\nMITRE Technique: {technique['technique_name']}",
            f"\nSeverity: {detection_context['severity'].upper()} (CVSS: {cve_data['cvss_score']})",
        ]

        if detection_context["exploit_available"]:
            parts.append("\n⚠️ PUBLIC EXPLOIT AVAILABLE")

        if detection_context["itw_exploitation"]:
            parts.append("\n⚠️ IN-THE-WILD EXPLOITATION OBSERVED")

        # Add technical analysis excerpts
        for analysis in detection_context["technical_analysis"][:3]:  # Top 3 sources
            if analysis["content"]:
                parts.append(f"\n\nSource: {analysis['source']}")
                parts.append(f"{analysis['content'][:500]}...")

        return "\n".join(parts)

    def _extract_platforms(self, cve_data: Dict) -> List[str]:
        """Extract affected platforms from CPE data"""
        platforms = set()

        for cpe in cve_data.get("cpe", []):
            cpe_lower = cpe.lower()
            if "windows" in cpe_lower:
                platforms.add("Windows")
            if "linux" in cpe_lower:
                platforms.add("Linux")
            if "macos" in cpe_lower or "mac_os" in cpe_lower:
                platforms.add("macOS")
            if "azure" in cpe_lower or "office365" in cpe_lower:
                platforms.add("Azure")

        return sorted(list(platforms)) if platforms else ["Windows"]  # Default to Windows

    def _build_threat_intel(self, detection_context: Dict) -> str:
        """Build threat intelligence summary"""
        intel_parts = []

        if detection_context["exploit_available"]:
            intel_parts.append("Public exploit code available.")

        if detection_context["itw_exploitation"]:
            intel_parts.append("Active in-the-wild exploitation observed.")

        # Add threat report summaries
        threat_reports = [
            a for a in detection_context["technical_analysis"]
            if a["type"] == "threat_analysis"
        ]

        if threat_reports:
            intel_parts.append(
                f"Referenced in {len(threat_reports)} threat intelligence report(s)."
            )

        return " ".join(intel_parts)


def enrich_cve_batch(cve_ids: List[str], output_dir: Path = None) -> List[Dict]:
    """
    Enrich a batch of CVEs and generate training examples.

    Args:
        cve_ids: List of CVE IDs to enrich
        output_dir: Directory to save training examples

    Returns:
        List of training examples
    """
    pipeline = CVEEnrichmentPipeline()
    training_examples = []

    output_dir = output_dir or CVE_DATA_DIR / "training_examples"
    output_dir.mkdir(parents=True, exist_ok=True)

    for cve_id in cve_ids:
        try:
            # Enrich CVE
            enriched = pipeline.enrich_cve(cve_id)

            # Generate training example
            training_example = pipeline.generate_training_example(enriched)
            training_examples.append(training_example)

            # Save individual training example
            output_file = output_dir / f"{cve_id}_training.json"
            with open(output_file, "w") as f:
                json.dump(training_example, f, indent=2)

        except Exception as e:
            print(f"✗ Failed to enrich {cve_id}: {e}")
            continue

    # Save batch as JSONL
    batch_file = output_dir / f"cve_batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    with open(batch_file, "w") as f:
        for example in training_examples:
            f.write(json.dumps(example) + "\n")

    print(f"\n✓ Generated {len(training_examples)} training examples → {batch_file}")
    return training_examples
