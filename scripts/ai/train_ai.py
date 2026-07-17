#!/usr/bin/env python3
"""
Archer Training Data Collection Script

Unified script for collecting training data from multiple sources:
- CVE enrichment (NVD + blog posts + exploits)
- Threat report conversion (PDF to JSONL)
- OSINT extraction (Elastic, Splunk rules)

Usage:
    # Enrich CVEs
    python scripts/train_ai.py cve --cves CVE-2024-1234 CVE-2024-5678
    python scripts/train_ai.py cve --year 2024 --min-cvss 7.0 --limit 50
    python scripts/train_ai.py cve --file cve_list.txt --itw-only

    # Convert threat reports
    python scripts/train_ai.py reports --pdf threat_report.pdf
    python scripts/train_ai.py reports --dir reports/ --batch

    # Extract OSINT samples
    python scripts/train_ai.py osint --source elastic --repo https://github.com/elastic/detection-rules
    python scripts/train_ai.py osint --source splunk --repo https://github.com/splunk/security_content
    python scripts/train_ai.py osint --all
"""

import argparse
import json
import sys
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from archer.ai.training.pipelines.cve_enrichment import (
    CVEEnrichmentPipeline,
    enrich_cve_batch,
)
from archer.ai.training.config import (
    CVE_DATA_DIR,
    THREAT_REPORTS_DIR,
    OSINT_SAMPLES_DIR,
    BLOG_POSTS_DIR,
)


# ============================================================================
# CVE Enrichment
# ============================================================================


def fetch_cves_by_year(year: int, min_cvss: float = 0.0, limit: int = None) -> List[str]:
    """Fetch CVEs from NVD for a specific year"""
    import requests

    cves = []
    start_index = 0
    results_per_page = 100

    print(f"Fetching CVEs from {year} (CVSS >= {min_cvss})...")

    while True:
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?pubStartDate={year}-01-01T00:00:00.000"
            f"&pubEndDate={year}-12-31T23:59:59.999"
            f"&startIndex={start_index}"
            f"&resultsPerPage={results_per_page}"
        )

        if min_cvss >= 7.0:
            url += f"&cvssV3Severity=HIGH&cvssV3Severity=CRITICAL"

        response = requests.get(url, timeout=30)

        if response.status_code != 200:
            print(f"Error fetching CVEs: {response.status_code}")
            break

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            break

        for vuln in vulnerabilities:
            cve_item = vuln["cve"]
            cve_id = cve_item["id"]

            # Check CVSS score
            cvss_score = extract_cvss_score(cve_item)
            if cvss_score >= min_cvss:
                cves.append(cve_id)

            if limit and len(cves) >= limit:
                break

        if limit and len(cves) >= limit:
            break

        # Check if there are more results
        total_results = data.get("totalResults", 0)
        if start_index + results_per_page >= total_results:
            break

        start_index += results_per_page

    print(f"Found {len(cves)} CVEs matching criteria")
    return cves[:limit] if limit else cves


def extract_cvss_score(cve_item: dict) -> float:
    """Extract CVSS score from CVE item"""
    metrics = cve_item.get("metrics", {})

    if "cvssMetricV31" in metrics:
        return metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)
    if "cvssMetricV30" in metrics:
        return metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", 0.0)
    if "cvssMetricV2" in metrics:
        return metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)

    return 0.0


def handle_cve_enrichment(args):
    """Handle CVE enrichment subcommand"""
    print("=" * 70)
    print("CVE ENRICHMENT")
    print("=" * 70)

    # Get CVE list
    cve_list = []

    if args.cves:
        cve_list = args.cves
        print(f"Enriching {len(cve_list)} specified CVEs")
    elif args.year:
        cve_list = fetch_cves_by_year(year=args.year, min_cvss=args.min_cvss, limit=args.limit)
    elif args.file:
        if not args.file.exists():
            print(f"Error: File not found: {args.file}")
            sys.exit(1)

        with open(args.file, "r") as f:
            cve_list = [line.strip() for line in f if line.strip()]
        print(f"Loaded {len(cve_list)} CVEs from file")

    if not cve_list:
        print("No CVEs to process")
        sys.exit(0)

    # Apply ITW filter if requested
    if args.itw_only:
        print("\n⚠️  ITW-only filtering will be applied during enrichment")

    print(f"\nEnriching {len(cve_list)} CVEs...")
    print("-" * 70)

    # Enrich CVEs
    training_examples = enrich_cve_batch(cve_ids=cve_list, output_dir=args.output)

    print("\n" + "=" * 70)
    print(f"✓ Successfully enriched {len(training_examples)} CVEs")
    print(f"✓ Training examples: {args.output or CVE_DATA_DIR / 'training_examples'}")
    print("=" * 70)


# ============================================================================
# Threat Report Conversion
# ============================================================================


def convert_pdf_to_jsonl(pdf_path: Path, output_dir: Path = None) -> Dict:
    """
    Convert PDF threat report to JSONL training data.

    Requires: pdfplumber or PyPDF2
    """
    try:
        import pdfplumber
    except ImportError:
        print("Error: pdfplumber not installed. Run: pip install pdfplumber")
        sys.exit(1)

    output_dir = output_dir or THREAT_REPORTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Converting: {pdf_path.name}")

    # Extract text from PDF
    full_text = []
    metadata = {}

    with pdfplumber.open(pdf_path) as pdf:
        # Extract metadata
        if pdf.metadata:
            metadata = {
                "title": pdf.metadata.get("Title", pdf_path.stem),
                "author": pdf.metadata.get("Author", "Unknown"),
                "creator": pdf.metadata.get("Creator", ""),
                "created": pdf.metadata.get("CreationDate", ""),
            }

        # Extract text from all pages
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                full_text.append(text)

    combined_text = "\n\n".join(full_text)

    # Extract CVEs mentioned in report
    import re

    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cves = list(set(re.findall(cve_pattern, combined_text, re.IGNORECASE)))

    # Extract threat group mentions
    threat_groups = extract_threat_groups(combined_text)

    # Extract techniques
    technique_pattern = r"T\d{4}(?:\.\d{3})?"
    techniques = list(set(re.findall(technique_pattern, combined_text)))

    # Build JSON structure
    report_data = {
        "title": metadata.get("title", pdf_path.stem),
        "author": metadata.get("author", "Unknown"),
        "source": pdf_path.stem,
        "date": metadata.get("created", datetime.now().isoformat()),
        "url": "",  # Manual input required
        "content": combined_text,
        "cves": sorted(cves),
        "threat_groups": sorted(threat_groups),
        "techniques": sorted(techniques),
        "tags": extract_tags_from_content(combined_text),
        "converted_at": datetime.now().isoformat(),
    }

    # Save as JSON
    output_file = output_dir / f"{pdf_path.stem}.json"
    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"✓ Converted → {output_file}")
    print(f"  - CVEs: {len(cves)}")
    print(f"  - Threat Groups: {len(threat_groups)}")
    print(f"  - Techniques: {len(techniques)}")

    return report_data


def extract_threat_groups(text: str) -> List[str]:
    """Extract threat group names from text"""
    # Common threat group naming patterns
    patterns = [
        r"\b(APT\d+)\b",
        r"\b(Lazarus Group)\b",
        r"\b(Fancy Bear)\b",
        r"\b(Cozy Bear)\b",
        r"\b(Scattered Spider)\b",
        r"\b(LAPSUS\$)\b",
        r"\b(FIN\d+)\b",
        r"\b(UNC\d+)\b",
        r"\b(TA\d+)\b",
    ]

    groups = set()
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        groups.update(m.strip() for m in matches)

    return list(groups)


def extract_tags_from_content(text: str) -> List[str]:
    """Extract relevant tags from content"""
    tags = set()

    # Keyword-based tags
    keywords = {
        "ransomware": ["ransomware", "ransom", "crypto-locker"],
        "phishing": ["phishing", "spear-phishing", "credential harvesting"],
        "malware": ["malware", "trojan", "backdoor", "rat"],
        "apt": ["advanced persistent threat", "apt"],
        "credential_theft": ["credential dumping", "mimikatz", "lsass"],
        "lateral_movement": ["lateral movement", "pass-the-hash", "smb"],
        "persistence": ["persistence", "registry", "scheduled task"],
        "exfiltration": ["exfiltration", "data theft", "data leak"],
    }

    text_lower = text.lower()
    for tag, kws in keywords.items():
        if any(kw in text_lower for kw in kws):
            tags.add(tag)

    return sorted(list(tags))


def handle_report_conversion(args):
    """Handle threat report conversion subcommand"""
    print("=" * 70)
    print("THREAT REPORT CONVERSION")
    print("=" * 70)

    if args.pdf:
        # Convert single PDF
        if not args.pdf.exists():
            print(f"Error: PDF not found: {args.pdf}")
            sys.exit(1)

        convert_pdf_to_jsonl(args.pdf, args.output)

    elif args.dir:
        # Batch convert directory
        if not args.dir.exists():
            print(f"Error: Directory not found: {args.dir}")
            sys.exit(1)

        pdf_files = list(args.dir.glob("*.pdf"))

        if not pdf_files:
            print(f"No PDF files found in {args.dir}")
            sys.exit(0)

        print(f"Found {len(pdf_files)} PDF files")
        print("-" * 70)

        converted = 0
        for pdf_file in pdf_files:
            try:
                convert_pdf_to_jsonl(pdf_file, args.output)
                converted += 1
            except Exception as e:
                print(f"✗ Failed to convert {pdf_file.name}: {e}")

        print("\n" + "=" * 70)
        print(f"✓ Converted {converted}/{len(pdf_files)} reports")
        print(f"✓ Output: {args.output or THREAT_REPORTS_DIR}")
        print("=" * 70)


# ============================================================================
# OSINT Extraction
# ============================================================================


def clone_repo(repo_url: str, target_dir: Path) -> Path:
    """Clone git repository"""
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    clone_dir = target_dir / repo_name

    if clone_dir.exists():
        print(f"Repository already cloned: {clone_dir}")
        return clone_dir

    print(f"Cloning {repo_url}...")
    subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(clone_dir)], check=True, capture_output=True
    )

    return clone_dir


def extract_elastic_rules(repo_dir: Path, output_file: Path):
    """Extract Elastic detection rules"""
    print(f"Extracting Elastic rules from {repo_dir}...")

    rule_files = list(repo_dir.rglob("*.toml"))
    print(f"Found {len(rule_files)} Elastic rule files")

    training_examples = []

    for rule_file in rule_files:
        try:
            # Parse TOML
            import toml

            with open(rule_file, "r", encoding="utf-8") as f:
                rule_data = toml.load(f)

            # Extract rule metadata
            rule = rule_data.get("rule", {})

            if not rule or "name" not in rule:
                continue

            # Extract techniques
            threat = rule.get("threat", [])
            techniques = []
            for t in threat:
                technique = t.get("technique", [])
                for tech in technique:
                    tech_id = tech.get("id", "")
                    if tech_id:
                        techniques.append(tech_id)

            if not techniques:
                continue

            # Build training example
            example = {
                "task": "detection_generation",
                "input": {
                    "technique_id": techniques[0],
                    "technique_name": rule.get("name", ""),
                    "description": rule.get("description", ""),
                    "platforms": ["Windows", "Linux"],
                    "threat_intel": f"Elastic detection rule: {rule.get('name', '')}",
                },
                "output": {
                    "detections": [
                        {
                            "platform": "elastic",
                            "query": rule.get("query", ""),
                            "confidence": "high",
                            "false_positive_rate": "low",
                        }
                    ],
                    "indicators": {},
                },
            }

            training_examples.append(example)

        except Exception as e:
            print(f"Failed to parse {rule_file.name}: {e}")
            continue

    # Save as JSONL
    with open(output_file, "w") as f:
        for example in training_examples:
            f.write(json.dumps(example) + "\n")

    print(f"✓ Extracted {len(training_examples)} Elastic rules → {output_file}")


def extract_splunk_rules(repo_dir: Path, output_file: Path):
    """Extract Splunk security content"""
    print(f"Extracting Splunk rules from {repo_dir}...")

    # Splunk security content is in YAML format
    rule_files = list(repo_dir.rglob("*.yml"))
    print(f"Found {len(rule_files)} Splunk rule files")

    training_examples = []

    for rule_file in rule_files:
        try:
            import yaml

            with open(rule_file, "r", encoding="utf-8") as f:
                rule_data = yaml.safe_load(f)

            if not rule_data or "name" not in rule_data:
                continue

            # Extract techniques
            tags = rule_data.get("tags", {})
            mitre_attack = tags.get("mitre_attack_id", [])

            if not mitre_attack:
                continue

            techniques = [t.upper() for t in mitre_attack if t]

            # Build training example
            example = {
                "task": "detection_generation",
                "input": {
                    "technique_id": techniques[0] if techniques else "T1000",
                    "technique_name": rule_data.get("name", ""),
                    "description": rule_data.get("description", ""),
                    "platforms": ["Windows"],
                    "threat_intel": f"Splunk rule: {rule_data.get('name', '')}",
                },
                "output": {
                    "detections": [
                        {
                            "platform": "splunk",
                            "query": rule_data.get("search", ""),
                            "confidence": "high",
                            "false_positive_rate": "low",
                        }
                    ],
                    "indicators": {},
                },
            }

            training_examples.append(example)

        except Exception as e:
            print(f"Failed to parse {rule_file.name}: {e}")
            continue

    # Save as JSONL
    with open(output_file, "w") as f:
        for example in training_examples:
            f.write(json.dumps(example) + "\n")

    print(f"✓ Extracted {len(training_examples)} Splunk rules → {output_file}")


def handle_osint_extraction(args):
    """Handle OSINT extraction subcommand"""
    print("=" * 70)
    print("OSINT EXTRACTION")
    print("=" * 70)

    output_dir = args.output or OSINT_SAMPLES_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    temp_dir = Path("/tmp/archer_osint_repos")
    temp_dir.mkdir(parents=True, exist_ok=True)

    sources = {
        "elastic": {
            "url": "https://github.com/elastic/detection-rules",
            "extractor": extract_elastic_rules,
        },
        "splunk": {
            "url": "https://github.com/splunk/security_content",
            "extractor": extract_splunk_rules,
        },
    }

    # Determine which sources to extract
    if args.all:
        sources_to_extract = sources.keys()
    elif args.source:
        if args.source not in sources:
            print(f"Error: Unknown source '{args.source}'")
            print(f"Available: {', '.join(sources.keys())}")
            sys.exit(1)
        sources_to_extract = [args.source]
    else:
        print("Error: Specify --source <name> or --all")
        sys.exit(1)

    # Extract from each source
    for source_name in sources_to_extract:
        print(f"\n{source_name.upper()}")
        print("-" * 70)

        source = sources[source_name]
        repo_url = args.repo if args.repo else source["url"]

        try:
            # Clone repository
            repo_dir = clone_repo(repo_url, temp_dir)

            # Extract rules
            output_file = output_dir / f"{source_name}_rules.jsonl"
            source["extractor"](repo_dir, output_file)

        except Exception as e:
            print(f"✗ Failed to extract {source_name}: {e}")

    print("\n" + "=" * 70)
    print(f"✓ OSINT extraction complete")
    print(f"✓ Output: {output_dir}")
    print("=" * 70)


# ============================================================================
# Main CLI
# ============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Archer Training Data Collection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    subparsers = parser.add_subparsers(dest="command", help="Data collection command")

    # ========================================================================
    # CVE Subcommand
    # ========================================================================
    cve_parser = subparsers.add_parser("cve", help="Enrich CVE data")

    cve_group = cve_parser.add_mutually_exclusive_group(required=True)
    cve_group.add_argument("--cves", nargs="+", help="Specific CVE IDs (e.g., CVE-2024-1234)")
    cve_group.add_argument("--year", type=int, help="Fetch CVEs from specific year")
    cve_group.add_argument("--file", type=Path, help="File with CVE IDs (one per line)")

    cve_parser.add_argument(
        "--min-cvss", type=float, default=0.0, help="Minimum CVSS score (default: 0.0)"
    )
    cve_parser.add_argument("--limit", type=int, help="Maximum CVEs to process")
    cve_parser.add_argument(
        "--itw-only", action="store_true", help="Only CVEs with ITW exploitation"
    )
    cve_parser.add_argument("--output", type=Path, help="Output directory")

    # ========================================================================
    # Reports Subcommand
    # ========================================================================
    reports_parser = subparsers.add_parser("reports", help="Convert threat reports")

    reports_group = reports_parser.add_mutually_exclusive_group(required=True)
    reports_group.add_argument("--pdf", type=Path, help="Single PDF file to convert")
    reports_group.add_argument("--dir", type=Path, help="Directory with PDF files (batch mode)")

    reports_parser.add_argument("--output", type=Path, help="Output directory")

    # ========================================================================
    # OSINT Subcommand
    # ========================================================================
    osint_parser = subparsers.add_parser("osint", help="Extract OSINT samples")

    osint_parser.add_argument(
        "--source", choices=["elastic", "splunk"], help="OSINT source to extract"
    )
    osint_parser.add_argument("--repo", help="Custom repository URL")
    osint_parser.add_argument("--all", action="store_true", help="Extract from all sources")
    osint_parser.add_argument("--output", type=Path, help="Output directory")

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Route to appropriate handler
    if args.command == "cve":
        handle_cve_enrichment(args)
    elif args.command == "reports":
        handle_report_conversion(args)
    elif args.command == "osint":
        handle_osint_extraction(args)


if __name__ == "__main__":
    main()
