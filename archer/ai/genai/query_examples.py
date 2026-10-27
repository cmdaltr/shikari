"""
Query Example Repository Manager

Downloads, parses, and indexes high-quality query examples from open source repositories
to enhance GenAI query generation through few-shot learning.

Supported repositories:
- Splunk Security Content
- Elastic Detection Rules
- Microsoft Defender Hunting Queries
"""

import json
import yaml
import subprocess
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from collections import defaultdict
import hashlib
from archer import paths


class QueryExampleRepository:
    """Manages a repository of high-quality query examples for learning."""

    def __init__(self, base_dir: str = None):
        """
        Initialize the query example repository.

        Args:
            base_dir: Base directory for storing query examples (default: archer/data/query_examples)
        """
        if base_dir is None:
            # Store in archer/data/query_examples
            base_dir = paths.HOME / "archer" / "data" / "query_examples"

        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # Repository definitions
        self.repositories = {
            "splunk_security_content": {
                "url": "https://github.com/splunk/security_content.git",
                "path": self.base_dir / "splunk_security_content",
                "type": "git",
                "parser": self._parse_splunk_security_content,
            },
            "defender_hunting": {
                "url": "https://github.com/francoisfried/Defender-Advanced-Hunting-Queries.git",
                "path": self.base_dir / "defender_hunting",
                "type": "git",
                "parser": self._parse_defender_hunting,
            },
        }

        # Index structure: technique_id -> [examples]
        self.index_file = self.base_dir / "index.json"
        self.index = self._load_index()

    def _load_index(self) -> Dict:
        """Load the query example index from disk."""
        if self.index_file.exists():
            try:
                with open(self.index_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Could not load index: {e}")
                return self._create_empty_index()
        return self._create_empty_index()

    def _create_empty_index(self) -> Dict:
        """Create an empty index structure."""
        return {
            "last_updated": None,
            "techniques": {},  # technique_id -> [examples]
            "tactics": {},  # tactic -> [examples]
            "platforms": {},  # platform -> [examples]
            "vendors": {  # vendor -> [examples]
                "splunk": [],
                "mde": [],
                "elastic": [],
            },
            "statistics": {
                "total_examples": 0,
                "by_vendor": {},
                "by_technique": {},
            },
        }

    def _save_index(self):
        """Save the index to disk."""
        try:
            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump(self.index, f, indent=2)
        except Exception as e:
            print(f"Error saving index: {e}")

    def update_repositories(self, force: bool = False):
        """
        Clone or update all configured repositories.

        Args:
            force: If True, delete existing repos and re-clone
        """
        print("Updating query example repositories...")

        for name, config in self.repositories.items():
            repo_path = config["path"]

            if force and repo_path.exists():
                print(f"  Removing existing repository: {name}")
                import shutil

                shutil.rmtree(repo_path)

            if not repo_path.exists():
                print(f"  Cloning {name}...")
                try:
                    subprocess.run(
                        ["git", "clone", "--depth", "1", config["url"], str(repo_path)],
                        check=True,
                        capture_output=True,
                    )
                    print(f"    ✓ Cloned {name}")
                except subprocess.CalledProcessError as e:
                    print(f"    ✗ Failed to clone {name}: {e.stderr.decode()}")
                    continue
            else:
                print(f"  Updating {name}...")
                try:
                    subprocess.run(
                        ["git", "-C", str(repo_path), "pull"],
                        check=True,
                        capture_output=True,
                    )
                    print(f"    ✓ Updated {name}")
                except subprocess.CalledProcessError as e:
                    print(f"    ✗ Failed to update {name}: {e.stderr.decode()}")

    def rebuild_index(self):
        """Parse all repositories and rebuild the index."""
        print("\nRebuilding query example index...")

        # Reset index
        self.index = self._create_empty_index()

        for name, config in self.repositories.items():
            repo_path = config["path"]
            if not repo_path.exists():
                print(f"  Skipping {name} (not cloned)")
                continue

            print(f"  Parsing {name}...")
            parser = config["parser"]
            try:
                examples = parser(repo_path)
                print(f"    Found {len(examples)} examples")

                # Add to index
                for example in examples:
                    self._index_example(example)

            except Exception as e:
                print(f"    Error parsing {name}: {e}")
                import traceback

                traceback.print_exc()

        # Update statistics
        self._update_statistics()

        # Save index
        self._save_index()

        print(
            f"\n✓ Index rebuilt: {self.index['statistics']['total_examples']} total examples"
        )
        print(f"  By vendor: {self.index['statistics']['by_vendor']}")
        print(f"  By technique: {len(self.index['techniques'])} techniques covered")

    def _index_example(self, example: Dict):
        """Add an example to the index."""
        # Index by technique
        for technique_id in example.get("techniques", []):
            if technique_id not in self.index["techniques"]:
                self.index["techniques"][technique_id] = []
            self.index["techniques"][technique_id].append(example)

        # Index by tactic
        for tactic in example.get("tactics", []):
            if tactic not in self.index["tactics"]:
                self.index["tactics"][tactic] = []
            self.index["tactics"][tactic].append(example)

        # Index by platform
        for platform in example.get("platforms", []):
            if platform not in self.index["platforms"]:
                self.index["platforms"][platform] = []
            self.index["platforms"][platform].append(example)

        # Index by vendor
        vendor = example.get("vendor", "unknown")
        if vendor in self.index["vendors"]:
            self.index["vendors"][vendor].append(example)

    def _update_statistics(self):
        """Update index statistics."""
        stats = self.index["statistics"]
        stats["total_examples"] = sum(
            len(examples) for examples in self.index["vendors"].values()
        )
        stats["by_vendor"] = {
            vendor: len(examples)
            for vendor, examples in self.index["vendors"].items()
        }
        stats["by_technique"] = {
            technique: len(examples)
            for technique, examples in self.index["techniques"].items()
        }
        import datetime

        self.index["last_updated"] = datetime.datetime.utcnow().isoformat()

    def _parse_splunk_security_content(self, repo_path: Path) -> List[Dict]:
        """Parse Splunk Security Content repository."""
        examples = []

        # Detections are in detections/ directory
        detections_dir = repo_path / "detections"
        if not detections_dir.exists():
            return examples

        # Recursively find all YAML files
        yaml_files = list(detections_dir.rglob("*.yml"))

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                if not data or "search" not in data:
                    continue

                # Extract MITRE ATT&CK mapping
                techniques = []
                tactics = []

                mitre_attack = data.get("tags", {}).get("mitre_attack_id", [])
                if isinstance(mitre_attack, list):
                    techniques = mitre_attack
                elif isinstance(mitre_attack, str):
                    techniques = [mitre_attack]

                # Extract tactic from kill chain
                for tag in data.get("tags", {}).get("mitre_attack_technique", []):
                    if isinstance(tag, dict) and "tactic" in tag:
                        tactics.append(tag["tactic"])

                example = {
                    "id": hashlib.md5(str(yaml_file).encode()).hexdigest()[:16],
                    "source": "splunk_security_content",
                    "file": str(yaml_file.relative_to(repo_path)),
                    "name": data.get("name", "Unknown"),
                    "description": data.get("description", ""),
                    "vendor": "splunk",
                    "query": data.get("search", ""),
                    "techniques": techniques,
                    "tactics": tactics,
                    "platforms": self._detect_platforms_from_splunk(
                        data.get("search", "")
                    ),
                    "data_sources": data.get("tags", {}).get("required_fields", []),
                    "severity": data.get("tags", {}).get("severity", "medium"),
                    "metadata": {
                        "author": data.get("author", "Unknown"),
                        "date": data.get("date", ""),
                        "confidence": data.get("tags", {}).get("confidence", ""),
                    },
                }

                examples.append(example)

            except Exception as e:
                # Skip files that fail to parse
                continue

        return examples

    def _parse_defender_hunting(self, repo_path: Path) -> List[Dict]:
        """Parse Defender Advanced Hunting Queries repository."""
        examples = []

        # KQL files are typically in root or subdirectories
        kql_files = list(repo_path.rglob("*.kql")) + list(repo_path.rglob("*.kusto"))

        for kql_file in kql_files:
            try:
                with open(kql_file, "r", encoding="utf-8") as f:
                    content = f.read()

                # Try to extract metadata from comments
                name = kql_file.stem.replace("_", " ").title()
                description = ""
                techniques = []
                tactics = []

                # Look for MITRE ATT&CK references in comments
                for line in content.split("\n"):
                    if line.strip().startswith("//"):
                        comment = line.strip()[2:].strip()
                        # Check for technique IDs
                        tech_matches = re.findall(r"T\d{4}(?:\.\d{3})?", comment)
                        techniques.extend(tech_matches)

                        # Check for tactic mentions
                        for tactic in [
                            "Initial Access",
                            "Execution",
                            "Persistence",
                            "Privilege Escalation",
                            "Defense Evasion",
                            "Credential Access",
                            "Discovery",
                            "Lateral Movement",
                            "Collection",
                            "Exfiltration",
                            "Command and Control",
                            "Impact",
                        ]:
                            if tactic.lower() in comment.lower():
                                tactics.append(tactic)

                        # Extract description
                        if not description and len(comment) > 20:
                            description = comment

                example = {
                    "id": hashlib.md5(str(kql_file).encode()).hexdigest()[:16],
                    "source": "defender_hunting",
                    "file": str(kql_file.relative_to(repo_path)),
                    "name": name,
                    "description": description,
                    "vendor": "mde",
                    "query": content,
                    "techniques": list(set(techniques)),  # Remove duplicates
                    "tactics": list(set(tactics)),
                    "platforms": ["Windows"],  # Defender is primarily Windows
                    "data_sources": self._extract_kql_tables(content),
                    "severity": "medium",  # Default
                    "metadata": {
                        "author": "Microsoft",
                        "date": "",
                    },
                }

                examples.append(example)

            except Exception as e:
                # Skip files that fail to parse
                continue

        # Also check for markdown files with embedded queries
        md_files = list(repo_path.rglob("*.md"))
        for md_file in md_files:
            try:
                with open(md_file, "r", encoding="utf-8") as f:
                    content = f.read()

                # Extract code blocks that contain KQL
                kql_blocks = re.findall(
                    r"```(?:kql|kusto)?\s*\n(.*?)\n```", content, re.DOTALL
                )

                for idx, kql in enumerate(kql_blocks):
                    if not kql.strip():
                        continue

                    # Try to find a title
                    lines_before = content[: content.find(kql)].split("\n")
                    name = md_file.stem.replace("_", " ").title()
                    for line in reversed(lines_before[-10:]):
                        if line.startswith("#"):
                            name = line.lstrip("#").strip()
                            break

                    example = {
                        "id": hashlib.md5(
                            (str(md_file) + str(idx)).encode()
                        ).hexdigest()[:16],
                        "source": "defender_hunting",
                        "file": f"{md_file.relative_to(repo_path)}#block{idx}",
                        "name": name,
                        "description": "",
                        "vendor": "mde",
                        "query": kql.strip(),
                        "techniques": [],
                        "tactics": [],
                        "platforms": ["Windows"],
                        "data_sources": self._extract_kql_tables(kql),
                        "severity": "medium",
                        "metadata": {},
                    }

                    examples.append(example)

            except Exception:
                continue

        return examples

    def _detect_platforms_from_splunk(self, query: str) -> List[str]:
        """Detect platforms from Splunk query content."""
        platforms = set()
        query_lower = query.lower()

        if any(
            x in query_lower
            for x in ["windows", "eventcode", "win_", "process_name", "registry"]
        ):
            platforms.add("Windows")
        if any(x in query_lower for x in ["linux", "unix", "bash", "shell"]):
            platforms.add("Linux")
        if any(x in query_lower for x in ["macos", "darwin", "osx"]):
            platforms.add("macOS")
        if any(x in query_lower for x in ["aws", "cloudtrail", "ec2", "s3"]):
            platforms.add("AWS")
        if any(x in query_lower for x in ["azure", "azuread", "azureactivity"]):
            platforms.add("Azure")
        if any(x in query_lower for x in ["gcp", "google cloud"]):
            platforms.add("GCP")

        return list(platforms) if platforms else ["Windows"]  # Default to Windows

    def _extract_kql_tables(self, query: str) -> List[str]:
        """Extract table names from KQL query."""
        tables = set()

        # Common Defender tables
        table_pattern = r"\b(Device\w+|Alert\w+|Email\w+|Identity\w+|Cloud\w+)\b"
        matches = re.findall(table_pattern, query)
        tables.update(matches)

        return list(tables)

    def get_examples_for_technique(
        self, technique_id: str, vendor: str = None, limit: int = 5
    ) -> List[Dict]:
        """
        Get query examples for a specific MITRE ATT&CK technique.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., "T1003", "T1003.001")
            vendor: Filter by vendor (splunk, mde, elastic)
            limit: Maximum number of examples to return

        Returns:
            List of query examples
        """
        # Normalize technique ID
        technique_id = technique_id.upper()
        if not technique_id.startswith("T"):
            technique_id = "T" + technique_id

        examples = self.index.get("techniques", {}).get(technique_id, [])

        # Filter by vendor if specified
        if vendor:
            vendor_lower = vendor.lower()
            examples = [e for e in examples if e.get("vendor") == vendor_lower]

        # Limit results
        return examples[:limit]

    def get_examples_for_tactic(
        self, tactic: str, vendor: str = None, limit: int = 5
    ) -> List[Dict]:
        """Get query examples for a specific MITRE ATT&CK tactic."""
        examples = self.index.get("tactics", {}).get(tactic, [])

        if vendor:
            vendor_lower = vendor.lower()
            examples = [e for e in examples if e.get("vendor") == vendor_lower]

        return examples[:limit]

    def get_statistics(self) -> Dict:
        """Get repository statistics."""
        return self.index.get("statistics", {})


# Singleton instance
_repository = None


def get_repository() -> QueryExampleRepository:
    """Get the global query example repository instance."""
    global _repository
    if _repository is None:
        _repository = QueryExampleRepository()
    return _repository


if __name__ == "__main__":
    # CLI for managing the repository
    import sys

    repo = get_repository()

    if len(sys.argv) < 2:
        print("Usage: python query_examples.py [update|rebuild|stats]")
        sys.exit(1)

    command = sys.argv[1]

    if command == "update":
        repo.update_repositories()
    elif command == "rebuild":
        repo.update_repositories()
        repo.rebuild_index()
    elif command == "stats":
        stats = repo.get_statistics()
        print(json.dumps(stats, indent=2))
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
