# Adding New Query Repositories

Quick guide for adding new query example sources to enhance the learning system.

## Quick Start

To add a new GitHub repository of security queries:

1. **Add repository definition**
2. **Implement parser function**
3. **Update and rebuild**
4. **Verify examples indexed**

## Step-by-Step Guide

### 1. Add Repository Definition

Edit `archer/genai/query_examples.py`, add to `self.repositories` in `__init__`:

```python
self.repositories = {
    # ... existing repositories ...

    "your_repo_name": {
        "url": "https://github.com/org/repo.git",
        "path": self.base_dir / "your_repo_name",
        "type": "git",
        "parser": self._parse_your_repo_name,
    },
}
```

### 2. Implement Parser Function

Add parser method to `QueryExampleRepository` class:

```python
def _parse_your_repo_name(self, repo_path: Path) -> List[Dict]:
    """Parse your repository's query format."""
    examples = []

    # Find query files (adjust pattern as needed)
    query_files = list(repo_path.rglob("*.yml"))  # or *.json, *.kql, etc.

    for query_file in query_files:
        try:
            # Parse file
            with open(query_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)  # or json.load, or custom parser

            # Skip if no query present
            if "query" not in data and "search" not in data:
                continue

            # Extract MITRE ATT&CK techniques
            techniques = self._extract_techniques(data)

            # Extract tactics
            tactics = self._extract_tactics(data)

            # Detect vendor/platform
            vendor = self._detect_vendor(data, query_file)

            # Detect platforms (Windows, Linux, etc.)
            platforms = self._detect_platforms(data)

            # Create example dictionary
            example = {
                "id": hashlib.md5(str(query_file).encode()).hexdigest()[:16],
                "source": "your_repo_name",
                "file": str(query_file.relative_to(repo_path)),
                "name": data.get("name") or data.get("title") or "Unknown",
                "description": data.get("description", ""),
                "vendor": vendor,  # "splunk", "mde", "elastic", "sigma"
                "query": data.get("query") or data.get("search") or "",
                "techniques": techniques,  # ["T1003", "T1059", ...]
                "tactics": tactics,  # ["Credential Access", "Execution", ...]
                "platforms": platforms,  # ["Windows", "Linux", ...]
                "data_sources": data.get("data_sources", []),
                "severity": data.get("severity") or data.get("level") or "medium",
                "metadata": {
                    "author": data.get("author", "Unknown"),
                    "date": data.get("date", ""),
                    "status": data.get("status", ""),
                    # Add other metadata as needed
                },
            }

            examples.append(example)

        except Exception as e:
            # Skip files that fail to parse
            # print(f"Warning: Could not parse {query_file}: {e}")
            continue

    return examples
```

### 3. Helper Functions

You can reuse or create these helper functions:

```python
def _extract_techniques(self, data: Dict) -> List[str]:
    """Extract MITRE ATT&CK technique IDs from metadata."""
    techniques = []

    # Common locations for technique IDs
    # Check tags
    tags = data.get("tags", [])
    for tag in tags:
        if isinstance(tag, str):
            # Extract T1234 or T1234.001 patterns
            tech_matches = re.findall(r"T\d{4}(?:\.\d{3})?", tag.upper())
            techniques.extend(tech_matches)

    # Check mitre_attack field
    mitre = data.get("mitre_attack", []) or data.get("mitre_attack_id", [])
    if isinstance(mitre, list):
        techniques.extend(mitre)
    elif isinstance(mitre, str):
        techniques.append(mitre)

    # Check techniques field
    if "techniques" in data:
        tech_list = data["techniques"]
        if isinstance(tech_list, list):
            techniques.extend(tech_list)

    # Remove duplicates and normalize
    return list(set([t.upper() for t in techniques if t]))


def _extract_tactics(self, data: Dict) -> List[str]:
    """Extract MITRE ATT&CK tactics from metadata."""
    tactics = []

    # Check kill_chain_phases
    kill_chain = data.get("kill_chain_phases", [])
    for phase in kill_chain:
        if isinstance(phase, dict) and "phase_name" in phase:
            tactic = phase["phase_name"].replace("_", " ").title()
            tactics.append(tactic)

    # Check tactics field
    if "tactics" in data:
        tactic_list = data["tactics"]
        if isinstance(tactic_list, list):
            tactics.extend(tactic_list)

    # Check tags for tactic keywords
    TACTIC_KEYWORDS = [
        "Initial Access", "Execution", "Persistence",
        "Privilege Escalation", "Defense Evasion",
        "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact"
    ]

    tags = data.get("tags", [])
    for tag in tags:
        if isinstance(tag, str):
            for tactic in TACTIC_KEYWORDS:
                if tactic.lower() in tag.lower():
                    tactics.append(tactic)

    return list(set(tactics))


def _detect_vendor(self, data: Dict, file_path: Path) -> str:
    """Detect SIEM vendor from query content or metadata."""

    # Check explicit vendor field
    if "vendor" in data:
        vendor = data["vendor"].lower()
        if vendor in ["splunk", "elastic", "mde", "microsoft", "sigma"]:
            return vendor

    # Check query content
    query = data.get("query", "") or data.get("search", "")
    query_lower = query.lower()

    if query.startswith("index="):
        return "splunk"
    elif query.startswith("Device") or "summarize" in query_lower:
        return "mde"
    elif "from" in query_lower and "where" in query_lower:
        return "elastic"

    # Check file extension
    if file_path.suffix == ".kql":
        return "mde"
    elif file_path.suffix == ".eql":
        return "elastic"

    # Default
    return "sigma"  # Universal format


def _detect_platforms(self, data: Dict) -> List[str]:
    """Detect target platforms (Windows, Linux, etc.)."""
    platforms = set()

    # Check explicit platform field
    if "platforms" in data:
        plat_list = data["platforms"]
        if isinstance(plat_list, list):
            platforms.update(plat_list)

    # Check query content for indicators
    query = data.get("query", "") or data.get("search", "")
    query_lower = query.lower()

    if any(x in query_lower for x in ["windows", "eventcode", "win_", "registry"]):
        platforms.add("Windows")
    if any(x in query_lower for x in ["linux", "unix", "bash", "shell"]):
        platforms.add("Linux")
    if any(x in query_lower for x in ["macos", "darwin", "osx"]):
        platforms.add("macOS")
    if any(x in query_lower for x in ["aws", "cloudtrail", "ec2", "s3"]):
        platforms.add("AWS")
    if any(x in query_lower for x in ["azure", "azuread"]):
        platforms.add("Azure")
    if any(x in query_lower for x in ["gcp", "google cloud"]):
        platforms.add("GCP")

    return list(platforms) if platforms else ["Windows"]  # Default
```

### 4. Update and Rebuild

```bash
# Clone the new repository
python scripts/manage_query_examples.py update

# Rebuild index to include new examples
python scripts/manage_query_examples.py rebuild

# Verify examples were indexed
python scripts/manage_query_examples.py stats
```

You should see the new repository in the statistics:

```
Examples by Vendor:
  splunk: 1,234
  mde: 856
  sigma: 2,433
  your_vendor: 123  # New!
```

### 5. Test Examples

```bash
# Search for a specific technique
python scripts/manage_query_examples.py search T1003

# Should now include examples from your new repository
```

## Example: Adding Elastic Detection Rules

Here's a complete example for adding Elastic's official detection rules:

```python
# In archer/genai/query_examples.py

# 1. Add to __init__
self.repositories["elastic_detection_rules"] = {
    "url": "https://github.com/elastic/detection-rules.git",
    "path": self.base_dir / "elastic_detection_rules",
    "type": "git",
    "parser": self._parse_elastic_detection_rules,
}

# 2. Implement parser
def _parse_elastic_detection_rules(self, repo_path: Path) -> List[Dict]:
    """Parse Elastic Detection Rules repository."""
    examples = []

    # Elastic rules are in rules/ directory as TOML files
    rules_dir = repo_path / "rules"
    if not rules_dir.exists():
        return examples

    # Find all TOML rule files
    toml_files = list(rules_dir.rglob("*.toml"))

    for toml_file in toml_files:
        try:
            import toml

            with open(toml_file, "r", encoding="utf-8") as f:
                data = toml.load(f)

            # Elastic structure: data["rule"] contains the rule
            rule = data.get("rule", {})

            if "query" not in rule:
                continue

            # Extract MITRE ATT&CK from threat field
            techniques = []
            tactics = []

            threat = rule.get("threat", [])
            for t in threat:
                if t.get("framework") == "MITRE ATT&CK":
                    # Get tactic
                    tactic_name = t.get("tactic", {}).get("name", "")
                    if tactic_name:
                        tactics.append(tactic_name)

                    # Get techniques
                    for technique in t.get("technique", []):
                        tech_id = technique.get("id", "")
                        if tech_id:
                            techniques.append(tech_id)

                        # Get sub-techniques
                        for subtech in technique.get("subtechnique", []):
                            subtech_id = subtech.get("id", "")
                            if subtech_id:
                                techniques.append(subtech_id)

            example = {
                "id": hashlib.md5(str(toml_file).encode()).hexdigest()[:16],
                "source": "elastic_detection_rules",
                "file": str(toml_file.relative_to(repo_path)),
                "name": rule.get("name", "Unknown"),
                "description": rule.get("description", ""),
                "vendor": "elastic",
                "query": rule.get("query", ""),
                "techniques": techniques,
                "tactics": tactics,
                "platforms": self._detect_platforms_from_elastic(rule),
                "data_sources": rule.get("index", []),
                "severity": rule.get("severity", "medium"),
                "metadata": {
                    "author": rule.get("author", ["Unknown"])[0] if rule.get("author") else "Unknown",
                    "date": rule.get("creation_date", ""),
                    "type": rule.get("type", ""),
                    "language": rule.get("language", ""),
                },
            }

            examples.append(example)

        except Exception as e:
            continue

    return examples

def _detect_platforms_from_elastic(self, rule: Dict) -> List[str]:
    """Detect platforms from Elastic rule metadata."""
    platforms = set()

    # Check index patterns
    indices = rule.get("index", [])
    for index in indices:
        if "windows" in index.lower() or "winlogbeat" in index.lower():
            platforms.add("Windows")
        elif "linux" in index.lower() or "auditbeat" in index.lower():
            platforms.add("Linux")
        elif "macos" in index.lower():
            platforms.add("macOS")
        elif "aws" in index.lower() or "cloudtrail" in index.lower():
            platforms.add("AWS")

    return list(platforms) if platforms else ["Windows"]
```

## Example: Adding Web-Based Resources

For documentation/blog posts instead of Git repositories:

```python
# In archer/genai/query_examples.py

self.repositories["kql_blog_articles"] = {
    "url": None,  # Not a git repo
    "path": self.base_dir / "kql_articles",
    "type": "web",
    "parser": self._parse_kql_articles,
}

def _parse_kql_articles(self, storage_path: Path) -> List[Dict]:
    """Scrape KQL examples from blog articles."""
    examples = []

    articles = [
        "https://kqlquery.com/posts/from-threat-report-to-hunting-query/",
        "https://systemweakness.com/50-threat-hunting-queries-splunk-kql-every-analyst-should-know-ca82c1e5abe0",
    ]

    storage_path.mkdir(exist_ok=True)

    for article_url in articles:
        try:
            # Fetch article
            response = requests.get(article_url, timeout=30)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find code blocks
            code_blocks = soup.find_all(['pre', 'code'])

            for idx, block in enumerate(code_blocks):
                code = block.get_text()

                # Check if looks like KQL
                if not ("DeviceProcessEvents" in code or "DeviceFileEvents" in code):
                    continue

                # Try to extract context from surrounding text
                title = "KQL Query Example"
                description = ""

                # Look for heading above code block
                heading = block.find_previous(['h1', 'h2', 'h3', 'h4'])
                if heading:
                    title = heading.get_text().strip()

                # Look for paragraph before code
                para = block.find_previous('p')
                if para:
                    description = para.get_text().strip()[:200]

                # Try to extract technique IDs from text
                techniques = []
                page_text = soup.get_text()
                tech_matches = re.findall(r"T\d{4}(?:\.\d{3})?", page_text)
                techniques = list(set(tech_matches))

                example = {
                    "id": hashlib.md5(f"{article_url}_{idx}".encode()).hexdigest()[:16],
                    "source": "kql_blog_articles",
                    "file": f"{article_url}#block{idx}",
                    "name": title,
                    "description": description,
                    "vendor": "mde",
                    "query": code.strip(),
                    "techniques": techniques,
                    "tactics": [],
                    "platforms": ["Windows"],
                    "data_sources": self._extract_kql_tables(code),
                    "severity": "medium",
                    "metadata": {
                        "source_url": article_url,
                    },
                }

                examples.append(example)

        except Exception as e:
            print(f"Warning: Could not scrape {article_url}: {e}")
            continue

    return examples
```

## Testing Your Parser

Create a test script:

```python
# test_parser.py
from pathlib import Path
from archer.genai.query_examples import QueryExampleRepository

# Create test instance
repo = QueryExampleRepository()

# Test your parser
test_path = Path("archer/data/query_examples/your_repo_name")

if test_path.exists():
    examples = repo._parse_your_repo_name(test_path)

    print(f"Found {len(examples)} examples")

    if examples:
        # Show first example
        ex = examples[0]
        print(f"\nFirst example:")
        print(f"  Name: {ex['name']}")
        print(f"  Vendor: {ex['vendor']}")
        print(f"  Techniques: {ex['techniques']}")
        print(f"  Query: {ex['query'][:200]}...")
else:
    print("Repository not cloned yet. Run:")
    print("  python scripts/manage_query_examples.py update")
```

Run test:
```bash
python test_parser.py
```

## Troubleshooting

### Repository Not Cloning

```bash
# Try manual clone
cd archer/data/query_examples
git clone https://github.com/org/repo.git repo_name

# Then rebuild
python scripts/manage_query_examples.py rebuild
```

### No Examples Found

- Check file patterns in `rglob()` match your repo's structure
- Add debug prints in parser to see what files are being processed
- Verify query field names match your data structure

### Incorrect Technique Mapping

- Add more patterns to `_extract_techniques()`
- Check different metadata fields in your repository's format
- Consider manual mapping file for common patterns

## Best Practices

1. **Start Small**: Test parser on a few files before full repository
2. **Handle Errors Gracefully**: Use try/except to skip problematic files
3. **Validate Examples**: Check that required fields are present
4. **Document Format**: Add comments explaining your repository's structure
5. **Test Thoroughly**: Verify examples appear in search results

## Repository Ideas

High-value repositories to consider adding:

- ✅ **Elastic Detection Rules** - EQL and KQL queries
- ✅ **SOC Prime Sigma** - Additional Sigma rules
- ✅ **Panther Analysis** - Python-based detections
- ✅ **Chronicle Detection Rules** - YARA-L rules
- ✅ **Palantir ADS** - Detection strategy framework
- ✅ **Your Organization's Internal Queries** - Proven, production queries

## Summary

To add a new repository:

1. **Define** in `self.repositories`
2. **Parse** with custom function
3. **Extract** techniques, tactics, vendors, queries
4. **Update** and rebuild
5. **Test** search and retrieval

The system will automatically use examples from your new repository when generating queries for matching techniques.

For questions or help, see:
- [HOW_QUERY_LEARNING_WORKS.md](HOW_QUERY_LEARNING_WORKS.md) - Detailed system explanation
- [QUERY_LEARNING_SYSTEM.md](QUERY_LEARNING_SYSTEM.md) - Complete documentation
