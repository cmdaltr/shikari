# CVE Training Data

> **Status (2026-10-16):** some of what this document names was never built: `scripts/validate_training_data.py`; the files it shows are examples of output. What exists: `scripts/config/` (`setup_knowledge_base.py`, `import_community_rules.py`, `build_embeddings.py`, `search_similar_detections.py`, `validate_detections.py`, `quickstart_rag.py`), `scripts/ai/` (`setup_local_llm.py`, `train_ai.py`), `scripts/data/` and `scripts/validation/`: see [SCRIPTS.md](../../../../../docs/SCRIPTS.md).

This directory contains CVE data enriched with technical analysis from security blogs, threat reports, and exploit POCs for training LLMs on ITW (In-The-Wild) exploit and POC detection generation.

## Directory Structure

```
cve_data/
├── README.md                  # This file
├── cache/                     # Raw CVE data from NVD
│   ├── CVE-2024-1234.json
│   └── CVE-2024-5678.json
├── enriched/                  # Enriched CVEs with blog posts and analysis
│   ├── CVE-2024-1234.json
│   └── CVE-2024-5678.json
└── training_examples/         # Final training examples in JSONL format
    ├── CVE-2024-1234_training.json
    ├── CVE-2024-5678_training.json
    └── cve_batch_20250114_120000.jsonl
```

## CVE Enrichment Workflow

### Step 1: Fetch CVE Data

```bash
# Enrich specific CVEs
python scripts/ai/train_ai.py cve --cves CVE-2024-1234 CVE-2024-5678

# Enrich high-severity CVEs from 2024
python scripts/ai/train_ai.py cve --year 2024 --min-cvss 7.0 --limit 50

# Enrich only ITW exploits
python scripts/ai/train_ai.py cve --year 2024 --itw-only
```

### Step 2: Review Enriched Data

```bash
# View enriched CVE with full context
cat archer/ai/training/datasets/cve_data/enriched/CVE-2024-1234.json | jq .
```

### Step 3: Add Manual Detections

The enriched CVEs generate training examples with **empty detection arrays** that need to be filled by security experts:

```json
{
  "task": "detection_generation",
  "input": {
    "technique_id": "T1210",
    "description": "CVE-2024-1234 - Buffer overflow...",
    "platforms": ["Windows"],
    "related_cves": ["CVE-2024-1234"]
  },
  "output": {
    "detections": [],  // ← ADD YOUR DETECTIONS HERE
    "indicators": {
      "cmd": ["nc -e /bin/sh"],
      "file": ["C:\\exploit.exe"]
    }
  }
}
```

Add platform-specific detections:

```json
{
  "detections": [
    {
      "platform": "splunk",
      "query": "index=windows_logs sourcetype=WinEventLog:Sysmon EventCode=3 DestinationPort=4444 | where Image LIKE \"%exploit.exe%\" | stats count by Computer, SourceIp, DestinationIp",
      "confidence": "high",
      "false_positive_rate": "low",
      "data_sources": ["Sysmon Event ID 3", "Network connection logs"]
    },
    {
      "platform": "elastic",
      "query": "{\n  \"query\": {\n    \"bool\": {\n      \"must\": [\n        {\"term\": {\"event.code\": \"3\"}},\n        {\"term\": {\"destination.port\": 4444}},\n        {\"wildcard\": {\"process.executable\": \"*exploit.exe*\"}}\n      ]\n    }\n  }\n}",
      "confidence": "high",
      "false_positive_rate": "low"
    }
  ]
}
```

### Step 4: Validate Training Examples

```bash
# Validate JSONL format
python scripts/validate_training_data.py archer/ai/training/datasets/cve_data/training_examples/

# Check for required fields
# Verify query syntax
# Ensure technique IDs are valid
```

## Enrichment Pipeline Details

### What Gets Enriched?

For each CVE, the pipeline:

1. **Fetches NVD Data**
   - CVE description
   - CVSS score and severity
   - Affected products (CPE)
   - CWE (weakness type)
   - Publication dates

2. **Searches Related Content**
   - ExploitDB POCs
   - GitHub exploit repositories
   - Security blog posts from:
     - Google Project Zero
     - Microsoft Security Response Center
     - Recorded Future
     - Mandiant
     - CrowdStrike
     - Rapid7
   - Vendor threat reports

3. **Extracts Technical Indicators**
   - Commands: Shell commands, PowerShell, bash scripts
   - Files: Executables, DLLs, modified files
   - Registry: Windows registry keys
   - Network: IPs, domains, ports, protocols
   - Processes: Service names, process names
   - Hashes: MD5, SHA1, SHA256

4. **Maps to MITRE ATT&CK**
   - Identifies relevant techniques
   - Determines tactics
   - Assigns confidence levels

5. **Builds Detection Context**
   - Combines all sources into comprehensive context
   - Flags ITW exploitation
   - Flags public exploit availability

### Example: CVE-2021-44228 (Log4Shell)

**Input**: `CVE-2021-44228`

**Enrichment Output**:

```json
{
  "cve_id": "CVE-2021-44228",
  "cve_data": {
    "description": "Remote code execution in Apache Log4j 2.x via JNDI lookup...",
    "cvss_score": 10.0,
    "affected_products": ["cpe:2.3:a:apache:log4j:2.0:*"]
  },
  "related_content": {
    "blog_posts": [
      {
        "source": "lunasec",
        "url": "https://www.lunasec.io/docs/blog/log4j-zero-day/",
        "content": "Detailed technical analysis of Log4Shell exploitation..."
      },
      {
        "source": "crowdstrike",
        "url": "https://www.crowdstrike.com/blog/log4j2-vulnerability-analysis/",
        "content": "CrowdStrike analysis of Log4Shell ITW exploitation..."
      }
    ],
    "exploits": [
      {
        "source": "github",
        "url": "https://github.com/kozmer/log4j-shell-poc",
        "description": "Public POC for Log4Shell"
      }
    ]
  },
  "indicators": {
    "cmd": ["${jndi:ldap://"],
    "net": ["ldap://", "rmi://"],
    "file": ["log4j-core-2."],
    "proc": ["java"]
  },
  "attack_techniques": [
    {
      "technique_id": "T1190",
      "technique_name": "Exploit Public-Facing Application",
      "tactic": "Initial Access",
      "confidence": "high"
    },
    {
      "technique_id": "T1203",
      "technique_name": "Exploitation for Client Execution",
      "tactic": "Execution",
      "confidence": "high"
    }
  ],
  "detection_context": {
    "severity": "critical",
    "exploit_available": true,
    "itw_exploitation": true
  }
}
```

**Training Example** (after manual detection addition):

```json
{
  "task": "detection_generation",
  "input": {
    "technique_id": "T1190",
    "technique_name": "Exploit Public-Facing Application",
    "description": "CVE-2021-44228 (Log4Shell) - Remote code execution in Apache Log4j 2.x...\n\nSeverity: CRITICAL (CVSS: 10.0)\n⚠️ PUBLIC EXPLOIT AVAILABLE\n⚠️ IN-THE-WILD EXPLOITATION OBSERVED\n\nWidespread exploitation targeting Java applications...",
    "platforms": ["Linux", "Windows"],
    "threat_intel": "Massive ITW exploitation. 100+ threat groups observed. Public POCs available.",
    "related_cves": ["CVE-2021-44228"]
  },
  "output": {
    "detections": [
      {
        "platform": "splunk",
        "query": "index=web_logs OR index=app_logs | regex _raw=\".*\\$\\{jndi:(ldap|rmi|dns)://.*\\}.*\" | stats count by src_ip, uri, user_agent | where count > 0",
        "confidence": "high",
        "false_positive_rate": "very_low",
        "data_sources": ["Web Access Logs", "Application Logs", "WAF Logs"]
      },
      {
        "platform": "elastic",
        "query": "{\n  \"query\": {\n    \"bool\": {\n      \"should\": [\n        {\"regexp\": {\"http.request.body.content\": \".*\\\\$\\\\{jndi:(ldap|rmi|dns)://.*\"}},\n        {\"regexp\": {\"url.original\": \".*\\\\$\\\\{jndi:(ldap|rmi|dns)://.*\"}},\n        {\"regexp\": {\"user_agent.original\": \".*\\\\$\\\\{jndi:(ldap|rmi|dns)://.*\"}}\n      ],\n      \"minimum_should_match\": 1\n    }\n  }\n}",
        "confidence": "high",
        "false_positive_rate": "very_low"
      }
    ],
    "indicators": {
      "cmd": ["${jndi:ldap://", "${jndi:rmi://"],
      "net": ["ldap://", "rmi://"],
      "file": ["log4j-core-2."]
    },
    "metadata": {
      "cve_id": "CVE-2021-44228",
      "cvss_score": 10.0,
      "exploit_available": true,
      "itw_exploitation": true
    }
  }
}
```

## Data Quality Guidelines

### High-Quality Training Examples

✅ **Good Training Examples**:
- CVEs with detailed technical analysis from multiple sources
- Public exploit POCs available
- Clear MITRE ATT&CK technique mapping
- Multiple platform-specific detections
- Known ITW exploitation with threat intel

✅ **Include**:
- CVEs with CVSS >= 7.0 (High/Critical)
- CVEs with public exploits
- CVEs mentioned in threat reports
- CVEs with ITW exploitation
- CVEs with multiple blog post analyses

❌ **Avoid**:
- CVEs with minimal information
- Theoretical vulnerabilities without POCs
- CVEs without technical details
- Deprecated/ancient vulnerabilities (unless historically significant)

### Manual Review Process

1. **Review Enriched CVE**
   - Verify blog post content is relevant
   - Check indicator extraction accuracy
   - Validate ATT&CK technique mapping

2. **Add Platform Detections**
   - Write detection queries for each platform
   - Test queries for syntax correctness
   - Document data sources required
   - Estimate false positive rates

3. **Validate Training Example**
   - Ensure JSONL format is correct
   - Verify all required fields present
   - Check query syntax
   - Validate technique IDs

## Priority CVEs for Training

### High-Priority Categories

1. **ITW Exploits** (Highest Priority)
   - CVEs with confirmed in-the-wild exploitation
   - Active campaigns targeting the vulnerability
   - Weaponized exploits available

2. **Public POCs** (High Priority)
   - CVEs with working exploit code on GitHub/ExploitDB
   - POCs demonstrated at security conferences
   - Exploits in Metasploit/exploit frameworks

3. **Critical Severity** (Medium Priority)
   - CVSS >= 9.0
   - Remote code execution
   - Authentication bypass
   - Privilege escalation

4. **Well-Documented** (Medium Priority)
   - Multiple blog posts with technical analysis
   - Vendor advisories with details
   - Detailed threat reports

### Recommended Starting Set

```bash
# Log4Shell (most important)
python scripts/ai/train_ai.py cve --cves CVE-2021-44228

# ProxyLogon/ProxyShell (Exchange)
python scripts/ai/train_ai.py cve --cves CVE-2021-26855 CVE-2021-34473 CVE-2021-34523

# PrintNightmare
python scripts/ai/train_ai.py cve --cves CVE-2021-34527 CVE-2021-1675

# Zerologon
python scripts/ai/train_ai.py cve --cves CVE-2020-1472

# BlueKeep
python scripts/ai/train_ai.py cve --cves CVE-2019-0708

# EternalBlue
python scripts/ai/train_ai.py cve --cves CVE-2017-0144

# Recent critical vulnerabilities from 2024
python scripts/ai/train_ai.py cve --year 2024 --min-cvss 9.0 --limit 100
```

## Adding Blog Posts Manually

If automatic search doesn't find relevant blog posts, add them manually:

1. Create a blog post JSON file in `archer/ai/training/datasets/blog_posts/`:

```json
{
  "title": "Technical Analysis of CVE-2024-1234",
  "author": "Google Project Zero",
  "url": "https://googleprojectzero.blogspot.com/...",
  "date": "2024-01-15",
  "content": "Full blog post content here...",
  "cves": ["CVE-2024-1234"],
  "tags": ["memory corruption", "windows", "privilege escalation"]
}
```

2. Re-run enrichment:

```bash
python scripts/ai/train_ai.py cve --cves CVE-2024-1234
```

The pipeline will automatically find and include the blog post in the enrichment.

## Training with CVE Data

Once you have enriched CVEs with manual detections:

```bash
# Combine all CVE training examples into single JSONL
cat archer/ai/training/datasets/cve_data/training_examples/*.json | jq -c . > archer/ai/training/datasets/cve_training.jsonl

# Train model with CVE data
python -m archer.ai.training.pipelines.training \
    --data archer/ai/training/datasets/cve_training.jsonl \
    --model llama3.1:70b \
    --epochs 5
```

## Contribution Workflow

1. **Find Important CVE**: Identify high-impact CVE
2. **Enrich CVE**: Run enrichment pipeline
3. **Review Output**: Check enriched CVE JSON
4. **Add Detections**: Write platform-specific queries
5. **Validate**: Test queries, check syntax
6. **Commit**: Add to training dataset

## Metrics

Track these metrics for your CVE training dataset:

- **Total CVEs**: Number of enriched CVEs
- **With Exploits**: CVEs with public POCs
- **ITW Exploitation**: CVEs exploited in the wild
- **With Detections**: CVEs with manual detection queries
- **Blog Post Coverage**: Average blog posts per CVE
- **Platform Coverage**: Detections per platform (Splunk, Elastic, etc.)

Target metrics for production training:
- 200+ enriched CVEs
- 80%+ with public exploits
- 50%+ with ITW exploitation
- 100% with manual detections
- 3+ blog posts per CVE
- 4 platforms per CVE
