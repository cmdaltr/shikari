# Training Datasets

This directory contains training data for fine-tuning local LLMs for detection engineering.

## Directory Structure

```
datasets/
├── hunting_queries/       # High-fidelity hunting queries from various sources
├── correlations/          # Example correlation rules and multi-stage detections
├── threat_intelligence/   # Threat intelligence documents and IOCs
├── threat_reports/        # Threat actor reports, TTPs, and campaign analysis
├── blog_posts/           # Security blog posts and research articles
├── cve_data/             # CVE data, exploits, and vulnerability information
└── osint_samples/        # Samples from OSINT repositories (Sigma, Elastic, etc.)
```

## Data Format

All training data should be in JSONL format with the following structure:

### Detection Generation Examples

```json
{
  "task": "detection_generation",
  "input": {
    "technique_id": "T1003.001",
    "technique_name": "OS Credential Dumping: LSASS Memory",
    "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS)...",
    "platforms": ["Windows"],
    "threat_intel": "...",
    "related_cves": ["CVE-2023-XXXX"]
  },
  "output": {
    "detections": [
      {
        "platform": "splunk",
        "query": "index=windows_logs sourcetype=WinEventLog:Security EventCode=10 TargetImage=*lsass.exe*...",
        "confidence": "high",
        "false_positive_rate": "low"
      }
    ],
    "indicators": {
      "cmd": ["mimikatz", "procdump"],
      "sw": ["lsass.exe"],
      "evt": ["10", "4688"]
    }
  }
}
```

### Correlation Generation Examples

```json
{
  "task": "correlation_generation",
  "input": {
    "techniques": ["T1003.001", "T1021.002", "T1078.003"],
    "group": "APT29",
    "hypothesis": "Lateral movement after credential theft",
    "context": "..."
  },
  "output": {
    "correlation": {
      "name": "APT29 Credential Theft and Lateral Movement",
      "query": "...",
      "time_window": "10m",
      "confidence": "high"
    }
  }
}
```

### Report Generation Examples

```json
{
  "task": "report_generation",
  "input": {
    "group": "Scattered Spider",
    "detections": [...],
    "correlations": [...],
    "metrics": {...}
  },
  "output": {
    "executive_summary": "...",
    "technical_analysis": "...",
    "recommendations": [...],
    "coverage_metrics": {...}
  }
}
```

## Data Sources

### 1. Hunting Queries
Place high-fidelity hunting queries from:
- Internal SOC/threat hunting teams
- Public hunting repositories
- Purple team exercises
- Incident response playbooks

### 2. Correlations
Include multi-stage detection logic:
- Real-world attack chains
- Kill chain correlations
- Behavioral analytics
- Cross-platform detections

### 3. Threat Intelligence
Add structured threat intel:
- STIX/TAXII feeds
- Threat actor profiles
- Campaign documentation
- IOC databases

### 4. Threat Reports
Include detailed reports:
- Vendor threat reports (CrowdStrike, Mandiant, etc.)
- Government advisories (CISA, NSA, etc.)
- Research papers
- Conference presentations

### 5. Blog Posts
Add security research blogs:
- Detection engineering content
- Threat research
- Tool development
- Case studies

### 6. CVE Data
Include vulnerability data:
- CVE descriptions and CVSS scores
- Exploit PoCs
- Patch information
- Attack vectors

### 7. OSINT Samples
Extract from existing OSINT repos:
- Sigma rules with context
- Elastic detection rules
- Splunk Security Content
- Azure Sentinel detections

## Data Quality Guidelines

1. **Accuracy**: All queries must be tested and validated
2. **Context**: Include platform, log source, and prerequisites
3. **Metadata**: Tag with technique IDs, tactics, and platforms
4. **Variety**: Include diverse detection approaches
5. **Recency**: Prioritize recent threats and techniques
6. **Documentation**: Explain detection logic and tuning

## Preprocessing Pipeline

Data will be automatically preprocessed:
1. **Cleaning**: Remove duplicates, normalize formatting
2. **Enrichment**: Add MITRE ATT&CK context, platform info
3. **Chunking**: Split long documents into training chunks
4. **Validation**: Check query syntax, structure validity
5. **Augmentation**: Generate variations and edge cases
6. **Balancing**: Ensure platform/technique distribution

## Adding New Data

To add new training data:

```bash
# Add hunting queries
cp your_queries.jsonl datasets/hunting_queries/

# Add threat reports
cp report.pdf datasets/threat_reports/
python scripts/convert_pdf_to_jsonl.py datasets/threat_reports/report.pdf

# Add CVE data
python scripts/fetch_cve_data.py --year 2024 --output datasets/cve_data/

# Preprocess all new data
python -m archer.ai_training.pipelines.preprocess --validate
```

## Data Privacy and Security

- ⚠️ **Do not include sensitive data** (customer data, internal IPs, etc.)
- ⚠️ **Sanitize all examples** before adding to training set
- ⚠️ **Review queries** for information disclosure
- ⚠️ **Anonymize** organization-specific information
