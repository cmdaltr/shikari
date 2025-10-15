# Correlation Filtering System

## Overview

The correlation filtering system reduces thousands of potential correlations to a manageable set of **≤20 high-fidelity** detections that only trigger on malicious or rare suspicious behavior.

## Problem Statement

Without filtering, the system can generate **9,000+ correlations** by combining all possible query pairs. This creates several problems:

- **Impossible to test**: No analyst can validate 9,000 queries
- **High false positive rate**: Most pairs are not meaningful attack sequences
- **Low signal-to-noise**: Critical attack patterns buried in noise
- **Resource intensive**: Testing and deployment overhead

## Solution: Multi-Factor Scoring

Each correlation is scored 0-100 based on five factors:

### 1. Technique Criticality (0-30 points)

**Purpose**: Prioritize high-impact MITRE ATT&CK techniques that indicate sophisticated attacks.

**Scoring**: 15 points per high-impact technique (max 30)

**High-Impact Techniques** (47 total across all tactics):

| Tactic | Techniques |
|--------|-----------|
| **Persistence** | T1053 (Scheduled Task), T1136 (Create Account), T1543 (Create/Modify System Process), T1547 (Boot/Logon Autostart), T1037 (Boot/Logon Init Scripts), T1098 (Account Manipulation) |
| **Privilege Escalation** | T1068 (Exploitation for Privilege Escalation), T1134 (Access Token Manipulation), T1078 (Valid Accounts), T1055 (Process Injection), T1548 (Abuse Elevation Control) |
| **Defense Evasion** | T1070 (Indicator Removal), T1027 (Obfuscated Files/Info), T1562 (Impair Defenses), T1218 (System Binary Proxy Execution), T1140 (Deobfuscate/Decode Files) |
| **Credential Access** | T1003 (OS Credential Dumping), T1110 (Brute Force), T1555 (Credentials from Password Stores), T1556 (Modify Authentication Process), T1558 (Steal/Forge Kerberos Tickets) |
| **Lateral Movement** | T1021 (Remote Services), T1091 (Replication Through Removable Media), T1080 (Taint Shared Content), T1550 (Use Alternate Authentication Material) |
| **Collection** | T1005 (Data from Local System), T1039 (Data from Network Shared Drive), T1056 (Input Capture), T1074 (Data Staged), T1114 (Email Collection) |
| **Exfiltration** | T1020 (Automated Exfiltration), T1041 (Exfiltration Over C2), T1048 (Exfiltration Over Alternative Protocol), T1567 (Exfiltration Over Web Service) |
| **Impact** | T1485 (Data Destruction), T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1491 (Defacement), T1496 (Resource Hijacking) |

**Example**:
- Correlation involving T1003 (Credential Dumping) + T1021 (Remote Services) → 30 points (2 × 15)
- Correlation involving only T1059 (Command/Scripting Interpreter) → 0 points (not in high-impact list)

### 2. Query Specificity (0-20 points)

**Purpose**: Favor specific queries over generic ones. Specific queries have fewer false positives.

**Scoring**: Average specificity of both queries × 20

**Increases Specificity** (+0.1 each):
- File hashes (SHA256, SHA1, MD5)
- Specific IP addresses
- Domain names
- URLs
- Registry keys
- Process names
- Long command lines (>20 chars)
- Multiple conditions (WHERE, AND, OR, JOIN)

**Decreases Specificity** (-0.05 per wildcard):
- Excessive wildcards (`*`, `%`)
- Overly broad filters

**Example**:
```kql
// High specificity (0.8) - specific hash and registry key
| where SHA256 == "abc123..."
| where RegistryKey == "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

// Low specificity (0.3) - generic process and wildcards
| where ProcessName contains "*"
| where CommandLine has "powershell"
```

### 3. False Positive Rate (0-20 points)

**Purpose**: Penalize queries that trigger on common operations. Reward queries with rarity filters.

**Scoring**: (1.0 - FP_rate) × 20 (inverse scoring)

**High False Positives** (+0.15 each):
- `svchost.exe`, `powershell.exe`, `cmd.exe` (very common processes)
- Event ID 4624 (successful logon - millions daily)
- Event ID 4688 (process creation - extremely common)
- Overly broad wildcards in WHERE clauses

**Low False Positives** (-0.1 each):
- Explicit rarity filters (`rare`, `suspicious`, `malicious`)
- Threshold counting (`count() > 10`)
- Anomaly detection patterns
- Summarization with filters

**Example**:
```kql
// High FP rate (0.6) - triggers constantly
| where ProcessName == "powershell.exe"
| where EventID == 4688

// Low FP rate (0.2) - rare and suspicious
| where ProcessName == "powershell.exe"
| where CommandLine contains "Invoke-Mimikatz"
| summarize count() by User
| where count_ > 5
```

### 4. Semantic Overlap (0-15 points)

**Purpose**: Ensure correlated queries are actually related. Already filtered to >50% overlap.

**Scoring**: Normalize 50-100% overlap to 0-15 points

**Calculation**: Jaccard similarity of query tokens (excluding stopwords)

**Example**:
- 92% overlap (SigninLogs + MFA tables, same columns) → 12.6 points
- 55% overlap (minimal shared context) → 1.5 points

### 5. Attack Progression (0-15 points)

**Purpose**: Reward logical attack sequences that represent real-world TTPs.

**Scoring**: 15 points if tactics form a known progression (0 otherwise)

**Defined Progressions** (9 total):

```
initial-access → execution
initial-access → persistence
execution → privilege-escalation
privilege-escalation → defense-evasion
privilege-escalation → credential-access
credential-access → lateral-movement
lateral-movement → collection
collection → exfiltration
defense-evasion → persistence
```

**Example**:
- Correlation: Azure AD Sign-in (Initial Access) + Role Assignment (Privilege Escalation) → **15 points**
- Correlation: Two defense evasion techniques → **0 points** (no progression)

## Scoring Examples

### High Score: Scattered Spider Attack Chain

**Correlation**: Tor Sign-in + MFA Fatigue
- **Technique Criticality**: T1078.004 + T1621 (both high-impact) → **30 points**
- **Query Specificity**: Specific filters for Tor exit nodes, MFA result codes → **16 points** (0.8 × 20)
- **False Positive Rate**: Rare indicators (Tor, >5 MFA attempts) → **16 points** ((1-0.2) × 20)
- **Semantic Overlap**: 92% (both query SigninLogs) → **12.6 points**
- **Attack Progression**: Initial Access → Credential Access → **15 points**

**Total**: 89.6 / 100 → **relevance_score: 0.90**

### Low Score: Generic Process Correlation

**Correlation**: PowerShell Execution + CMD Execution
- **Technique Criticality**: T1059.001 + T1059.003 (not high-impact) → **0 points**
- **Query Specificity**: Generic process names with wildcards → **6 points** (0.3 × 20)
- **False Positive Rate**: Extremely common processes → **6 points** ((1-0.7) × 20)
- **Semantic Overlap**: 60% (both look at process tables) → **3 points**
- **Attack Progression**: Both are execution → **0 points**

**Total**: 15 / 100 → **relevance_score: 0.15**

## Filtering Process

1. **Score All Correlations**: Every correlation receives a 0-100 score
2. **Sort by Score**: Descending order (highest first)
3. **Select Top 20**: Keep only the highest-scoring correlations
4. **Add Relevance Score**: Normalize to 0-1 and add `relevance_score` field
5. **Log Distribution**: Output top, median, and lowest scores for analysis

## Configuration

The filtering threshold can be adjusted in `engine.py`:

```python
# Default: Top 20 correlations
vendor_corr = _score_and_filter_correlations(vendor_corr, file_info, max_results=20)

# Custom: Top 10 (even stricter)
vendor_corr = _score_and_filter_correlations(vendor_corr, file_info, max_results=10)

# Custom: Top 50 (more comprehensive)
vendor_corr = _score_and_filter_correlations(vendor_corr, file_info, max_results=50)
```

## Output Example

```
GenAI: Total correlations before filtering: 9847
GenAI: Scoring 9847 correlations...
GenAI: Score distribution:
  Top score: 89.6
  Median score: 24.3
  Lowest score: 8.1
GenAI: Keeping top 20 correlations (threshold: score >= 67.2)
GenAI: Filtered to 20 high-fidelity correlations
```

## Expected Impact

| Metric | Before | After |
|--------|--------|-------|
| **Total Correlations** | 9,000+ | ≤20 |
| **Testing Time** | Weeks/months | Hours/days |
| **False Positive Rate** | High (20-50%) | Low (<5%) |
| **Analyst Confidence** | Low (buried in noise) | High (vetted patterns) |
| **Detection Quality** | Mixed | High-fidelity only |

## Benefits

1. **Actionable Results**: 20 correlations can be tested thoroughly
2. **High Confidence**: Only sophisticated attack patterns included
3. **Low Noise**: Generic/common operations filtered out
4. **Logical Sequences**: Attack progressions match real-world TTPs
5. **Explainable Scoring**: Each correlation has a relevance_score with clear reasoning

## Future Enhancements

Potential improvements to the scoring system:

1. **Machine Learning**: Train model on validated true/false positives
2. **Threat Intelligence**: Integrate IOC feeds for specificity scoring
3. **Historical Data**: Use SIEM query frequency for FP estimation
4. **User Feedback**: Allow analysts to rate correlations and retrain
5. **Dynamic Thresholds**: Adjust max_results based on threat group sophistication
