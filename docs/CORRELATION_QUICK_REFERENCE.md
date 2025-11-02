# Correlation Engine Quick Reference

## TL;DR

The correlation engine generates high-quality attack chain correlations by:
1. Pairing all detections within each vendor
2. Scoring each pair on 6 factors (0-140 points)
3. Keeping only top-scored correlations (≥60%)
4. Intelligently merging correlations (skip if >10 targets)
5. Building JOIN-based queries that chain events by device + account

---

## Key Numbers

| Metric | Value |
|--------|-------|
| **Min Quality Score** | 60% (84/140 points) |
| **Max Techniques/Correlation** | 8 |
| **Min Tactics/Correlation** | 2 |
| **Super-Merge Threshold** | Skip if >10 target techniques |
| **Simple Correlation Frequency** | Max 10 appearances per technique |
| **Super-Merge Frequency** | Unlimited (already consolidated) |
| **JOIN Time Window** | 60 minutes |
| **Max Correlations/Vendor** | 25 initial filter |

---

## Scoring Factors (140 Points Total)

| Factor | Points | What It Measures |
|--------|--------|------------------|
| **Technique Criticality** | 0-30 | High-impact techniques (T1003, T1021, etc.) |
| **Tactic Priority** | 0-20 | Critical tactics (Cred Access, Lateral Mvmt) |
| **Query Specificity** | 0-20 | Specific IOCs vs generic terms |
| **False Positive Rate** | 0-25 | Query precision (inverse - lower FP = higher score) |
| **Attack Progression** | 0-25 | Valid kill chain steps |
| **Data Source Diversity** | -10 to +20 | Multiple data sources |

---

## Processing Pipeline

```
Detection Files (141 MDE)
         ↓
All Possible Pairs (9,870)
         ↓
Score Each Pair (0-140 pts)
         ↓
Filter by Quality (≥60%) → ~25 kept
         ↓
Group by Technique Pair → ~19 unique pairs
         ↓
Smart Super-Merge
    ├─ If 1 target: keep as-is
    ├─ If 2-10 targets: merge (max 8 techniques, min 2 tactics)
    └─ If >10 targets: skip merge, keep individual correlations
         ↓
Frequency Limit
    ├─ Super-merged (3+ techniques): unlimited
    └─ Simple (2 techniques): max 10 appearances
         ↓
Generate JOIN Queries
         ↓
Final Output (10-25 correlations per vendor)
```

---

## Tactic Priority Weights

| Tactic | Weight | Priority |
|--------|--------|----------|
| Credential Access, Lateral Movement, Exfiltration, Impact | 10 | **Critical** |
| Privilege Escalation, Persistence, Command & Control | 8 | **High** |
| Defense Evasion, Collection, Initial Access | 6 | **Medium** |
| Execution, Discovery | 4 | **Lower** |
| Resource Development, Reconnaissance | 3 | **Lowest** |

---

## Valid Attack Progressions (Examples)

```
✅ Initial Access → Execution
✅ Execution → Privilege Escalation
✅ Privilege Escalation → Credential Access
✅ Credential Access → Lateral Movement ⭐ (KEY)
✅ Lateral Movement → Collection
✅ Collection → Exfiltration ⭐ (KEY)
✅ Defense Evasion → Persistence
✅ Persistence → Command & Control
✅ Command & Control → Exfiltration
```

---

## High-Impact Techniques (Partial List)

| Technique | Name | Why High-Impact |
|-----------|------|-----------------|
| T1003 | Credential Dumping | Direct credential theft |
| T1021 | Remote Services | Lateral movement |
| T1078 | Valid Accounts | Persistence/privilege esc |
| T1110 | Brute Force | Credential access |
| T1098 | Account Manipulation | Persistence |
| T1070 | Indicator Removal | Defense evasion |
| T1486 | Data Encrypted for Impact | Ransomware |
| T1048 | Exfiltration Over Alternative Protocol | Data theft |

---

## JOIN Query Example

```kql
// Define indicators with technique attribution
let DeviceFileEvents_CredentialAccess = DeviceFileEvents
| where Timestamp > ago(1h)
| where
  // Multi-FactorAuthentication
  (InitiatingProcessCommandLine contains "C:\\windows\\system32\\drivers\\etc\\hosts") or
  // CreateProcessWithToken
  (InitiatingProcessCommandLine has_any("CreateProcessWithTokenW", "runas"))
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, *;

let DeviceEvents_CredentialAccess = DeviceEvents
| where Timestamp > ago(1h)
| where
  // AdditionalCloudCredentials
  (AdditionalFields has_all("gcloud", "iam", "service-accounts"))
| project Timestamp, DeviceName, AccountName, *;

// Chain events by device + account + time
DeviceFileEvents_CredentialAccess
| join kind=inner (
    DeviceEvents_CredentialAccess
) on DeviceName, AccountName
| where abs(datetime_diff('minute', Timestamp, Timestamp1)) <= 60
| project *
```

**Why JOIN?**
- ✅ Proves events are related (same device + account)
- ✅ Lower false positives
- ✅ Shows actual attack chain
- ✅ More actionable for analysts

---

## Account Field Mapping

| Table | Account Field |
|-------|---------------|
| DeviceFileEvents | `InitiatingProcessAccountName` |
| DeviceProcessEvents | `AccountName` |
| DeviceEvents | `AccountName` |
| DeviceNetworkEvents | `InitiatingProcessAccountName` |
| DeviceRegistryEvents | `InitiatingProcessAccountName` |
| DeviceLogonEvents | `AccountName` |

**Note:** Automatically selected by correlation engine.

---

## Quality Indicators

### Good Correlation (90%+ score)
```yaml
✅ High-impact techniques (T1003 + T1021)
✅ Critical tactics (Credential Access → Lateral Movement)
✅ Specific queries (mimikatz.exe, RemoteIP filters)
✅ Low FP rate (precise conditions)
✅ Valid attack progression
✅ Multiple data sources

Example Score: 126/140 = 90% ✅
```

### Poor Correlation (30%+ score)
```yaml
❌ Low-impact techniques (T1059 + T1082)
❌ Lower priority tactics (Execution, Discovery)
❌ Generic queries (FileName contains "exe")
❌ High FP rate (too broad)
❌ No clear progression
❌ Same data source

Example Score: 46/140 = 33% ❌ FILTERED OUT
```

---

## Output Structure

```json
{
  "vendor_correlations": [
    {
      "vendor": "mde",
      "a": "path/to/technique_a.yaml",
      "b": "path/to/technique_b.yaml",
      "query_a": "...",
      "query_b": "...",
      "combined_query": "JOIN query...",
      "relevance_score": 0.92,
      "techniques_involved": [
        "Multi-FactorAuthentication",
        "AdditionalCloudCredentials",
        "..."
      ]
    }
  ]
}
```

---

## Common Issues & Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| **No correlations** | No files in data/generate/ | Generate detections first |
| **Too few correlations** | High quality threshold | ✅ Fixed - lowered to 60% |
| **Correlations too complex** | Too many techniques | ✅ Fixed - limited to 8 |
| **Unrelated techniques** | No tactic requirement | ✅ Fixed - requires 2+ tactics |
| **Same technique repeated** | No frequency limit | ✅ Fixed - smart frequency (10 for simple, unlimited for merged) |
| **One massive correlation** | Aggressive super-merge | ✅ Fixed - skip merge if >10 targets |

---

## Tuning Parameters

### Change Quality Threshold
```python
# In archer/config.py or set environment variable
CORRELATION_MIN_RELEVANCE=0.50  # Lower from 0.60 (more correlations, lower quality)
# Or
CORRELATION_MIN_RELEVANCE=0.70  # Raise from 0.60 (fewer correlations, higher quality)
```

### Adjust Super-Merge Threshold
```python
# In engine.py _apply_correlation_grouping()
elif num_targets > 15:  # Change from 10 to be more aggressive
    # Skip super-merge for very popular techniques
```

### Adjust Frequency Limits
```python
# In engine.py _apply_correlation_grouping()
if max_occurrences < 15:  # Change from 10 for simple correlations
```

### Adjust Time Window
```python
# In JOIN query generation
| where abs(datetime_diff('minute', Timestamp, Timestamp1)) <= 120  # Change from 60
```

---

## Files & Locations

| Component | File Path |
|-----------|-----------|
| **Correlation Engine** | `archer/genai/engine.py` |
| **Configuration** | `archer/config.py` |
| **Detection Files** | `data/generate/*.yaml` |
| **Correlation Output** | `data/correlate/{group_name}.json` |
| **Full Documentation** | `docs/CORRELATION_ENGINE.md` |

---

## Quick Commands

```bash
# Generate correlations
python -c "from archer.genai.engine import generate_correlations; \
           generate_correlations('Group Name', 'data/generate')"

# Check correlation output
cat data/correlate/Group_Name.json | jq '.vendor_correlations | length'

# View correlation details
cat data/correlate/Group_Name.json | jq '.vendor_correlations[0]'
```

---

## Key Takeaways

1. **Quality Over Quantity:** Only top 25 correlations per vendor (≥75% score)
2. **Attack Chain Focus:** Requires valid kill chain progression (+25 pts)
3. **Complexity Limits:** Max 8 techniques, min 2 tactics
4. **JOIN-Based:** Events must be related (same device + account + time)
5. **Tactic-Driven:** Prioritizes critical tactics (Credential Access, Lateral Movement)

---

**For Full Details:** See [CORRELATION_ENGINE.md](CORRELATION_ENGINE.md)

**Version:** 1.3 (October 31, 2024)
