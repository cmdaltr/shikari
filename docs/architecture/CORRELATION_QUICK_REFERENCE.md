# Correlation Engine Quick Reference

> **Status (2026-10-16):** some of what this document names was never built: `scripts/test_correlation_params.py`; try thresholds with `archer-cli offline correlate <group> --min-queries … --max-queries …` instead. What exists: `scripts/config/` (`setup_knowledge_base.py`, `import_community_rules.py`, `build_embeddings.py`, `search_similar_detections.py`, `validate_detections.py`, `quickstart_rag.py`), `scripts/ai/` (`setup_local_llm.py`, `train_ai.py`), `scripts/data/` and `scripts/validation/`: see [SCRIPTS.md](../SCRIPTS.md).

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
| **Min Quality Score (Threshold)** | 40% (56/140 points) ⚙️ **TUNABLE** |
| **Max Correlations/Vendor** | 60 per vendor ⚙️ **TUNABLE** |
| **Simple Correlation Frequency** | Max 20 appearances per technique ⚙️ **TUNABLE** |
| **Chain Length** | 3 techniques, each bringing a tactic the other two don't |
| **Chains per Technique** | 3 (`CHAIN_PER_TECHNIQUE`) |
| **Chains per Vendor** | 20 (`CHAIN_MAX`); Google SecOps and MDE |
| **JOIN Time Window** | 60 minutes |

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
Filter by Quality (≥40%) → ~60 kept
         ↓
Group by Technique Pair → ~19 unique pairs
         ↓
Generate JOIN Queries (every pair its own correlation)
         ↓
Frequency Limit (pairs): max 20 appearances per technique
         ↓
Chains: A–B and B–C both pairs → A + B + C on one host within 1h
    ├─ each technique brings a tactic of its own
    └─ a new tactic first, then closed triangles; max 3 per technique, 1 per technique pair, 20 per vendor
         ↓
Final Output (40-60 correlations per vendor)
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

### Results Page Fields

When correlations are rendered in the Web UI, additional fields are added:

| Field | Description |
|-------|-------------|
| `individual_queries` | Per-technique query blocks shown stacked above the combined query |
| `techniques_by_tactic` | Techniques grouped by kill-chain tactic (used for the attack flow diagram) |
| `primary_tactics` | Tactics highlighted with a blue border in the flow |
| `attack_chain_length` | Number of tactics in the kill-chain progression |
| `tables_indexes` | Data sources shown as pill tags (MDE tables or Splunk indexes) |

See [CORRELATION_ENGINE.md — Results Page](CORRELATION_ENGINE.md#results-page--per-technique-queries) for the full field reference.
```

---

## Common Issues & Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| **No correlations** | No files in data/groups/ | Generate detections first |
| **Too few correlations** | High quality threshold | ✅ Fixed - lowered to 60% |
| **Every correlation is two techniques** | Super-merge skipped hubs with >10 partners | ✅ Fixed - chains of three built from the pairs |
| **Unrelated techniques** | No tactic requirement | ✅ Fixed - requires 2+ tactics |
| **Same technique repeated** | No frequency limit | ✅ Fixed - frequency limit for pairs, 3 chains per technique |

---

## Tunable Correlation Parameters

### Overview

Archer provides **three primary parameters** to control correlation generation quality and quantity. These can be adjusted via the **Profile → Config** page in the UI or via CLI script.

**Current Defaults:**
- **Threshold:** 40% (minimum relevance score)
- **Per-Vendor Limit:** 60 (max correlations per vendor)
- **Tech Frequency:** 20 (max appearances as first technique)

---

### 1️⃣ Threshold (Min Quality Score)

**Default:** 40% (56/140 points)

**What it does:**
- Filters correlations based on their calculated relevance score
- Score is calculated from 6 factors: technique criticality, tactic priority, query specificity, false positive rate, attack progression, and data source diversity
- Only correlations with `score ≥ threshold` are kept

**How it influences correlations:**

| Threshold | Effect | Use Case |
|-----------|--------|----------|
| **20-30%** | More correlations (100+), lower quality | Testing, exploratory analysis |
| **40%** ⭐ | Balanced coverage (40-60), good quality | **RECOMMENDED DEFAULT** |
| **50-60%** | Fewer correlations (25-40), high quality | Production environments |
| **70%+** | Very few correlations (<20), excellent quality | High-fidelity alerting only |

**Test Results (Scattered Spider, 141 MDE detections):**
```
Threshold = 40%, per_vendor = 25, tech_freq = 20 → 40 correlations
Threshold = 30%, per_vendor = 25, tech_freq = 20 → 40 correlations (no change)
Threshold = 20%, per_vendor = 25, tech_freq = 20 → 40 correlations (no change)
```

**Why 40%?**
- Current scoring is generous (most correlations score 100%)
- 40% ensures basic quality requirements are met
- Provides good coverage without sacrificing quality
- Lower thresholds (20-30%) show no increase because almost all pairs pass

**When to adjust:**
- **Lower (30%):** If you need more coverage and can tolerate some noise
- **Raise (50-60%):** If you want only the highest-quality correlations

**How to change:**
```bash
# Via CLI script
python scripts/test_correlation_params.py -t 50 -v 60 -f 20

# Via Profile → Config page
# Set "Relevance Threshold" to 50%
```

---

### 2️⃣ Per-Vendor Limit (Max Correlations)

**Default:** 60

**What it does:**
- Caps the technique pairs kept **per vendor** (MDE, Splunk, etc.); Google SecOps has 100
- A pair's per-table variants (Defender XDR's `DeviceProcessEvents` and `DeviceFileEvents` queries for the same two techniques) share one place, since they're merged into one correlation
- Places are filled best first after scoring; a technique already paired with 20 others gives its place to the next-best pair
- Until a tactic has 3 kept pairs (`PAIRS_PER_TACTIC`), its best pair above the threshold takes the next place

**How it influences correlations:**

| Per-Vendor | Effect | Use Case |
|------------|--------|----------|
| **25** | Conservative coverage (~40 correlations) | Limited SOC resources |
| **50** | Moderate coverage (~59 correlations) | Typical production |
| **60** ⭐ | Good coverage (~59 correlations) | **RECOMMENDED DEFAULT** |
| **100+** | Maximum coverage (100+ correlations) | Comprehensive detection |

**Test Results (Scattered Spider, 141 MDE detections, 40% threshold, 20 tech freq):**
```
per_vendor = 25 → 40 correlations
per_vendor = 50 → 59 correlations (+47%)
per_vendor = 60 → 59 correlations (no change - hit other limit)
per_vendor = 100 → 111 correlations (+88% from 60)
```

**Why 60?**
- Balances coverage with analyst workload
- 59 correlations observed (hitting tech frequency limit first)
- Increasing to 100 would provide +88% more coverage (111 correlations)
- 60 provides room for growth without overwhelming analysts

**When to adjust:**
- **Lower (25-40):** Small SOC team, focus on highest-value correlations only
- **Raise (80-100):** Large SOC team, want comprehensive attack chain coverage

**Important:** This limit is **per vendor**. If you have MDE + Splunk, you'll get up to 120 correlations total (60 each).

**How to change:**
```bash
# Via CLI script
python scripts/test_correlation_params.py -t 40 -v 100 -f 20

# Via Profile → Config page
# Set "Per-Vendor Limit" to 100
```

---

### 3️⃣ Tech Frequency (Technique Appearance Limit)

**Default:** 20

**What it does:**
- Limits how many times a technique can appear as the **first technique** in simple (2-technique) correlations
- Prevents popular techniques from dominating the correlation list
- Ensures diversity in attack chain coverage
- **Does NOT apply** to chains, which have their own limit (3 per technique)

**How it influences correlations:**

| Tech Freq | Effect | Use Case |
|-----------|--------|----------|
| **10** | Limited diversity (~20 correlations) | Focus on unique chains |
| **20** ⭐ | Good diversity (~40-60 correlations) | **RECOMMENDED DEFAULT** |
| **30** | High diversity (~41 correlations) | Comprehensive coverage |
| **40+** | Maximum diversity (~41 correlations) | Hits per-vendor limit |

**Test Results (Scattered Spider, 141 MDE detections, 40% threshold, 25 per-vendor):**
```
tech_freq = 10 → 20 correlations
tech_freq = 20 → 40 correlations (+100% 🚀)
tech_freq = 30 → 41 correlations (+2.5%)
tech_freq = 40 → 41 correlations (no change - hit per-vendor limit)
```

**Why 20?**
- **Biggest impact parameter** (10→20 doubled correlations!)
- Ensures popular techniques (T1003 Credential Dumping) don't dominate
- Provides good technique diversity
- Balances coverage with avoiding repetition

**When to adjust:**
- **Lower (10-15):** Want only the most unique attack chains
- **Raise (30-40):** Want maximum coverage of all possible chains

**How it works in practice:**

Example: If "Credential Dumping" (T1003) is paired with 25 different techniques:
- With tech_freq = 10: Only top 10 correlations involving T1003 are kept
- With tech_freq = 20: Top 20 correlations involving T1003 are kept
- With tech_freq = 30: All 25 correlations are kept

**How to change:**
```bash
# Via CLI script
python scripts/test_correlation_params.py -t 40 -v 60 -f 30

# Via Profile → Config page
# Set "Tech Frequency Limit" to 30
```

---

### Parameter Interaction

The three parameters work together in this order:

```
1. Score all correlation pairs (0-140 points)
2. Filter by THRESHOLD (keep if score ≥ threshold)
3. Apply TECH FREQUENCY limit (max appearances per technique)
4. Sort by score and cap at PER-VENDOR limit
5. Generate final correlations
```

**Example Flow:**
```
1000 possible pairs
  ↓ Threshold (40%)
600 pairs pass quality check
  ↓ Tech Frequency (20)
80 diverse pairs remain
  ↓ Per-Vendor (60)
60 top-scoring correlations outputted
```

---

### Testing Different Configurations

Use the provided CLI script to test different parameter combinations:

```bash
# Test current defaults
python scripts/test_correlation_params.py -t 40 -v 60 -f 20

# Test for maximum coverage
python scripts/test_correlation_params.py -t 30 -v 100 -f 40

# Test for highest quality only
python scripts/test_correlation_params.py -t 60 -v 25 -f 10
```

The script will:
1. Update configuration files
2. Trigger correlation generation
3. Wait for completion
4. Report the number of correlations generated

---

### Recommendations by Use Case

| Use Case | Threshold | Per-Vendor | Tech Freq | Expected Output |
|----------|-----------|------------|-----------|-----------------|
| **Small SOC** | 50% | 25 | 15 | ~20-30 high-quality correlations |
| **Standard Production** ⭐ | 40% | 60 | 20 | ~40-60 balanced correlations |
| **Large SOC** | 40% | 100 | 30 | ~80-110 comprehensive coverage |
| **Testing/Development** | 30% | 100 | 40 | ~100+ maximum coverage |
| **High-Fidelity Alerts** | 60% | 25 | 10 | ~10-20 excellent quality |

---

### Additional Tuning (Advanced)

For advanced users, additional parameters can be modified directly in code:

#### Adjust Chains
```python
# In engine.py
CHAIN_PER_TECHNIQUE = 3  # how many chains one technique can be in
CHAIN_MAX = 20           # chains per vendor
```

#### Adjust Time Window
```python
# In JOIN query generation
| where abs(datetime_diff('minute', Timestamp, Timestamp1)) <= 120  # Change from 60
```

---

## Files & Locations

| Component | File Path |
|-----------|-----------|
| **Correlation Engine** | `archer/ai/genai/engine.py` |
| **Configuration** | `archer/config.py` |
| **Detection Files** | `data/groups/*.yaml` |
| **Correlation Output** | `data/correlate/{group_name}.json` (index) and `data/correlate/{group_name}/<A>_and_<B>[_and_<C>]_<UDM, KQL, SPL or ESQL>.yaml` (one per correlation; three names for a chain) |
| **Full Documentation** | `docs/architecture/CORRELATION_ENGINE.md` |

---

## Quick Commands

```bash
# Generate correlations
python -c "from archer.ai.genai.engine import generate_correlations; \
           generate_correlations('Group Name', 'data/groups')"

# Check correlation output
cat data/correlate/Group_Name.json | jq '.vendor_correlations | length'

# View correlation details
cat data/correlate/Group_Name.json | jq '.vendor_correlations[0]'
```

---

## Key Takeaways

1. **Three Tunable Parameters:** Threshold (40%), Per-Vendor (60), Tech Frequency (20)
2. **Quality Over Quantity:** Default settings balance coverage with quality (~40-60 correlations)
3. **Attack Chain Focus:** Requires valid kill chain progression (+25 pts)
4. **Complexity Limits:** Max 8 techniques, min 2 tactics
5. **JOIN-Based:** Events must be related (same device + account + time)
6. **Tactic-Driven:** Prioritizes critical tactics (Credential Access, Lateral Movement)
7. **Tech Frequency has Biggest Impact:** 10→20 doubled correlations (+100%)

---

**For Full Details:** See [CORRELATION_ENGINE.md](CORRELATION_ENGINE.md)

**Version:** 1.5 (March 4, 2025)
**Parameters:** threshold=40%, per_vendor=60, tech_freq=20
