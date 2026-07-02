# Correlation Engine Documentation

## Overview

The Archer Correlation Engine automatically generates high-quality detection correlations by analyzing YAML detection files and identifying meaningful attack chain relationships. It uses a sophisticated multi-phase scoring and filtering system to produce actionable, JOIN-based correlation queries.

## Table of Contents

1. [Architecture](#architecture)
2. [Correlation Building Process](#correlation-building-process)
3. [Scoring System](#scoring-system)
4. [Grouping & Merging](#grouping--merging)
5. [JOIN Query Generation](#join-query-generation)
6. [Configuration Parameters](#configuration-parameters)
7. [Results Page — Per-Technique Queries](#results-page--per-technique-queries)
8. [Examples](#examples)

---

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                   Correlation Engine                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  1. File Discovery    → Find detection YAML files            │
│  2. Pairing           → Create all vendor pairs              │
│  3. Scoring           → 6-factor relevance scoring (0-140)   │
│  4. Filtering         → Keep top-scored correlations         │
│  5. Grouping          → Merge by technique pairs             │
│  6. Super-Merging     → Multi-technique correlations         │
│  7. Frequency Limit   → Ensure diversity                     │
│  8. JOIN Generation   → Build actionable queries             │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Key Files

- **`archer/ai/genai/engine.py`** - Main correlation engine
- **`archer/config.py`** - Configuration (GENERATE_DIR, CORRELATE_DIR)
- **`data/correlate/`** - Output directory for correlation JSON files

---

## Correlation Building Process

### Phase 1: File Discovery

**Purpose:** Locate all detection YAML files for the specified group.

**Logic:**
```python
# Find files matching group name pattern
files = glob.glob(f"{GENERATE_DIR}/{group_name}_*.yaml")

# Group by vendor (MDE, Splunk, Elastic, etc.)
by_vendor = group_files_by_vendor(files)
```

**Requirements:**
- ✅ Files must exist in `data/groups/`
- ✅ Files must match group name or contain group tag
- ✅ Must have valid YAML format

---

### Phase 2: Pairing

**Purpose:** Create all possible correlation pairs within each vendor.

**Logic:**
```python
# For each vendor, create all pairs
for vendor in vendors:
    files = vendor_files[vendor]
    for i in range(len(files)):
        for j in range(i+1, len(files)):
            correlations.append({
                "vendor": vendor,
                "a": files[i],
                "b": files[j]
            })
```

**Result:**
- 100 detections → 4,950 possible pairs
- Only same-vendor pairs (cross-vendor disabled)

---

### Phase 3: Scoring (0-140 Points)

**Purpose:** Rank correlations by relevance and quality.

Each correlation receives a score from **0-140 points** based on 6 factors:

#### Factor 1: Technique Criticality (0-30 points)

**Formula:** `min(30, high_impact_count × 15)`

**High-Impact Techniques:**

| Tactic | Techniques |
|--------|------------|
| **Persistence** | T1053, T1136, T1543, T1547, T1037, T1098 |
| **Privilege Escalation** | T1068, T1134, T1078, T1055, T1548 |
| **Defense Evasion** | T1070, T1027, T1562, T1218, T1140 |
| **Credential Access** | T1003, T1110, T1555, T1556, T1558 |
| **Lateral Movement** | T1021, T1091, T1080, T1550 |
| **Collection** | T1005, T1039, T1056, T1074, T1114 |
| **Exfiltration** | T1020, T1041, T1048, T1567 |
| **Impact** | T1485, T1486, T1490, T1491, T1496 |

**Scoring:**
- Each high-impact technique = +15 points
- Maximum 2 techniques counted (30 points max)

**Example:**
```yaml
Correlation: T1003 (Credential Dumping) + T1021 (Remote Services)
Score: 15 + 15 = 30 points ✅
```

---

#### Factor 2: Tactic Priority (0-20 points)

**Formula:** `min(20, sum(tactic_weights))`

**Tactic Weights:**

| Priority | Tactics | Weight |
|----------|---------|--------|
| **Critical** | Credential Access, Lateral Movement, Exfiltration, Impact | 10 pts |
| **High** | Privilege Escalation, Persistence, Command & Control | 8 pts |
| **Medium** | Defense Evasion, Collection, Initial Access | 6 pts |
| **Lower** | Execution, Discovery | 4 pts |
| **Lowest** | Resource Development, Reconnaissance | 3 pts |

**Example:**
```yaml
Tactics: [Credential Access, Lateral Movement]
Score: 10 + 10 = 20 points ✅
```

---

#### Factor 3: Query Specificity (0-20 points)

**Formula:** `avg_specificity × 20`

**Specificity Calculation:**
- **High specificity (0.8-1.0):** Specific IOCs (hashes, IPs, exact commands)
- **Medium specificity (0.5-0.8):** Patterns, API calls, file paths
- **Low specificity (0.0-0.5):** Generic terms only

**Good Indicators:**
```kql
// High specificity
| where SHA256 == "abc123..."
| where ProcessCommandLine contains "mimikatz.exe"
| where RemoteIP == "192.168.1.100"
```

**Bad Indicators:**
```kql
// Low specificity - too generic
| where FileName contains "file"
| where AccountName contains "user"
```

**Scoring:**
- Avg of both queries' specificity scores
- Normalized to 0-20 points

---

#### Factor 4: False Positive Rate - Inverse (0-25 points)

**Formula:** `(1.0 - avg_fp_rate) × 25`

**FP Rate Estimation:**
- **Low FP (0.0-0.3):** Multiple specific conditions, rare indicators
- **Medium FP (0.3-0.6):** Some generic terms, moderate filtering
- **High FP (0.6-1.0):** Mostly generic terms, broad queries

**Example:**
```kql
// Low FP rate (good) = 0.2
| where ProcessCommandLine has_all("mimikatz", "sekurlsa::logonpasswords")
| where InitiatingProcessFileName == "powershell.exe"
Score: (1.0 - 0.2) × 25 = 20 points ✅

// High FP rate (bad) = 0.8
| where FileName contains "exe"
Score: (1.0 - 0.8) × 25 = 5 points ❌
```

---

#### Factor 5: Attack Progression (0-25 points)

**Formula:** `25 points if tactics form valid progression, else 0`

**Valid Progressions (Partial List):**

```
Initial Access → Execution
Initial Access → Persistence
Initial Access → Defense Evasion

Execution → Privilege Escalation ✅
Execution → Defense Evasion
Execution → Credential Access ✅
Execution → Discovery

Privilege Escalation → Credential Access ✅
Credential Access → Lateral Movement ✅ (KEY)
Lateral Movement → Collection ✅
Collection → Exfiltration ✅ (KEY)

Defense Evasion → Persistence
Defense Evasion → Lateral Movement
Persistence → Command & Control
Command & Control → Exfiltration ✅
```

**Example:**
```yaml
Correlation: Credential Access + Lateral Movement
Progression: Valid kill chain step
Score: +25 points ✅
```

**Why This Matters:**
This is the **most important** scoring factor. Correlations that show logical attack progression are far more valuable than random technique pairings.

---

#### Factor 6: Data Source Diversity (-10 to +20 points)

**Scoring:**
- **+20 points:** Multiple different data sources (e.g., DeviceFileEvents + DeviceProcessEvents)
- **0 points:** Same data source for both
- **-10 points:** Redundant/duplicate sources

**Example:**
```yaml
# Good diversity
Query A: DeviceFileEvents (file operations)
Query B: DeviceNetworkEvents (network connections)
Score: +20 points ✅

# No diversity
Query A: DeviceFileEvents
Query B: DeviceFileEvents
Score: 0 points

# Redundant
Query A: DeviceProcessEvents
Query B: DeviceProcessEvents (duplicate)
Score: -10 points ❌
```

---

### Scoring Summary

| Factor | Max Points | Purpose |
|--------|-----------|---------|
| **Technique Criticality** | 30 | Prioritize sophisticated attacks |
| **Tactic Priority** | 20 | Focus on critical attack phases |
| **Query Specificity** | 20 | Reward precise detections |
| **False Positive Rate** | 25 | Penalize noisy queries |
| **Attack Progression** | 25 | Identify kill chain steps |
| **Data Source Diversity** | 20 | Reward multi-source correlations |
| **TOTAL** | **140** | |

**Minimum Threshold:** 75% (105/140 points)

---

## Phase 4: Relevance Filtering

**Purpose:** Keep only high-quality correlations.

**Logic:**
```python
# Calculate relevance score (0-1 scale)
relevance_score = total_score / 140

# Filter by threshold
if relevance_score >= 0.75:  # 75% minimum
    keep_correlation()

# Keep top 25 per vendor
top_25 = sorted_correlations[:25]
```

**Result:**
- Typically reduces from thousands to 25-50 correlations per vendor
- Only high-quality, meaningful correlations proceed

---

## Grouping & Merging

### Phase 5: First-Level Grouping (by Technique Pair)

**Purpose:** Merge correlations with the same technique pair but different data sources.

**Logic:**
```python
# Group by technique pair
for correlation in correlations:
    tech_a = extract_technique(correlation.a)  # "Multi-FactorAuthentication"
    tech_b = extract_technique(correlation.b)  # "AdditionalCloudCredentials"
    pair_key = (tech_a, tech_b)

    grouped[pair_key].append(correlation)

# Merge same-pair correlations
for pair_key, corr_list in grouped.items():
    if len(corr_list) > 1:
        # Merge using UNION
        merged_query_a = " UNION ".join([c.query_a for c in corr_list])
        merged_query_b = " UNION ".join([c.query_b for c in corr_list])
```

**Example:**
```
Before:
- Multi-FactorAuthentication (DeviceFileEvents) → AdditionalCloudCredentials (DeviceEvents)
- Multi-FactorAuthentication (DeviceProcessEvents) → AdditionalCloudCredentials (DeviceEvents)

After:
- Multi-FactorAuthentication (DeviceFileEvents UNION DeviceProcessEvents)
  → AdditionalCloudCredentials (DeviceEvents)
```

**Result:** Reduces from 50 to ~40 unique technique pairs

---

### Phase 6: Super-Merging (Multi-Technique Correlations)

**Purpose:** Create comprehensive correlations where one technique correlates with multiple others.

**Logic:**
```python
# Group by primary technique
for correlation in correlations:
    primary = extract_technique(correlation.a)
    secondary = extract_technique(correlation.b)

    grouped_by_primary[primary][secondary].append(correlation)

# Merge if one technique has multiple targets
for primary, secondaries in grouped_by_primary.items():
    if len(secondaries) > 1:
        # Multi-FactorAuthentication → (B, C, D, E...)
        merge_into_single_correlation()
```

**NEW LIMITS (Critical Quality Controls):**

#### Limit 1: Maximum 8 Techniques
**Why:** Prevents overly complex correlations that overwhelm analysts.

**Before Limit:**
```yaml
Correlation: 20 techniques merged
Problem: Too complex, difficult to investigate
```

**After Limit:**
```yaml
Correlation: 8 techniques maximum
Benefit: Focused, actionable correlation
```

#### Limit 2: Minimum 2 Tactics
**Why:** Ensures correlation spans multiple attack phases (actual attack chain).

**Before Limit:**
```yaml
Techniques: 8 techniques, all from "Execution" tactic
Problem: Not showing attack progression
```

**After Limit:**
```yaml
Techniques: 8 techniques from "Credential Access" + "Lateral Movement"
Benefit: Shows kill chain progression ✅
```

**Selection Algorithm:**
```python
techniques_involved = set()
tactics_involved = set()

for correlation in all_correlations:
    temp_techniques = techniques_involved + correlation.techniques
    temp_tactics = tactics_involved + correlation.tactics

    # Add if under limits OR need more tactics
    if len(temp_techniques) <= 8 or len(tactics_involved) < 2:
        techniques_involved = temp_techniques
        tactics_involved = temp_tactics
        selected_correlations.append(correlation)

    # Stop when limits reached
    if len(techniques_involved) >= 8 and len(tactics_involved) >= 2:
        break
```

**Example:**
```
Before Super-Merging: 42 correlations
- Multi-FactorAuthentication → AdditionalCloudCredentials
- Multi-FactorAuthentication → CreateProcessWithToken
- Multi-FactorAuthentication → PassTheHash
- ... (19 more with Multi-FactorAuthentication)

After Super-Merging: 1 correlation
- Multi-FactorAuthentication → (AdditionalCloudCredentials OR CreateProcessWithToken OR PassTheHash OR ... up to 8 techniques, 2+ tactics)
```

**Result:** Reduces from ~40 to 3-10 comprehensive correlations

---

### Phase 7: Frequency Limiting

**Purpose:** Ensure technique diversity across correlations.

**Logic:**
```python
technique_count = {}

for correlation in correlations:
    techniques = extract_all_techniques(correlation)

    # Check frequency
    max_occurrences = max([technique_count.get(t, 0) for t in techniques])

    # Keep if under limit
    if max_occurrences < 3:
        keep_correlation()

        # Update counts
        for technique in techniques:
            technique_count[technique] += 1
```

**Limit:** Each technique can appear in maximum **3 correlations**

**Why:** Prevents a single high-value technique (e.g., T1003 - Credential Dumping) from dominating the entire correlation set.

---

## JOIN Query Generation

### Phase 8: BUILD JOIN-Based Correlation Queries

**Purpose:** Create actionable queries that chain events by device and account context.

**Why JOIN vs UNION:**

| Aspect | UNION (Old) | JOIN (New) |
|--------|------------|-----------|
| **Result** | All events matching any technique | Only related events |
| **Relationship** | No connection required | Must be on same device/account |
| **False Positives** | High - unrelated events | Low - proven relationship |
| **Performance** | Returns more data | Returns less data |
| **Analyst Value** | Manual correlation needed | Pre-correlated results |

**JOIN Query Structure:**

```kql
// Step 1: Define each table's indicators with technique attribution
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
  (AdditionalFields has_all("gcloud", "iam", "service-accounts")) or
  // SID-HistoryInjection
  (AdditionalFields contains "MISC::AddSid")
| project Timestamp, DeviceName, AccountName, *;

// Step 2: Chain events by DeviceName and AccountName
DeviceFileEvents_CredentialAccess
| join kind=inner (
    DeviceEvents_CredentialAccess
) on DeviceName, AccountName
| where abs(datetime_diff('minute', Timestamp, Timestamp1)) <= 60
| project *
```

**Key Features:**

1. **Technique Attribution:**
   ```kql
   // TECHNIQUE_NAME
   (condition)
   ```
   - Shows which indicators belong to which technique
   - Helps analysts understand what they're seeing

2. **Account Field Mapping:**
   ```python
   DeviceFileEvents → InitiatingProcessAccountName
   DeviceProcessEvents → AccountName
   DeviceEvents → AccountName
   DeviceNetworkEvents → InitiatingProcessAccountName
   ```
   - Automatically selects correct field per table

3. **Time Window:**
   ```kql
   | where abs(datetime_diff('minute', Timestamp, Timestamp1)) <= 60
   ```
   - Events must occur within 60 minutes of each other

4. **JOIN Type:**
   ```kql
   | join kind=inner
   ```
   - Only returns events that match on both sides
   - Proves causality/relationship

---

## Configuration Parameters

### Tunable Parameters ⚙️

These three parameters can be adjusted via **Profile → Config** in the web UI or via the CLI script.

| Parameter | Default | Location | Purpose | Tunable? |
|-----------|---------|----------|---------|----------|
| **Min Relevance Score (Threshold)** | **40%** (56/140) | `config.py` + `engine.py` | Quality threshold | ✅ **YES** |
| **Max Correlations/Vendor** | **60** | `engine.py` function parameter | Prevent overload | ✅ **YES** |
| **Tech Frequency Limit** | **20** | `_apply_correlation_grouping()` | Ensure diversity | ✅ **YES** |

**See:** [Correlation Quick Reference](../reference/CORRELATION_QUICK_REFERENCE.md) for detailed tuning guide.

### Fixed Parameters

| Parameter | Value | Location | Purpose |
|-----------|-------|----------|---------|
| **Max Techniques/Correlation** | 8 | Super-merging logic | Prevent complexity |
| **Min Tactics/Correlation** | 2 | Super-merging logic | Ensure cross-phase |
| **JOIN Time Window** | 60 minutes | JOIN query generation | Event correlation window |
| **Super-Merge Skip Threshold** | >10 targets | `_apply_correlation_grouping()` | Prevent massive correlations |

### Scoring Weights

| Factor | Weight | Adjustable? |
|--------|--------|-------------|
| Technique Criticality | 15 pts/technique | Yes - Edit `_HIGH_IMPACT_TECHNIQUES` |
| Tactic Priority | 3-10 pts/tactic | Yes - Edit `_TACTIC_PRIORITY` |
| Attack Progression | 25 pts | Yes - Edit `_ATTACK_PROGRESSIONS` |
| FP Rate Penalty | 0-25 pts | Yes - Adjust multiplier |
| Query Specificity | 0-20 pts | Yes - Adjust multiplier |
| Data Source Diversity | -10 to +20 pts | Yes - Edit `_score_data_source_diversity()` |

---

## Examples

### Example 1: High-Quality Correlation

**Input:**
```yaml
Detection A:
  Technique: T1003 (Credential Dumping)
  Tactic: Credential Access
  Query: | where ProcessCommandLine contains "mimikatz.exe"

Detection B:
  Technique: T1021 (Remote Services)
  Tactic: Lateral Movement
  Query: | where RemoteIP != "" and AccountName != ""
```

**Scoring:**
```
✅ Technique Criticality: 30 pts (T1003 + T1021 both high-impact)
✅ Tactic Priority: 20 pts (Credential Access=10 + Lateral Movement=10)
✅ Query Specificity: 16 pts (specific commands)
✅ False Positive Rate: 20 pts (low FP rate)
✅ Attack Progression: 25 pts (Credential Access → Lateral Movement is valid progression)
✅ Data Source Diversity: 15 pts (different sources)
──────────────────────────────
TOTAL: 126/140 = 90% ✅ KEPT
```

**Generated Query:**
```kql
let DeviceProcessEvents_CredentialAccess = DeviceProcessEvents
| where Timestamp > ago(1h)
| where
  // T1003 - Credential Dumping
  (ProcessCommandLine contains "mimikatz.exe")
| project Timestamp, DeviceName, AccountName, *;

let DeviceNetworkEvents_LateralMovement = DeviceNetworkEvents
| where Timestamp > ago(1h)
| where
  // T1021 - Remote Services
  (RemoteIP != "" and InitiatingProcessAccountName != "")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, *;

DeviceProcessEvents_CredentialAccess
| join kind=inner (
    DeviceNetworkEvents_LateralMovement
) on DeviceName, AccountName
| where abs(datetime_diff('minute', Timestamp, Timestamp1)) <= 60
| project *
```

---

### Example 2: Low-Quality Correlation (Filtered Out)

**Input:**
```yaml
Detection A:
  Technique: T1059 (Command-Line Interface)
  Tactic: Execution
  Query: | where FileName contains "exe"

Detection B:
  Technique: T1082 (System Information Discovery)
  Tactic: Discovery
  Query: | where ProcessCommandLine contains "systeminfo"
```

**Scoring:**
```
❌ Technique Criticality: 0 pts (neither is high-impact)
❌ Tactic Priority: 8 pts (Execution=4 + Discovery=4)
❌ Query Specificity: 8 pts (too generic)
❌ False Positive Rate: 5 pts (high FP rate)
❌ Attack Progression: 25 pts (Execution → Discovery is valid)
❌ Data Source Diversity: 0 pts (same source)
──────────────────────────────
TOTAL: 46/140 = 33% ❌ FILTERED OUT
```

**Reason for Rejection:** Below 75% threshold due to generic queries and low-impact techniques.

---

### Example 3: Super-Merged Correlation

**Before Super-Merging:**
```
1. Multi-FactorAuthentication → AdditionalCloudCredentials (score: 95%)
2. Multi-FactorAuthentication → CreateProcessWithToken (score: 92%)
3. Multi-FactorAuthentication → PassTheHash (score: 90%)
4. Multi-FactorAuthentication → SID-HistoryInjection (score: 88%)
... (15 more)
```

**After Super-Merging:**
```yaml
Merged Correlation:
  Primary: Multi-FactorAuthentication
  Secondaries:
    - AdditionalCloudCredentials
    - CreateProcessWithToken
    - PassTheHash
    - SID-HistoryInjection
    - (4 more - limited to 8 total techniques)

  Tactics: Credential Access, Persistence (2 tactics ✅)
  Techniques: 8 techniques ✅

  Query: JOIN-based with technique comments for each indicator
```

---

## Output Format

### Correlation JSON Structure

```json
{
  "vendor_correlations": [
    {
      "vendor": "mde",
      "a": "data/groups/Multi-FactorAuthentication_DeviceFileEvents.yaml",
      "b": "data/groups/AdditionalCloudCredentials_DeviceEvents.yaml",
      "query_a": "DeviceFileEvents | where ...",
      "query_b": "DeviceEvents | where ...",
      "combined_query": "let DeviceFileEvents_... JOIN ...",
      "relevance_score": 0.92,
      "techniques_involved": [
        "Multi-FactorAuthentication",
        "AdditionalCloudCredentials",
        "CreateProcessWithToken",
        "PassTheHash",
        "SID-HistoryInjection",
        "AccessTokenManipulation",
        "PowerShell",
        "BypassUserAccountControl"
      ]
    }
  ],
  "cross_vendor_correlations": []
}
```

### UI Display

Correlations are displayed in the web UI with:

1. **Technique Flow** - Color-coded by tactic:
   ```
   [Multi-Factor Authentication] → [Additional Cloud Credentials]
   (Yellow background = Credential Access tactic)
   ```

2. **Metadata:**
   - Relevance Score: 92%
   - Time Window: 1h
   - Tactics: Credential Access, Persistence

3. **Techniques Involved:** (For super-merged correlations)
   - Shows all 8 techniques as colored badges
   - Color indicates attack phase (early/mid/late/final)

4. **Combined Query:** Expandable JOIN-based query with technique comments

---

## Troubleshooting

### Issue: No Correlations Generated

**Possible Causes:**
1. No detection files in `data/groups/`
2. Detection quality too low (all below 75% threshold)
3. No valid technique pairs found
4. Group name mismatch

**Solution:**
```bash
# Check for detection files
ls data/groups/

# Check correlation debug output
# Look for "Kept X/Y after relevance filtering"
# If 0 kept, queries need improvement
```

---

### Issue: Too Few Correlations

**Possible Causes:**
1. Threshold too high (75% is strict)
2. Limited technique variety
3. Frequency limiting removing correlations

**Solution:**
```python
# Temporarily lower threshold for testing
min_relevance = 0.65  # 65% instead of 75%

# Increase max per vendor
max_per_vendor = 50  # Instead of 25
```

---

### Issue: Correlations Too Complex

**Symptoms:**
- Correlations with 15+ techniques
- Multiple unrelated tactics
- Difficult to investigate

**Solution:**
Already fixed! New limits ensure:
- Max 8 techniques per correlation
- Minimum 2 tactics (ensures focus)

---

## Best Practices

### For Detection Authors

1. **Use Specific Indicators:**
   ```kql
   ✅ GOOD: | where SHA256 == "abc123..." or ProcessCommandLine contains "mimikatz"
   ❌ BAD: | where FileName contains "exe"
   ```

2. **Tag Tactics Correctly:**
   ```yaml
   tactics:
     - Credential Access  # Primary tactic first
     - Privilege Escalation
   ```

3. **Include Technique IDs:**
   ```yaml
   technique_id: T1003.001
   ```

### For Analysts

1. **Review Relevance Scores:**
   - 90%+ = Very high confidence
   - 75-90% = Good quality
   - <75% = Filtered out

2. **Check Techniques Involved:**
   - Look for attack progression
   - Verify tactics span kill chain

3. **Test Queries:**
   - JOIN queries require events on same device/account
   - 60-minute window is configurable
   - Adjust time window if needed for your environment

---

## Future Enhancements

### Planned Improvements

1. **Machine Learning Scoring:**
   - Train model on analyst feedback
   - Adaptive threshold based on environment

2. **Cross-vendor Correlations:**
   - Currently disabled
   - Future: Correlate MDE + Splunk + Elastic

3. **Configurable Limits:**
   - Make 8-technique limit adjustable
   - Tactic minimum configurable per use case

4. **Query Optimization:**
   - Automatic index selection
   - Performance hints for large environments

---

---

## Results Page — Per-Technique Queries

When correlations are displayed on the results page (`/results`), each correlation now surfaces **individual detection queries per technique** in addition to the combined JOIN query.

### What Is Shown

For each correlation, the results page renders:

1. **Attack flow diagram** — tactic boxes connected by arrows (e.g., `PERSISTENCE → PRIVILEGE ESCALATION → DEFENSE EVASION`)
2. **Per-technique query blocks** — one code block per technique, stacked vertically with "chained with" connectors
3. **Combined JOIN query** — the full chained correlation rule, collapsible below the individual queries

### Per-Technique Query Block Structure

```
┌─────────────────────────────────────────────────────────┐
│ Technique Name   T1078.004   Initial Access         📋  │
├─────────────────────────────────────────────────────────┤
│ DeviceSignInLogs                                        │
│ | where Application == "Office 365"                     │
│ | where ConditionalAccessStatus == "failure"            │
└─────────────────────────────────────────────────────────┘
              ── chained with ──
┌─────────────────────────────────────────────────────────┐
│ Lateral Movement   T1021.001   Remote Services      📋  │
├─────────────────────────────────────────────────────────┤
│ DeviceNetworkEvents                                     │
│ | where RemotePort == 3389                              │
│ | where InitiatingProcessCommandLine contains ...       │
└─────────────────────────────────────────────────────────┘
```

Each block shows:
- **Technique name** (from the YAML `name` field)
- **ATT&CK ID** (e.g., `T1078.004`) as a blue pill
- **Tactic** (e.g., `Initial Access`) as a green pill
- **📋 Copy** — copies the individual query to clipboard

After all individual blocks, **Show Combined Query** expands the full JOIN query.

### Correlation Result Object Fields

The correlation result dict passed to the template includes the following fields relevant to query display:

| Field | Type | Description |
|-------|------|-------------|
| `individual_queries` | `List[Dict]` | One entry per technique: `{technique_name, technique_id, tactic, query}` |
| `combined_query` | `str` | Full JOIN query combining all techniques |
| `techniques_by_tactic` | `Dict[str, List[str]]` | Techniques grouped by kill-chain tactic |
| `primary_tactics` | `List[str]` | Tactics directly involved in the correlation pair |
| `attack_chain_length` | `int` | Number of distinct tactics in the correlation |
| `tables_indexes` | `List[str]` | Data sources referenced (MDE tables or Splunk indexes) |
| `relevance_score` | `int` | Correlation quality score (0–100%) |
| `time_window` | `str` | JOIN time window (e.g., `"1h"`) |

### Saved Correlations

The `individual_queries` field is preserved when correlations are saved to the library (`/api/library/save`) and restored when loading saved detections from the database. Legacy saved correlations (created before this feature) will have `individual_queries: []` — only the combined query will show for those.

---

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- KQL Reference: https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/
- Splunk Search Reference: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-10-31 | Initial documentation |
| 1.1 | 2024-10-31 | Added 8-technique limit, 2-tactic minimum |
| 1.2 | 2024-10-31 | JOIN-based query generation |
| 1.3 | 2024-10-31 | Tactic-based color coding in UI |
| 1.4 | 2025-03-04 | Per-technique query blocks on results page |

---

**Last Updated:** March 4, 2025
**Author:** Archer Development Team
**Location:** `docs/CORRELATION_ENGINE.md`
