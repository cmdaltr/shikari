# Platform Validation Issue Analysis

## Problem Statement

Multi-factor Authentication (MFA) techniques are generating detections for platforms where the indicator cannot actually be detected.

**Example**: An MFA indicator that can only be detected on Windows hosts is generating queries for Linux, macOS, Azure, etc.

## Root Cause Analysis

### Current Behavior

1. **Technique-Level Platforms** (Correct):
   - T1621 (MFA Request Generation): Windows, Linux, macOS, IaaS, SaaS, Office Suite, Identity Provider
   - T1556.006 (MFA): Windows, SaaS, IaaS, Linux, macOS, Office Suite, Identity Provider
   - These correctly reflect that MFA attacks CAN occur on multiple platforms

2. **Platform Validation** (Working):
   - Located in `detections.py:272-294` (`is_query_applicable()`)
   - Validates that procedure platforms match index platforms
   - Uses platform mappings from `queries.py`

3. **The Gap** (Problem):
   - **Indicator-level platform specificity is not captured**
   - An indicator like "Windows Security Event 4776" is Windows-specific
   - But if the technique supports multiple platforms, queries are generated for all platforms
   - The validation only checks if procedure platforms overlap with index platforms
   - It doesn't check if the SPECIFIC INDICATOR being used is valid for that index

### Example Scenario

**Technique**: T1556.006 (Multi-Factor Authentication)
- **Technique Platforms**: Windows, SaaS, IaaS, Linux, macOS, Office Suite, Identity Provider
- **Indicator**: "Windows Security Event 4776 - Credential Validation"
- **Indicator Platform**: Windows ONLY

**Current Behavior**:
1. System checks: Does T1556.006 apply to Azure (SaaS)? → YES ✅
2. System creates: Azure query for Event 4776
3. **Problem**: Event 4776 doesn't exist in Azure! ❌

**Expected Behavior**:
1. System checks: Does T1556.006 apply to Azure? → YES
2. System checks: Does indicator "Event 4776" apply to Azure? → NO
3. System skips: No query created ✅

## Solution Options

### Option 1: Indicator-Level Platform Mapping (Recommended)

Add platform information to the indicator mappings:

```json
{
  "authentication_events": {
    "Splunk": {
      "windows_security": {
        "index": "index=windows_events",
        "platforms": ["Windows"]
      }
    },
    "MDE": {
      "DeviceLogonEvents": {
        "table": "DeviceLogonEvents",
        "platforms": ["Windows"]
      },
      "AADSignInEventsBeta": {
        "table": "AADSignInEventsBeta",
        "platforms": ["Azure AD", "Office 365", "SaaS"]
      }
    }
  }
}
```

Then update `is_query_applicable()` to check both:
1. Procedure platforms vs Index platforms (current)
2. Indicator platforms vs Index platforms (new)

### Option 2: Enhanced Detection Guidance

Enhance the detection guidance in MITRE data with platform-specific indicators:

```python
detect_guidance = {
    "Windows": ["Event ID 4776", "Event ID 4768"],
    "Linux": ["/var/log/auth.log PAM events"],
    "Azure AD": ["Sign-in logs MFA events"]
}
```

### Option 3: Post-Generation Filtering

Add a validation step after query generation that:
1. Analyzes the generated query
2. Checks if referenced fields/events exist in the target platform
3. Removes invalid queries

## Recommended Approach

**Immediate**: Option 1 (Indicator-Level Platform Mapping)
- Most accurate and maintainable
- Prevents invalid queries from being generated
- Works with existing architecture

**Long-term**: Combination of Options 1 and 2
- Use Option 1 for mappings
- Enhance MITRE data extraction to capture platform-specific detection methods
- Provides both automated and manual control

## Files Requiring Changes

1. **`archer/mappings/indicators.json`**
   - Add `platforms` field to each index/table mapping
   - Example: `{"index": "windows_events", "platforms": ["Windows"]}`

2. **`archer/build/detections.py`**
   - Update `is_query_applicable()` to accept indicator platforms
   - Add indicator platform validation logic
   - Pass indicator platforms from mappings

3. **`archer/build/queries.py`**
   - Update `get_platforms_for_index()` to handle new format
   - Add `get_platforms_for_indicator()` function

## Detection Count Impact

**Current**: 244 detection files for Scattered Spider
**After Fix**: Likely 150-180 detection files (estimate)

The reduction represents removal of invalid cross-platform detections where:
- Indicator is platform-specific
- Technique is multi-platform
- Query was incorrectly generated for non-applicable platforms

## Next Steps

1. Review indicator mappings to identify platform-specific indicators
2. Update mapping format to include platform information
3. Modify validation logic to check indicator platforms
4. Test with Scattered Spider group
5. Document platform assignment guidelines

## References

- Current validation: `detections.py:272-294`
- Platform mappings: `queries.py:get_platforms_for_index()`
- Indicator mappings: `mappings/indicators.json`
