# Correlation-Only Report Support - Update Complete

## Summary

Updated the Report Generation feature to support **correlation-only reports**. Users can now export Word/PDF reports that contain only correlation rules without any detection rules.

## Update Date
2025-11-12

## What Was Changed

### 1. API Endpoint Enhancement ✓
**File**: `archer/app.py` (lines 6631-6668, 6741-6861)

**Changes**:
- Added `correlation_ids` parameter to export endpoint
- Fetches correlations from `LibraryCorrelation` table
- Supports three export modes:
  1. **Detections only** (existing behavior)
  2. **Correlations only** (new feature)
  3. **Both detections and correlations** (new feature)
- Validates that at least one type is selected

### 2. Frontend JavaScript Update ✓
**File**: `templates/library.html` (lines 1799-1815)

**Changes**:
- Collects selected correlation checkbox IDs
- Sends `correlation_ids` array to API
- Works with existing export modal UI

### 3. Report Generator Updates ✓
**File**: `archer/reports/generator.py`

**Word Document Generator**:
- Dynamic table rows (adjusts to content)
- Shows "Total Correlations" when correlations present
- Custom executive summary for correlation-only reports
- Skips "Detection Rules" section if no detections
- Smart title: "Correlation Rules" for correlation-only exports

**Changes Made**:
- Lines 109-131: Dynamic metadata table
- Lines 128-153: Conditional executive summary
- Lines 163-166: Skip detection section if empty

## Usage

### Via UI (Correlation-Only Export)

1. **Go to Library page**
2. **Select ONLY correlations** (check correlation checkboxes)
3. **Do NOT select any detections** (leave detection checkboxes unchecked)
4. **Click "Export" button**
5. **Select format**:
   - ☑ Word Document (.docx)
   - ☑ PDF Report (.pdf)
6. **Click "Download"**
7. **Report contains only correlations!**

### Via UI (Mixed Export)

1. **Select both detections AND correlations**
2. **Click "Export"**
3. **Select format**
4. **Report contains both sections**

### Report Structure (Correlation-Only)

**When only correlations are selected**:
1. Title: "Correlation Rules Detection Report"
2. Report Information table:
   - Generated date
   - Report Type: "Correlation Rules"
   - **Total Correlations**: 5 (example)
   - Generator: Archer
3. Executive Summary:
   - "This report contains X correlation rules for detecting multi-technique attack patterns..."
4. ~~Detection Rules section~~ (SKIPPED)
5. Correlation Rules section (MAIN CONTENT)
   - Multi-technique correlations
   - Technique lists
   - Severity
   - Time windows
   - Combined queries
6. Appendix

## Examples

### Correlation-Only Report Content

**Executive Summary**:
```
This report contains 5 correlation rules for detecting multi-technique
attack patterns. These correlation rules analyze event sequences across
time windows to identify sophisticated attack chains commonly used by
advanced threat actors.
```

**Report Information**:
```
Generated:          2025-11-12 14:30:00
Report Type:        Correlation Rules
Total Correlations: 5
Generator:          Archer
```

**Sample Correlation**:
```
1. APT29 Multi-Stage Attack Chain

Techniques:    T1566.001, T1059.001, T1003.001
Severity:      Critical
Time Window:   1h
Vendor:        MDE

Correlation Query:
DeviceProcessEvents
| where Timestamp > ago(1h)
| summarize count() by AccountName
| where count_ > 3
```

## Testing

### Test Results
```bash
$ python test_correlation_report.py

✓ Word generator initialized
✓ Generated Word document (37636 bytes)
✓ Saved as test_correlation_report.docx

✓ PDF generator initialized
✓ Generated PDF document (3747 bytes)
✓ Saved as test_correlation_report.pdf

✓ Correlation-only report generation tests passed!
```

**Generated Files**:
- `test_correlation_report.docx` - Word doc with only correlations
- `test_correlation_report.pdf` - PDF with only correlations

## Benefits

### 1. Focused Correlation Analysis
- Export and share only correlation rules
- Cleaner reports for correlation-specific reviews
- Better for advanced threat hunting documentation

### 2. Flexibility
- Three export modes: detections, correlations, or both
- Users choose what to include
- No unnecessary content

### 3. Executive Communication
- Correlation-focused reports for leadership
- Highlight multi-technique detection capabilities
- Emphasize advanced threat coverage

### 4. Use Cases

**Correlation-Only Exports**:
- Sharing correlation strategies with SOC partners
- Documenting multi-technique detection coverage
- Training materials for correlation logic
- Executive briefings on advanced detection

**Mixed Exports**:
- Complete detection coverage reports
- Full capability demonstrations
- Comprehensive threat group analysis

## Technical Details

### API Request Format

**Correlation-Only**:
```json
{
  "ids": [],
  "correlation_ids": [123, 456, 789],
  "format": "docx"
}
```

**Detections-Only**:
```json
{
  "ids": [1, 2, 3],
  "correlation_ids": [],
  "format": "pdf"
}
```

**Mixed**:
```json
{
  "ids": [1, 2, 3],
  "correlation_ids": [123, 456],
  "format": "docx"
}
```

### Response

**Word Document**:
- MIME type: `application/vnd.openxmlformats-officedocument.wordprocessingml.document`
- Filename: `Correlation_Rules_report.docx` (for correlation-only)
- Filename: `{group_name}_report.docx` (for detections or mixed)

**PDF Document**:
- MIME type: `application/pdf`
- Filename: `Correlation_Rules_report.pdf` (for correlation-only)
- Filename: `{group_name}_report.pdf` (for detections or mixed)

## Backward Compatibility

✅ **Fully backward compatible**
- Existing detection-only exports work unchanged
- No breaking changes to API
- UI works with or without correlation selection
- Empty correlation_ids array = detections-only (legacy behavior)

## Files Modified

1. `archer/app.py` - API endpoint logic
2. `templates/library.html` - Frontend JavaScript
3. `archer/reports/generator.py` - Report formatting
4. `test_correlation_report.py` - Test suite (new)
5. `CORRELATION_REPORT_UPDATE.md` - This document (new)

## Summary

The report generation feature now supports **three export modes**:

1. ✅ **Detections only** - Original behavior
2. ✅ **Correlations only** - NEW! Focused correlation reports
3. ✅ **Both** - NEW! Comprehensive coverage

Users can select any combination of detections and correlations in the Library UI, and the generated Word/PDF reports will automatically adapt their content, structure, and executive summary to match the selection.

This enhancement makes Archer's reporting more flexible and targeted for different audiences and use cases.

---

**Update Status**: ✅ Complete
**Testing Status**: ✅ Verified
**Backward Compatibility**: ✅ Maintained
**Production Ready**: ✅ Yes
