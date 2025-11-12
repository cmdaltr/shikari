# Report Generation Tests

This directory contains test scripts for the report generation functionality.

## Test Files

### `test_report_generation.py`
Tests basic report generation for all three formats (Word, PDF, HTML).

**Usage**:
```bash
python tests/reports/test_report_generation.py
```

**Tests**:
- Word document generation
- PDF report generation
- HTML report generation
- File output verification

**Output**: Creates example reports in `examples/reports/`

### `test_correlation_report.py`
Tests correlation-only report generation.

**Usage**:
```bash
python tests/reports/test_correlation_report.py
```

**Tests**:
- Correlation-only Word reports
- Correlation-only PDF reports
- Empty detection list handling
- Dynamic content adaptation

**Output**: Creates correlation-focused reports in `examples/reports/`

## Running Tests

### Run All Report Tests
```bash
# From project root
python tests/reports/test_report_generation.py
python tests/reports/test_correlation_report.py
```

### Requirements
```bash
pip install python-docx reportlab
```

## Expected Results

All tests should pass with output similar to:
```
✓ Word generator initialized
✓ Generated Word document (37816 bytes)
✓ Saved as test_report.docx
✓ PDF generator initialized
✓ Generated PDF document (3689 bytes)
✓ Saved as test_report.pdf
✓ All report generation tests passed!
```

## Test Coverage

- ✅ Word document generation
- ✅ PDF report generation
- ✅ HTML report generation
- ✅ Detection-only reports
- ✅ Correlation-only reports
- ✅ Mixed reports (detections + correlations)
- ✅ Metadata handling
- ✅ File format validation
- ✅ Content adaptation
- ✅ Error handling

## Notes

- Generated example files are saved to `examples/reports/`
- Tests use sample data, not real database content
- All formats are tested with identical data for consistency
- Tests verify byte count to ensure files are generated properly
