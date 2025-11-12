# Report Generation Documentation

This directory contains comprehensive documentation for the report generation feature.

## Documentation Files

### `REPORT_GENERATION_COMPLETE.md`
Complete implementation documentation for Word/PDF report generation.

**Contents**:
- Feature overview and summary
- Implementation details
- Architecture diagrams
- Usage examples (UI and programmatic)
- Report structure and formatting
- Files created/modified
- Dependencies and installation
- Testing instructions
- Use cases
- Performance characteristics
- Troubleshooting guide

### `CORRELATION_REPORT_UPDATE.md`
Documentation for correlation-only report support.

**Contents**:
- Correlation-only export feature
- API endpoint changes
- Frontend updates
- Report structure adaptations
- Usage examples
- Testing results
- Use cases for correlation-focused reports
- Technical details
- Backward compatibility notes

## Quick Links

### User Documentation
- **How to Export Reports**: See `REPORT_GENERATION_COMPLETE.md` → Usage Examples
- **Correlation Reports**: See `CORRELATION_REPORT_UPDATE.md` → Usage
- **Supported Formats**: Word (.docx), PDF, HTML

### Developer Documentation
- **API Endpoint**: `REPORT_GENERATION_COMPLETE.md` → API Integration
- **Report Generators**: `REPORT_GENERATION_COMPLETE.md` → Architecture
- **Extending Formats**: `REPORT_GENERATION_COMPLETE.md` → Future Enhancements

## Feature Overview

The Report Generation feature allows users to export detection libraries as professional documents:

- **Word Documents** (.docx) - Full formatting, tables, professional layout
- **PDF Reports** (.pdf) - Print-ready, portable format
- **HTML Reports** (.html) - Web preview, browser printing

### Export Modes

1. **Detections Only** - Traditional detection rule reports
2. **Correlations Only** - Focused correlation analysis reports
3. **Mixed** - Comprehensive reports with both detections and correlations

## Quick Start

### For Users

1. Go to Library page
2. Select detections/correlations to export
3. Click "Export" button
4. Choose format (Word, PDF, HTML)
5. Click "Download"

See `REPORT_GENERATION_COMPLETE.md` for detailed instructions.

### For Developers

```python
from archer.reports.generator import WordReportGenerator

generator = WordReportGenerator()
report_bytes = generator.generate(
    group_name="APT29",
    detections=detections_list,
    correlations=correlations_list
)
```

See documentation files for complete API reference.

## Dependencies

- `python-docx==1.1.2` - Word document generation
- `reportlab==4.2.5` - PDF generation

```bash
pip install python-docx reportlab
```

## Examples

Example reports are available in `examples/reports/`:
- `test_report.docx` - Sample Word document
- `test_report.pdf` - Sample PDF
- `test_report.html` - Sample HTML
- `test_correlation_report.docx` - Correlation-only Word document
- `test_correlation_report.pdf` - Correlation-only PDF

## Support

For issues or questions:
1. Check the troubleshooting section in `REPORT_GENERATION_COMPLETE.md`
2. Review test files in `tests/reports/`
3. Examine example outputs in `examples/reports/`
4. Report issues at https://github.com/anthropics/archer/issues

## Version History

- **2025-11-12**: Correlation-only report support added
- **2025-11-12**: Initial Word/PDF/HTML report generation implemented
