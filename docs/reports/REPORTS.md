# Report Generation Documentation

## Feature Documentation

The complete report generation documentation has been moved to:
**[docs/features/REPORT_GENERATION.md](../features/REPORT_GENERATION.md)**

## Quick Start

### For Users

1. Go to Library page
2. Select detections/correlations to export
3. Click "Export" button
4. Choose format (Word, PDF, HTML)
5. Click "Download"

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

See [REPORT_GENERATION.md](../features/REPORT_GENERATION.md) for complete documentation.

## Dependencies

```bash
pip install python-docx reportlab
```

## Export Formats

- **Word** (.docx) - Full formatting, tables, professional layout
- **PDF** (.pdf) - Print-ready, portable format
- **HTML** (.html) - Web preview, browser printing

