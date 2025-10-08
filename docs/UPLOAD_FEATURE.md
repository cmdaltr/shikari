# File Upload Feature Documentation

## Overview

The Archer application has been enhanced with a new file upload feature that allows users to upload threat intelligence files for automatic TTP (Tactics, Techniques, and Procedures) and IOC (Indicators of Compromise) extraction using GenAI.

## Features

### 1. VirusTotal-Inspired Tabbed Interface

The homepage now features a modern tabbed interface with three main options:

#### **Generate** Tab
- Generate detection queries based on MITRE ATT&CK threat intelligence
- Enter threat group names (e.g., APT29, Scattered Spider)
- Advanced options for correlation, semantic analysis, and AI-powered enhancements
- VECTR integration for hunt tracking

#### **Upload** Tab
- Upload threat intelligence files for TTP/IOC extraction
- Supported formats:
  - **PDF** - Threat intelligence reports
  - **TXT/MD** - Plain text or Markdown reports
  - **JSON** - STIX, MISP, or custom formats
  - **CSV** - IOC lists
  - **YARA** - YARA rules
- Drag-and-drop file upload
- Optional OpenAI enhancement for better extraction
- Auto-generate detection queries from extracted data

#### **Emulate** Tab
- Execute adversary emulation tests using Atomic Red Team
- Simulate or live execution modes
- Remote execution capabilities
- Automatic detection enrichment

### 2. GenAI-Powered File Intelligence Parser

#### Module: `archer/parsers/file_intelligence.py`

**Features:**
- Automatic file type detection
- Text extraction from multiple formats
- Regex-based TTP/IOC extraction
- Optional AI-enhanced extraction using OpenAI or local LLM

**Extraction Capabilities:**
- **TTPs**: MITRE ATT&CK technique IDs (T1234, T1234.001)
- **IOCs**:
  - Commands/command-line patterns
  - Registry keys and values
  - Event IDs
  - Software/process names
  - IP addresses
  - Domain names
  - File hashes (MD5, SHA1, SHA256)
  - File paths

**Usage Example:**
```python
from archer.parsers.file_intelligence import parse_intelligence_file

# Parse a file
result = parse_intelligence_file(
    file_path="threat_report.pdf",
    use_openai=True  # Optional AI enhancement
)

# Access extracted data
ttps = result["ttps"]  # ["T1059.001", "T1003", ...]
iocs = result["iocs"]  # {cmd: [...], reg: [...], ...}
```

### 3. File Upload API Endpoint

#### Endpoint: `POST /upload`

**Parameters:**
- `file` (required): Uploaded file
- `use_openai` (optional): Enable OpenAI enhancement
- `auto_generate` (optional): Automatically generate detection queries
- `run_correlation` (optional): Run correlation on generated queries

**Response:**
```json
{
  "success": true,
  "redirect": "/progress?group_name=Upload_report_abc123",
  "ttps_found": 5,
  "iocs_found": 23
}
```

**Workflow:**
1. File is uploaded and content is read
2. File intelligence parser extracts TTPs and IOCs
3. If auto-generate is enabled:
   - Create synthetic group name for tracking
   - Build manual data structure with techniques and indicators
   - Generate detection queries in background
   - Redirect to progress page
4. Extraction results saved to `data/uploads/` for reference

## UI Design

### Tabbed Interface

**Styling:**
- Clean, modern design inspired by VirusTotal
- Smooth tab transitions with fade-in animations
- Responsive layout for mobile devices
- Consistent color scheme (#007bff primary color)

**CSS Files:**
- `static/css/tabs.css` - Tabbed interface styles
- `static/css/style.css` - Existing application styles

**JavaScript:**
- `static/js/tabs.js` - Tab switching and file upload handling
- Drag-and-drop file upload
- Form validation
- AJAX form submissions

### Upload Area Features

- Drag-and-drop support
- Visual feedback on drag hover
- File type validation
- File size indication
- Clear file selection button

## Configuration

### OpenAI Enhancement (Optional)

To enable AI-enhanced extraction, set environment variable:
```bash
export OPENAI_API_KEY=your-api-key-here
```

The parser will automatically use OpenAI's GPT-4o-mini model for:
- Semantic TTP extraction
- Command-line pattern identification
- Software/process name extraction

### Supported File Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| PDF | `.pdf` | Threat intelligence reports (requires PyPDF2) |
| Text | `.txt`, `.md` | Plain text or Markdown reports |
| JSON | `.json` | STIX, MISP, or custom threat intel formats |
| CSV | `.csv` | IOC lists and structured data |
| YARA | `.yar`, `.yara` | YARA rules for malware detection |

## Installation

### Required Dependencies

Add to `requirements.txt`:
```
PyPDF2  # For PDF parsing
```

Install:
```bash
pip install PyPDF2
```

### Optional Dependencies

For AI enhancement:
```bash
pip install openai
```

For local LLM support:
```bash
pip install llama-cpp-python
```

## Usage Examples

### Example 1: Upload PDF Report

1. Navigate to homepage
2. Click **Upload** tab
3. Drag-and-drop PDF file or click "Select File"
4. Enable "OpenAI Enhancement" (optional)
5. Ensure "Auto-Generate Queries" is checked
6. Click "Upload & Process"
7. View progress and results

### Example 2: Extract IOCs from JSON

1. Upload STIX or MISP JSON file
2. Disable "Auto-Generate Queries" if you only want extraction
3. Click "Upload & Process"
4. Receive JSON response with extracted TTPs and IOCs

### Example 3: Upload Text Report

1. Upload `.txt` or `.md` file
2. Enable both "OpenAI Enhancement" and "Run Correlation"
3. System extracts TTPs, generates queries, and correlates them
4. View comprehensive detection coverage

## Data Flow

```
File Upload
    ↓
File Intelligence Parser
    ├── Extract text (PDF/TXT/JSON/CSV)
    ├── Regex TTP/IOC extraction
    └── Optional: AI-enhanced extraction
    ↓
Manual Data Structure
    ├── Techniques (from extracted TTPs)
    └── Identifiers (from extracted IOCs)
    ↓
Detection Generation
    ├── Build queries (MDE/Splunk)
    └── Optional: Correlation
    ↓
Results & Progress
```

## File Storage

### Uploaded File Data

Extraction results are saved to:
```
data/uploads/Upload_{filename}_{hash}_extraction.json
```

Contains:
- Original filename
- Extracted TTPs
- Extracted IOCs
- Generated manual data structure

### Generated Detections

Detection queries saved to:
```
data/generate/Upload_{filename}_{hash}_*.yaml
```

## Security Considerations

1. **File Size Limits**: Consider adding file size limits in production
2. **File Type Validation**: Only accept whitelisted file extensions
3. **Malware Scanning**: Consider integrating malware scanning for uploaded files
4. **Rate Limiting**: Implement rate limiting on upload endpoint
5. **API Key Security**: Keep OPENAI_API_KEY secure and never commit to version control

## Future Enhancements

- [ ] Support for more file formats (DOCX, XLSX)
- [ ] Batch file upload
- [ ] Upload history and management UI
- [ ] File preview before processing
- [ ] Custom extraction templates
- [ ] Integration with threat intelligence platforms
- [ ] OCR support for scanned PDFs
- [ ] Multi-language support

## Troubleshooting

### Common Issues

**Issue**: PDF extraction returns empty text
- **Solution**: Install PyPDF2: `pip install PyPDF2`

**Issue**: OpenAI enhancement not working
- **Solution**: Ensure OPENAI_API_KEY is set: `export OPENAI_API_KEY=your-key`

**Issue**: No TTPs extracted
- **Solution**: Ensure file contains MITRE ATT&CK technique IDs (e.g., T1059.001)

**Issue**: File upload fails
- **Solution**: Check file size and format are supported

## Testing

### Manual Testing

1. Test each supported file format
2. Test drag-and-drop functionality
3. Test with and without OpenAI enhancement
4. Test auto-generate on/off
5. Verify extraction accuracy
6. Check progress page updates

### Unit Testing

See `tests/test_file_intelligence.py` for comprehensive tests (to be created).

## API Reference

### parse_intelligence_file()

```python
def parse_intelligence_file(
    file_path: str = None,
    file_content: bytes = None,
    use_openai: bool = False,
    use_local_llm: bool = False
) -> Dict[str, Any]
```

**Returns:**
```python
{
    "ttps": ["T1059.001", "T1003"],
    "iocs": {
        "cmd": ["powershell.exe", "cmd.exe /c"],
        "reg": ["HKEY_LOCAL_MACHINE\\..."],
        "evt": ["4688", "4624"],
        "sw": ["mimikatz", "rundll32"],
        "ip": ["192.168.1.1"],
        "domain": ["evil.com"],
        "hash": ["abc123..."],
        "file": ["C:\\malware.exe"]
    },
    "raw_text": "Extracted text content...",
    "metadata": {
        "file_type": "pdf",
        "file_name": "report.pdf"
    }
}
```

## Migration Notes

### Upgrading from Old Interface

The old single-form interface has been backed up to:
```
templates/index_old.html
```

To revert to the old interface:
```bash
mv templates/index.html templates/index_tabbed.html
mv templates/index_old.html templates/index.html
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/cmdshiftd/archer/issues
- Documentation: See docs/ directory
