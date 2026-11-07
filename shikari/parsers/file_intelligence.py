"""
File Intelligence Parser - GenAI-powered TTP and IOC extraction

This module provides functionality to parse various threat intelligence file formats
and extract TTPs (Tactics, Techniques, and Procedures) and IOCs (Indicators of Compromise)
using GenAI for semantic understanding.

Supported file formats:
- PDF reports
- TXT/MD threat intelligence reports
- JSON (STIX, MISP, custom formats)
- CSV (IOC lists)
- XLSX (Excel spreadsheets)
- DOCX (Word documents)
- YARA rules
"""

import os
import json
import re
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
import mimetypes


# A dotted quad (8.28.2.0) is identical in shape to a four-part software version, so octet-range
# validity alone can't tell an IP from a version string. These catch the common false positives.
# A defanged separator between two numbers: ".", "[.]" or "[[.]]"
_DOT_SEP = r"(?:\[\[?\.\]\]?|\.)"
# The quad sits inside a longer dotted-numeric run (…2.0.1, 1.8.28.…): a version, not an IPv4
_RUN_AFTER = re.compile(r"^\s*" + _DOT_SEP + r"\d")
_RUN_BEFORE = re.compile(r"\d" + _DOT_SEP + r"\s*$")
# A version/build keyword just before it ("version 8.28.2.0", "build 1.2.3.4")
_VERSION_PREFIX = re.compile(
    r"(?:\bv|\bver|\bversion|\brelease|\brev|\bbuild|\bupdate[sd]?|\bupgrade[sd]?|\bpatch|\bfirmware|\bbios)"
    r"\.?\s*$", re.I)


def _ip_is_version_like(text: str, start: int, end: int, clean_ip: str) -> bool:
    """
    True when a dotted quad matched in text is really a version number or a slice of a longer
    dotted run, not an IPv4 host indicator. Checked by context, since the quad alone is ambiguous:
    - part of a longer dotted-numeric run on either side (8.28.2.0.1, 1.8.28.2);
    - immediately preceded by a version/build keyword (version 8.28.2.0);
    - a bare network/broadcast address (ends .0 or .255) that isn't written as a CIDR (…/24):
      real host IOCs are host addresses, and version strings very often end in .0.
    """
    before = text[max(0, start - 24):start]
    after = text[end:end + 6]
    if _RUN_AFTER.match(after) or _RUN_BEFORE.search(before):
        return True
    if _VERSION_PREFIX.search(before):
        return True
    last = clean_ip.split(".")[-1]
    if last in ("0", "255") and not after.lstrip().startswith("/"):
        return True
    return False


# Sentence words that never belong to a command line; two of them after its last
# argument mean the match ran on into prose
_PROSE_WORDS = {"a", "an", "the", "and", "or", "of", "to", "in", "on", "near", "against", "with",
                "for", "from", "is", "are", "was", "were", "be", "been", "remain", "occurring",
                "that", "this", "which", "as", "by", "it", "its", "their", "user's", "was", "spawned",
                "command", "commands", "despite", "process", "tool", "tools", "such"}
_ARGUMENT = re.compile(r"^[-/]|[\\\"=%$:]|\.\w|\d|^'|'$")


def command_or_none(cmd: str):
    """
    The command line in a match, or None for prose that starts with a binary's name
    ("aws remain unpatched", "net group occurring near suspicious binary execution").
    A command has at least one argument that looks like one (a switch, path, quote,
    number or file name); words trailing after its last argument are cut when they read
    as a sentence.
    """
    # A list in a sentence ("whoami /priv , cmdkey /list , and net group"): a command's
    # own commas have no space before them (comsvcs.dll, MiniDump)
    tokens = re.split(r"\s*[,;]\s+(?=\S+\s+[/-])|\s+[,;]\s+|\s{2,}", cmd.strip())[0].split()
    # The sentence resumes at its first prose word ("whoami /priv was spawned from…")
    for i, t in enumerate(tokens[1:], 1):
        if t.lower().strip(".,;()") in _PROSE_WORDS:
            tokens = tokens[:i]
            break
    tokens[-1:] = [tokens[-1].rstrip(",;")] if tokens else []
    if len(tokens) < 2:
        return None
    args = [i for i, t in enumerate(tokens[1:], 1) if _ARGUMENT.search(t) and not re.search(r"'s$", t)]
    if not args:
        # A bare subcommand ("net group", "whoami /priv" counted above) is still a command
        # when nothing follows it
        return " ".join(tokens) if len(tokens) == 2 else None
    tail = tokens[args[-1] + 1:]
    if sum(t.lower().strip(".,;") in _PROSE_WORDS for t in tail) >= 1 and len(tail) >= 2:
        tokens = tokens[:args[-1] + 1]
    return " ".join(tokens)


class FileIntelligenceParser:
    """
    Parse threat intelligence files and extract TTPs and IOCs using GenAI.
    """

    def __init__(self, use_openai: bool = False, use_local_llm: bool = False, llm_config: Optional[Dict] = None):
        """
        Initialize the parser with optional AI backends.

        Args:
            use_openai: Use OpenAI API for extraction (OPENAI_API_KEY)
            use_local_llm: Use local LLM for extraction
            llm_config: the provider chosen for this run (app._hunt_llm_args); takes
                precedence over the two flags above
        """
        self.use_openai = use_openai and not llm_config
        self.use_local_llm = use_local_llm and not llm_config
        self.llm_config = llm_config
        self.openai_client = None
        self.local_llm = None

        # Initialize AI backends if requested
        if use_openai:
            self._init_openai()
        if use_local_llm:
            self._init_local_llm()

    def _init_openai(self):
        """Initialize OpenAI client if API key is available."""
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            print("Warning: OPENAI_API_KEY not found. OpenAI features disabled.")
            self.use_openai = False
            return

        try:
            import openai
            self.openai_client = openai.OpenAI(api_key=api_key)
        except ImportError:
            print("Warning: openai package not installed. Install with: pip install openai")
            self.use_openai = False

    def _init_local_llm(self):
        """Initialize local LLM if model path is available."""
        model_path = os.environ.get("LLAMA_MODEL_PATH")
        if not model_path:
            print("Warning: LLAMA_MODEL_PATH not found. Local LLM features disabled.")
            self.use_local_llm = False
            return

        try:
            from llama_cpp import Llama
            self.local_llm = Llama(model_path=model_path, n_ctx=4096)
        except ImportError:
            print("Warning: llama-cpp-python not installed. Install with: pip install llama-cpp-python")
            self.use_local_llm = False

    def parse_file(self, file_path: str, file_content: bytes = None) -> Dict[str, Any]:
        """
        Parse a threat intelligence file and extract TTPs and IOCs.

        Args:
            file_path: Path to the file or filename
            file_content: Optional file content bytes (for uploaded files)

        Returns:
            Dict with extracted data including:
                - ttps: List of MITRE ATT&CK technique IDs
                - iocs: Dict of IOC types and values
                - raw_text: Extracted text content
                - metadata: File metadata
        """
        # Determine file type
        file_type = self._detect_file_type(file_path, file_content)

        # Extract text based on file type
        if file_content:
            text = self._extract_text_from_bytes(file_content, file_type)
        else:
            text = self._extract_text_from_file(file_path, file_type)

        # Extract TTPs and IOCs
        result = {
            "ttps": self._extract_ttps(text),
            "iocs": self._extract_iocs(text),
            "raw_text": text,
            "metadata": {
                "file_type": file_type,
                "file_name": os.path.basename(file_path) if file_path else "uploaded_file"
            }
        }
        from shikari.build.ioc_flow import ioc_mentions
        result["ioc_mentions"] = ioc_mentions(text, result["iocs"])

        return result

    def _detect_file_type(self, file_path: str, content: bytes = None) -> str:
        """Detect file type from path or content."""
        if file_path:
            mime_type, _ = mimetypes.guess_type(file_path)
            ext = Path(file_path).suffix.lower()

            if ext == '.pdf':
                return 'pdf'
            elif ext in ['.txt', '.md']:
                return 'text'
            elif ext == '.json':
                return 'json'
            elif ext == '.csv':
                return 'csv'
            elif ext in ['.xlsx', '.xls']:
                return 'xlsx'
            elif ext in ['.docx', '.doc']:
                return 'docx'
            elif ext in ['.yar', '.yara']:
                return 'yara'

        # Try to detect from content
        if content:
            try:
                # Try to decode as text
                text = content.decode('utf-8', errors='ignore')
                if text.strip().startswith('{'):
                    return 'json'
                elif 'rule ' in text and '{' in text:
                    return 'yara'
            except:
                pass

        return 'unknown'

    def _extract_text_from_file(self, file_path: str, file_type: str) -> str:
        """Extract text content from a file on disk."""
        if file_type == 'pdf':
            return self._extract_pdf_text(file_path)
        elif file_type in ['text', 'yara']:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        elif file_type == 'json':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return self._extract_text_from_json(data)
        elif file_type == 'csv':
            return self._extract_csv_text(file_path)
        elif file_type == 'xlsx':
            return self._extract_xlsx_text(file_path)
        elif file_type == 'docx':
            return self._extract_docx_text(file_path)
        else:
            # Try reading as text
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            except:
                return ""

    def _extract_text_from_bytes(self, content: bytes, file_type: str) -> str:
        """Extract text content from bytes."""
        if file_type == 'pdf':
            return self._extract_pdf_bytes(content)
        elif file_type in ['text', 'yara']:
            return content.decode('utf-8', errors='ignore')
        elif file_type == 'json':
            data = json.loads(content.decode('utf-8'))
            return self._extract_text_from_json(data)
        elif file_type == 'csv':
            return content.decode('utf-8', errors='ignore')
        elif file_type == 'xlsx':
            return self._extract_xlsx_bytes(content)
        elif file_type == 'docx':
            return self._extract_docx_bytes(content)
        else:
            return content.decode('utf-8', errors='ignore')

    def _extract_pdf_text(self, file_path: str) -> str:
        """Extract text from PDF file."""
        try:
            with open(file_path, 'rb') as f:
                return self._extract_pdf_bytes(f.read())
        except OSError as e:
            print(f"Error reading PDF: {e}")
            return ""
        except Exception as e:
            print(f"Error extracting PDF text: {e}")
            return ""

    def _extract_pdf_bytes(self, content: bytes) -> str:
        """Extract text from PDF bytes."""
        try:
            # pypdf is a dependency; it's PyPDF2's successor (PyPDF2 was never installed, so a
            # PDF report quietly came back as no text at all)
            from pypdf import PdfReader
            from io import BytesIO
            reader = PdfReader(BytesIO(content))
            return '\n\n'.join(page.extract_text() or "" for page in reader.pages)
        except Exception as e:
            print(f"Error extracting PDF bytes: {e}")
            return ""

    def _extract_text_from_json(self, data: dict) -> str:
        """Extract relevant text from JSON structures (STIX, MISP, etc.)."""
        text_parts = []

        # Handle STIX format
        if 'objects' in data:
            for obj in data['objects']:
                if 'description' in obj:
                    text_parts.append(obj['description'])
                if 'name' in obj:
                    text_parts.append(obj['name'])

        # Handle MISP format
        if 'Event' in data:
            event = data['Event']
            if 'info' in event:
                text_parts.append(event['info'])
            if 'Attribute' in event:
                for attr in event['Attribute']:
                    if 'comment' in attr:
                        text_parts.append(attr['comment'])

        # Fallback: convert entire JSON to string
        if not text_parts:
            text_parts.append(json.dumps(data, indent=2))

        return '\n\n'.join(text_parts)

    def _extract_csv_text(self, file_path: str) -> str:
        """Extract text from CSV file."""
        try:
            import csv
            text_parts = []
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                for row in reader:
                    text_parts.append(' '.join(row))
            return '\n'.join(text_parts)
        except Exception as e:
            print(f"Error reading CSV: {e}")
            return ""

    def _extract_xlsx_text(self, file_path: str) -> str:
        """Extract text from XLSX/XLS file."""
        try:
            import openpyxl
            workbook = openpyxl.load_workbook(file_path, data_only=True)
            text_parts = []

            for sheet_name in workbook.sheetnames:
                sheet = workbook[sheet_name]
                text_parts.append(f"Sheet: {sheet_name}")

                for row in sheet.iter_rows(values_only=True):
                    row_text = ' | '.join([str(cell) if cell is not None else '' for cell in row])
                    if row_text.strip():
                        text_parts.append(row_text)

            return '\n'.join(text_parts)
        except ImportError:
            print("Warning: openpyxl not installed. Install with: pip install openpyxl")
            return ""
        except Exception as e:
            print(f"Error reading XLSX: {e}")
            return ""

    def _extract_xlsx_bytes(self, content: bytes) -> str:
        """Extract text from XLSX bytes."""
        try:
            import openpyxl
            from io import BytesIO
            workbook = openpyxl.load_workbook(BytesIO(content), data_only=True)
            text_parts = []

            for sheet_name in workbook.sheetnames:
                sheet = workbook[sheet_name]
                text_parts.append(f"Sheet: {sheet_name}")

                for row in sheet.iter_rows(values_only=True):
                    row_text = ' | '.join([str(cell) if cell is not None else '' for cell in row])
                    if row_text.strip():
                        text_parts.append(row_text)

            return '\n'.join(text_parts)
        except ImportError:
            print("Warning: openpyxl not installed. Install with: pip install openpyxl")
            return ""
        except Exception as e:
            print(f"Error reading XLSX bytes: {e}")
            return ""

    def _extract_docx_text(self, file_path: str) -> str:
        """Extract text from DOCX file."""
        try:
            import docx
            doc = docx.Document(file_path)
            text_parts = []

            # Extract paragraphs
            for para in doc.paragraphs:
                if para.text.strip():
                    text_parts.append(para.text)

            # Extract tables
            for table in doc.tables:
                for row in table.rows:
                    row_text = ' | '.join([cell.text for cell in row.cells])
                    if row_text.strip():
                        text_parts.append(row_text)

            return '\n\n'.join(text_parts)
        except ImportError:
            print("Warning: python-docx not installed. Install with: pip install python-docx")
            return ""
        except Exception as e:
            print(f"Error reading DOCX: {e}")
            return ""

    def _extract_docx_bytes(self, content: bytes) -> str:
        """Extract text from DOCX bytes."""
        try:
            import docx
            from io import BytesIO
            doc = docx.Document(BytesIO(content))
            text_parts = []

            # Extract paragraphs
            for para in doc.paragraphs:
                if para.text.strip():
                    text_parts.append(para.text)

            # Extract tables
            for table in doc.tables:
                for row in table.rows:
                    row_text = ' | '.join([cell.text for cell in row.cells])
                    if row_text.strip():
                        text_parts.append(row_text)

            return '\n\n'.join(text_parts)
        except ImportError:
            print("Warning: python-docx not installed. Install with: pip install python-docx")
            return ""
        except Exception as e:
            print(f"Error reading DOCX bytes: {e}")
            return ""

    def _extract_ttps(self, text: str) -> List[str]:
        """
        Extract MITRE ATT&CK technique IDs from text.
        Uses regex patterns and optionally GenAI for semantic extraction.
        """
        ttps = []

        # Regex pattern for MITRE ATT&CK technique IDs (T1234, T1234.001, etc.)
        pattern = r'\b(T\d{4}(?:\.\d{3})?)\b'
        matches = re.findall(pattern, text, re.IGNORECASE)
        ttps.extend([m.upper() for m in matches])

        # Use GenAI for semantic extraction if available
        if self.llm_config or self.use_openai or self.use_local_llm:
            ai_ttps = self._extract_ttps_with_ai(text)
            ttps.extend(ai_ttps)

        # Remove duplicates and sort
        return sorted(list(set(ttps)))

    def _extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """
        Extract IOCs (Indicators of Compromise) from text.
        Returns dict with IOC types: cmd, reg, evt, sw, ip, domain, hash, etc.
        """
        iocs = {
            "cmd": [],      # Commands/command-line indicators
            "reg": [],      # Registry keys/values
            "evt": [],      # Event IDs
            "sw": [],       # Software/process names
            "ip": [],       # IP addresses
            "domain": [],   # Domain names
            "hash": [],     # File hashes
            "file": []      # File paths/names
        }

        # Extract IP addresses (including defanged with [.] or [[.]])
        ip_pattern = r'\b(?:\d{1,3}(?:\[\[?\.\]\]?|\.)){3}\d{1,3}\b'
        for m in re.finditer(ip_pattern, text):
            ip = m.group(0)
            # Clean up to check validity (remove all bracket variations)
            clean_ip = ip.replace('[[.]]', '.').replace('[.]', '.').replace('[', '').replace(']', '')
            parts = clean_ip.split('.')
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                # Drop version numbers and dotted runs masquerading as IPs (8.28.2.0 et al)
                if _ip_is_version_like(text, m.start(), m.end(), clean_ip):
                    continue
                # Exclude common false positives
                if not clean_ip.startswith(('127.', '0.0.0.', '192.168.', '10.', '169.254.')):
                    # Keep original defanging format if already defanged, otherwise add [.]
                    if '[[.]]' in ip or '[.]' in ip:
                        normalized = ip  # Already defanged, keep as-is
                    else:
                        normalized = ip.replace('.', '[.]')
                    iocs["ip"].append(normalized)

        # Extract domain names with intelligent filtering
        # Match domains but with stricter validation
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\[\[?\.\]\]?|\.))+[a-zA-Z]{2,}\b'
        potential_domains = re.findall(domain_pattern, text)

        for domain in potential_domains:
            domain_lower = domain.lower()

            # Clean up for analysis (remove all bracket variations)
            clean_domain = domain.replace('[[.]]', '.').replace('[.]', '.').replace('[', '').replace(']', '')
            parts = clean_domain.split('.')

            # Two sentences run together by text extraction ("persistence.In addition"):
            # a capitalised word after an unfanged dot, never written that way for a domain
            if '[' not in domain and re.fullmatch(r'[A-Z][a-z]+', parts[-1]):
                continue

            # CHECK FILES FIRST: File extensions and known file indicators
            # Check against clean_domain since domain_lower might have [.] or [[.]]
            clean_domain_lower = clean_domain.lower()
            if any(clean_domain_lower.endswith(ext) for ext in [
                '.exe', '.dll', '.sys', '.bat', '.ps1', '.vbs', '.js', '.jar', '.zip', '.rar',
                '.7z', '.tar', '.gz', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.txt',
                '.log', '.tmp', '.bak', '.old', '.cab', '.msi', '.dat', '.dit', '.db', '.xml'
            ]):
                # Known malicious file indicators like NTDS.dit should go to file IOCs
                if clean_domain_lower in ['ntds.dit', 'sam.hive', 'system.hive', 'security.hive']:
                    if clean_domain not in iocs["file"]:
                        iocs["file"].append(clean_domain)
                # Otherwise skip files completely
                continue

            # EXCLUDE: Property/field names (e.g., Object.Property, Item.Subject)
            # These have PascalCase or camelCase and look like programming constructs
            if len(parts) >= 2:
                is_property_path = False

                # Count how many parts have PascalCase or camelCase
                mixed_case_parts = 0
                programming_term_parts = 0

                for part in parts:
                    # PascalCase: starts with uppercase, has more uppercase inside (ItemName, ParentFolder)
                    # camelCase: starts with lowercase, has uppercase inside (accessedProcess, commandLine)
                    has_uppercase_in_middle = len(part) > 1 and any(c.isupper() for c in part[1:])

                    if part and has_uppercase_in_middle:
                        mixed_case_parts += 1

                    # Check for programming/schema terms
                    # Only include terms that are UNLIKELY to be in real domain names
                    if part.lower() in [
                        # Schema/Object terms
                        'item', 'object', 'folder', 'parent', 'dest', 'accessed',
                        # Property terms
                        'path', 'name', 'id', 'type', 'value', 'size', 'subject',
                        # Data structure terms
                        'data', 'context', 'metadata', 'attachments', 'messages',
                        # Event/Log terms
                        'event', 'audit', 'evaluation', 'match',
                        # System terms
                        'system', 'process', 'command', 'image', 'line', 'full',
                        # Schema-specific
                        'copiloteventdata', 'dlpauditeventmetadata', 'appaccesscontext',
                        'apphost', 'aiplugin', 'aistemplugin', 'modeltransparency',
                        'transparency', 'clientappname', 'fullimage', 'commandline',
                        'parentfolder', 'destfolder', 'accessedobject', 'accessedprocess'
                    ]:
                        programming_term_parts += 1

                # Rule 1: If has mixed case AND programming terms, it's likely a property
                # Example: ParentFolder.Path (has PascalCase + "path" term)
                if mixed_case_parts >= 1 and programming_term_parts >= 1:
                    is_property_path = True
                # Rule 2: If ALL parts are programming terms (even without mixed case)
                # Example: accessed.name, folder.path
                elif programming_term_parts == len(parts):
                    is_property_path = True
                # Rule 3: Multiple parts with mixed case (likely object hierarchy)
                # Example: Item.ParentFolder.Path
                elif mixed_case_parts >= 2:
                    is_property_path = True

                if is_property_path:
                    continue

            # EXCLUDE: Version numbers (e.g., 3.1.rar, 1.0.0.0)
            if all(part.isdigit() for part in parts):
                continue
            if len(parts) == 2 and parts[0].isdigit():
                continue

            # Must have valid TLD (at least 2 chars, all letters)
            tld = parts[-1].lower()
            if len(tld) < 2 or not tld.isalpha():
                continue

            # EXCLUDE: TLDs that are actually file extensions or should be filtered
            file_extension_tlds = {
                'exe', 'dll', 'sys', 'bat', 'ps1', 'vbs', 'js', 'jar', 'zip', 'rar',
                'txt', 'log', 'tmp', 'bak', 'old', 'cab', 'msi', 'dat', 'dit', 'xml',
                'pdf', 'doc', 'xls', 'ppt', 'docx', 'xlsx', 'pptx', 'rtf', 'csv', 'ini',
                'sh', 'py', 'rb', 'pl', 'php',  # Script file extensions
                'email', 'id'  # Additional TLDs to exclude
            }
            if tld in file_extension_tlds:
                continue

            # REQUIRE: TLD must be a known valid internet TLD
            # Common valid TLDs (not exhaustive, but covers most real-world cases)
            # Sources: https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains
            valid_tlds = {
                # Generic TLDs (most common)
                'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
                'info', 'biz', 'pro', 'museum', 'coop', 'aero',
                'xxx', 'tel', 'mobi', 'asia', 'cat', 'jobs', 'travel',
                'post', 'arpa',
                # New gTLDs (common ones)
                'app', 'dev', 'blog', 'shop', 'store', 'tech', 'online',
                'site', 'website', 'space', 'cloud', 'digital',
                'top', 'xyz', 'club', 'live', 'news', 'media', 'today',
                'world', 'earth', 'money', 'bank', 'insurance', 'finance',
                'solutions', 'services', 'consulting', 'management', 'agency',
                'company', 'business', 'enterprises', 'ventures', 'holdings',
                'group', 'network', 'systems', 'software', 'technology',
                'link', 'click', 'download', 'support', 'help', 'wiki',
                # Country codes (common ones used by threat actors)
                'ru', 'cn', 'us', 'uk', 'de', 'fr', 'jp', 'kr', 'in', 'br',
                'au', 'ca', 'nl', 'pl', 'se', 'no', 'fi', 'dk', 'it', 'es',
                'pt', 'ch', 'at', 'be', 'cz', 'ro', 'hu', 'bg', 'ua', 'sk',
                'ie', 'nz', 'za', 'sg', 'hk', 'tw', 'th', 'my', 'ph', 'id',
                'vn', 'pk', 'bd', 'ir', 'tr', 'il', 'sa', 'ae', 'eg', 'ng',
                'ke', 'gh', 'tz', 'ug', 'mx', 'ar', 'cl', 'co', 've', 'pe',
                # Infrastructure/hosting TLDs often used by threat actors
                'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'ws',
                'to', 'io', 'sh', 'ac', 'im', 'gg', 'je', 'tv', 'fm', 'am',
                # Other legitimate TLDs
                'eu', 'gov', 'edu', 'ac', 'co', 'org', 'net', 'me'
            }

            # If TLD is not in valid list, it's probably not a domain
            if tld not in valid_tlds:
                continue

            # Must have at least one letter in the domain name (not just numbers)
            if not any(c.isalpha() for c in clean_domain.replace('.', '')):
                continue

            # EXCLUDE: Common legitimate domains and security vendor domains
            # Check against clean_domain to handle defanged indicators
            clean_check = clean_domain.lower().replace('[.]', '.').replace('[[.]]', '.')
            exclude_domains = [
                'microsoft.com', 'google.com', 'github.com', 'windows.com',
                'apple.com', 'adobe.com', 'mozilla.org', 'kernel.org',
                'example.com', 'test.com', 'localhost',
                'crowdstrike.com', 'splunkcloud.com', 'file.io'
            ]
            if any(exclude in clean_check for exclude in exclude_domains):
                continue
            # Also check if it ends with these domains (for subdomains)
            if any(clean_check.endswith(exclude) for exclude in exclude_domains):
                continue

            # REQUIRE: At least 2 parts (domain + TLD minimum)
            if len(parts) < 2:
                continue

            # REQUIRE: Domain part should be at least 2 chars
            if len(parts[-2]) < 2:
                continue

            # Keep original defanging format if already defanged, otherwise add [.]
            if '[[.]]' in domain or '[.]' in domain:
                normalized = domain  # Already defanged, keep as-is
            else:
                normalized = domain.replace('.', '[.]')

            iocs["domain"].append(normalized)

        # Extract file hashes (MD5, SHA1, SHA256)
        hash_patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b'
        }
        for hash_type, pattern in hash_patterns.items():
            iocs["hash"].extend(re.findall(pattern, text))

        # Extract Windows Event IDs
        evt_pattern = r'Event\s*ID\s*:?\s*(\d+)|EventID\s*:?\s*(\d+)'
        evt_matches = re.findall(evt_pattern, text, re.IGNORECASE)
        for match in evt_matches:
            iocs["evt"].extend([m for m in match if m])

        # Extract registry keys
        reg_pattern = r'HKEY_[A-Z_]+\\[^\s\n]+'
        iocs["reg"] = re.findall(reg_pattern, text, re.IGNORECASE)

        # Extract file paths
        file_patterns = [
            r'C:\\[^\s\n]+\.[a-zA-Z]{2,4}',  # Windows paths
            r'/[^\s\n]+/[^\s\n]+\.[a-zA-Z]{2,4}',  # Unix paths
        ]
        for pattern in file_patterns:
            iocs["file"].extend(re.findall(pattern, text))

        # Extract command-line indicators
        command_patterns = [
            # FTP commands
            r'\bftp(?:\.[a-z]+)?\s+[^\s]+',
            # SSH commands with keys
            r'\bssh\s+-i\s+[^\s]+\s+[^\s]+@[^\s]+',
            # AWS CLI commands
            r'\baws\s+[a-z0-9-]+\s+[^\n]+',
            # Azure CLI commands
            r'\baz\s+[a-z0-9-]+\s+[^\n]+',
            # Docker commands
            r'\bdocker\s+(?:run|exec|build|pull|push)[^\n]+',
            # gcloud commands
            r'\bgcloud\s+[a-z0-9-]+\s+[^\n]+',
            # PowerShell commands
            r'\bpowershell(?:\.exe)?\s+-[^\n]+',
            r'\bInvoke-[A-Za-z]+[^\n]*',
            # CMD commands
            r'\bcmd(?:\.exe)?\s+/[ck][^\n]+',
            # Curl/wget
            r'\b(?:curl|wget)\s+[^\n]+',
            # General command line with common executables
            r'\b(?:rundll32|regsvr32|mshta|certutil|bitsadmin|wmic|net|sc|whoami|cmdkey|nltest|vssadmin|schtasks|reg)(?:\.exe)?\s+[^\n]+'
        ]

        for pattern in command_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                # Strip description after ': ' separator (e.g., "command: description")
                if ': ' in match:
                    match = match.split(': ')[0]

                # Clean up: strip whitespace and trailing dots
                cleaned = match.strip().rstrip('.')

                # Strip trailing punctuation patterns like ) or (.exe .dll dump)))
                # Use regex to remove patterns like ") or (.xxx" and trailing parentheses
                cleaned = re.sub(r'\)\s+or\s+\([^)]+\)+$', '', cleaned)

                # Remove remaining trailing closing parentheses and spaces
                while cleaned.endswith(')') or cleaned.endswith(' '):
                    cleaned = cleaned.rstrip(') ')

                # Strip trailing punctuation that might vary (: , ; etc)
                cleaned = cleaned.rstrip(':,;')

                # Smart quote stripping: only strip trailing quotes if there are no quotes in the command body
                if cleaned:
                    # Check for trailing single or double quotes
                    if cleaned.endswith('"'):
                        # Only strip if there are no other double quotes in the command
                        if cleaned[:-1].count('"') == 0:
                            cleaned = cleaned[:-1]
                    elif cleaned.endswith("'"):
                        # Only strip if there are no other single quotes in the command
                        if cleaned[:-1].count("'") == 0:
                            cleaned = cleaned[:-1]

                # Defang URLs in commands: http -> hxxp, https -> hxxps
                cleaned = re.sub(r'\bhttp://', 'hxxp://', cleaned, flags=re.IGNORECASE)
                cleaned = re.sub(r'\bhttps://', 'hxxps://', cleaned, flags=re.IGNORECASE)

                # Truncate if too long
                cleaned = command_or_none(cleaned[:200])

                if cleaned:
                    iocs["cmd"].append(cleaned)

        # Extract command-line indicators using GenAI if available
        if self.llm_config or self.use_openai or self.use_local_llm:
            ai_iocs = self._extract_iocs_with_ai(text)
            for key in ai_iocs:
                if key in iocs:
                    iocs[key].extend(ai_iocs[key])

        # Remove duplicates and convert ALL IOCs to lowercase
        for key in iocs:
            # Convert all to lowercase first
            lowercase_items = [item.lower() for item in iocs[key]]
            # Remove duplicates
            unique_items = sorted(list(set(lowercase_items)))
            iocs[key] = unique_items

        # Special processing for commands: merge similar commands
        if iocs["cmd"]:
            merged_commands = []
            skip_indices = set()

            for i, cmd1 in enumerate(iocs["cmd"]):
                if i in skip_indices:
                    continue

                # Check against all subsequent commands
                for j in range(i + 1, len(iocs["cmd"])):
                    if j in skip_indices:
                        continue

                    cmd2 = iocs["cmd"][j]

                    # Normalize both commands for comparison (handle URL defanging variations)
                    norm_cmd1 = cmd1.replace('hxxp://', 'http://').replace('hxxps://', 'https://')
                    norm_cmd2 = cmd2.replace('hxxp://', 'http://').replace('hxxps://', 'https://')

                    # Check if commands are identical after normalization
                    if norm_cmd1 == norm_cmd2:
                        # Keep the defanged version (with hxxp) if one exists
                        if 'hxxp' in cmd1:
                            skip_indices.add(j)  # cmd1 has hxxp, skip cmd2
                        else:
                            skip_indices.add(i)  # cmd2 has hxxp, skip cmd1 and use cmd2
                            break
                        continue

                    # Calculate length difference
                    len_diff = abs(len(cmd1) - len(cmd2))

                    # If length difference is ≤5, check if they're similar
                    if len_diff <= 5:
                        # Get the shorter command for comparison
                        shorter = cmd1 if len(cmd1) <= len(cmd2) else cmd2
                        longer = cmd2 if len(cmd1) <= len(cmd2) else cmd1

                        # Check if shorter command is a prefix of longer (allowing trailing punctuation)
                        if longer.startswith(shorter):
                            # They're similar enough, keep the shorter one and skip the longer
                            skip_indices.add(j)

                # Add the command if not skipped
                if i not in skip_indices:
                    merged_commands.append(cmd1)

            iocs["cmd"] = sorted(merged_commands)

        return iocs

    def _extract_ttps_with_ai(self, text: str) -> List[str]:
        """Use AI to extract TTPs from text based on semantic understanding."""
        if self.llm_config:
            return llm_extract_ttps(text, self.llm_config)
        if self.use_openai and self.openai_client:
            return self._extract_ttps_openai(text)
        elif self.use_local_llm and self.local_llm:
            return self._extract_ttps_local(text)
        return []

    def _extract_iocs_with_ai(self, text: str) -> Dict[str, List[str]]:
        """Use AI to extract IOCs from text based on semantic understanding."""
        if self.llm_config:
            return llm_extract_iocs(text, self.llm_config)
        if self.use_openai and self.openai_client:
            return self._extract_iocs_openai(text)
        elif self.use_local_llm and self.local_llm:
            return self._extract_iocs_local(text)
        return {}

    def _extract_ttps_openai(self, text: str) -> List[str]:
        """Extract TTPs using OpenAI API."""
        try:
            # Truncate text if too long
            max_chars = 8000
            truncated_text = text[:max_chars] if len(text) > max_chars else text

            prompt = f"""Analyze the following threat intelligence text and extract all MITRE ATT&CK technique IDs mentioned or implied.
Return ONLY a JSON array of technique IDs in the format ["T1234", "T1234.001", ...].
If no techniques are found, return an empty array [].

Text:
{truncated_text}

JSON array of technique IDs:"""

            response = self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert that extracts MITRE ATT&CK technique IDs from threat intelligence reports."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=500
            )

            result = response.choices[0].message.content.strip()
            # Parse JSON array
            ttps = json.loads(result)
            return [t.upper() for t in ttps if isinstance(t, str)]
        except Exception as e:
            print(f"Error extracting TTPs with OpenAI: {e}")
            return []

    def _extract_iocs_openai(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs using OpenAI API."""
        try:
            # Truncate text if too long
            max_chars = 8000
            truncated_text = text[:max_chars] if len(text) > max_chars else text

            prompt = f"""Analyze the following threat intelligence text and extract indicators of compromise (IOCs).
Focus on command-line indicators, process names, and software names that could be used in detection queries.

Return ONLY a JSON object with these keys:
- "cmd": array of command-line patterns/commands
- "sw": array of software/process names
- "file": array of file names (not full paths)

Text:
{truncated_text}

JSON object:"""

            response = self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert that extracts IOCs from threat intelligence reports."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1000
            )

            result = response.choices[0].message.content.strip()
            # Parse JSON object
            iocs = json.loads(result)
            return iocs
        except Exception as e:
            print(f"Error extracting IOCs with OpenAI: {e}")
            return {}

    def _extract_ttps_local(self, text: str) -> List[str]:
        """Extract TTPs using local LLM."""
        # TODO: Implement local LLM extraction
        # This would use llama.cpp with a similar prompt to OpenAI
        return []

    def _extract_iocs_local(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs using local LLM."""
        # TODO: Implement local LLM extraction
        return {}


def parse_intelligence_file(
    file_path: str = None,
    file_content: bytes = None,
    use_openai: bool = False,
    use_local_llm: bool = False,
    llm_config: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Convenience function to parse a threat intelligence file.

    Args:
        file_path: Path to file (if reading from disk)
        file_content: File content bytes (if file is uploaded)
        use_openai: Use OpenAI for enhanced extraction
        use_local_llm: Use local LLM for enhanced extraction
        llm_config: the provider chosen for this run (see FileIntelligenceParser)

    Returns:
        Dict with extracted TTPs and IOCs
    """
    parser = FileIntelligenceParser(use_openai=use_openai, use_local_llm=use_local_llm, llm_config=llm_config)
    return parser.parse_file(file_path or "uploaded_file", file_content)


# AI extraction through the provider chosen for the run (Hunt's AI prompt; Profile → API
# Keys), for uploaded files and blog posts alike. Each returns nothing on any failure, so
# a run carries on with what the patterns found.
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_EXTRACT_MAX_CHARS = 8000


def _ask(prompt: str, llm_config: Dict, max_tokens: int) -> str:
    from shikari.build.llm_queries import call_llm

    return call_llm(prompt, {**llm_config, "max_tokens": max_tokens}) or ""


def _json_in(reply: str, opener: str, closer: str):
    start, end = reply.find(opener), reply.rfind(closer)
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(reply[start:end + 1])
    except ValueError:
        return None


def llm_extract_ttps(text: str, llm_config: Dict) -> List[str]:
    """ATT&CK technique IDs the text names or describes."""
    prompt = (
        "Analyse the following threat intelligence text and extract every MITRE ATT&CK technique it "
        "names or clearly describes. Return ONLY a JSON array of technique IDs, e.g. "
        '["T1059.001", "T1566"]. Return [] if there are none.\n\nText:\n' + text[:_EXTRACT_MAX_CHARS]
    )
    try:
        found = _json_in(_ask(prompt, llm_config, 600), "[", "]")
    except Exception as e:
        print(f"AI technique extraction failed: {e}")
        return []
    return sorted({t.strip().upper() for t in found or [] if isinstance(t, str) and _TECHNIQUE_ID.match(t.strip().upper())})


def llm_extract_iocs(text: str, llm_config: Dict) -> Dict[str, List[str]]:
    """Command lines, software and file names the text describes, for detection queries."""
    prompt = (
        "Analyse the following threat intelligence text and extract indicators that detection queries "
        "can match. Return ONLY a JSON object with these keys: \"cmd\" (command lines), \"sw\" "
        "(software or process names), \"file\" (file names, not paths). Use empty arrays when there "
        "are none.\n\nText:\n" + text[:_EXTRACT_MAX_CHARS]
    )
    try:
        found = _json_in(_ask(prompt, llm_config, 1200), "{", "}")
    except Exception as e:
        print(f"AI indicator extraction failed: {e}")
        return {}
    if not isinstance(found, dict):
        return {}
    return {k: [str(v).strip() for v in found.get(k) or [] if str(v).strip()] for k in ("cmd", "sw", "file")
            if isinstance(found.get(k), list)}
