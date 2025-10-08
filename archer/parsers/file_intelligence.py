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
- YARA rules
"""

import os
import json
import re
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
import mimetypes


class FileIntelligenceParser:
    """
    Parse threat intelligence files and extract TTPs and IOCs using GenAI.
    """

    def __init__(self, use_openai: bool = False, use_local_llm: bool = False):
        """
        Initialize the parser with optional AI backends.

        Args:
            use_openai: Use OpenAI API for extraction
            use_local_llm: Use local LLM for extraction
        """
        self.use_openai = use_openai
        self.use_local_llm = use_local_llm
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
        else:
            return content.decode('utf-8', errors='ignore')

    def _extract_pdf_text(self, file_path: str) -> str:
        """Extract text from PDF file."""
        try:
            import PyPDF2
            text = []
            with open(file_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                for page in reader.pages:
                    text.append(page.extract_text())
            return '\n\n'.join(text)
        except ImportError:
            print("Warning: PyPDF2 not installed. Install with: pip install PyPDF2")
            return ""
        except Exception as e:
            print(f"Error extracting PDF text: {e}")
            return ""

    def _extract_pdf_bytes(self, content: bytes) -> str:
        """Extract text from PDF bytes."""
        try:
            import PyPDF2
            from io import BytesIO
            text = []
            pdf_file = BytesIO(content)
            reader = PyPDF2.PdfReader(pdf_file)
            for page in reader.pages:
                text.append(page.extract_text())
            return '\n\n'.join(text)
        except ImportError:
            print("Warning: PyPDF2 not installed. Install with: pip install PyPDF2")
            return ""
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
        if self.use_openai or self.use_local_llm:
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

        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs["ip"] = re.findall(ip_pattern, text)

        # Extract domain names
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        iocs["domain"] = re.findall(domain_pattern, text)

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

        # Extract command-line indicators using GenAI if available
        if self.use_openai or self.use_local_llm:
            ai_iocs = self._extract_iocs_with_ai(text)
            for key in ai_iocs:
                if key in iocs:
                    iocs[key].extend(ai_iocs[key])

        # Remove duplicates
        for key in iocs:
            iocs[key] = sorted(list(set(iocs[key])))

        return iocs

    def _extract_ttps_with_ai(self, text: str) -> List[str]:
        """Use AI to extract TTPs from text based on semantic understanding."""
        if self.use_openai and self.openai_client:
            return self._extract_ttps_openai(text)
        elif self.use_local_llm and self.local_llm:
            return self._extract_ttps_local(text)
        return []

    def _extract_iocs_with_ai(self, text: str) -> Dict[str, List[str]]:
        """Use AI to extract IOCs from text based on semantic understanding."""
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
    use_local_llm: bool = False
) -> Dict[str, Any]:
    """
    Convenience function to parse a threat intelligence file.

    Args:
        file_path: Path to file (if reading from disk)
        file_content: File content bytes (if file is uploaded)
        use_openai: Use OpenAI for enhanced extraction
        use_local_llm: Use local LLM for enhanced extraction

    Returns:
        Dict with extracted TTPs and IOCs
    """
    parser = FileIntelligenceParser(use_openai=use_openai, use_local_llm=use_local_llm)
    return parser.parse_file(file_path or "uploaded_file", file_content)
