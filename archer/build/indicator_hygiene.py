"""
Indicator hygiene: reject prose and markup that indicator extraction picks up.

Indicators come from code spans and procedure text in ATT&CK descriptions, and
some spans capture the surrounding sentence instead of a command, e.g.
").(Citation: SSH Authorized Keys) Users may edit the system's SSH config file"
or HTML-escaped placeholders like "&lt;user-home&gt;/.ssh/authorized_keys".
Every vendor's queries are built from these values, so they are cleaned once.
"""

import html
import re
from typing import Dict, Iterable, List, Optional

_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "for", "from", "has", "have", "how",
    "in", "into", "is", "it", "its", "may", "of", "on", "or", "such", "that", "the", "their",
    "this", "to", "used", "using", "via", "was", "well", "were", "which", "while", "with", "within",
}
# Characters that mark a token as command syntax rather than English
_SYNTAX = set("-/\\=:\"{}|$%<>*[]_@&;^~+#")
_PLACEHOLDER = re.compile(r"<[A-Za-z][\w\s-]*>")
_SENTENCE_BREAK = re.compile(r"[a-z0-9][.)]\s+[A-Z][a-z]")


def _looks_like_prose(value: str) -> bool:
    words = value.split()
    if len(words) < 5:
        return False
    tokens = [w.strip(".,;:!?()") for w in words]
    if any(set(t) & _SYNTAX or t.lower().endswith((".exe", ".dll", ".ps1", ".sh")) for t in tokens):
        return False
    return sum(t.lower() in _STOPWORDS for t in tokens) / len(tokens) >= 0.2


def clean_indicator(value) -> Optional[str]:
    """The indicator as a usable literal, or None when it's prose or markup."""
    if value is None:
        return None
    v = html.unescape(str(value)).strip().strip("`").strip()
    v = re.sub(r"\s+", " ", v)
    if not v or "citation:" in v.lower():
        return None
    if re.match(r"^[).,;:]\s|^\)", v) or _SENTENCE_BREAK.search(v) or _looks_like_prose(v):
        return None
    # Documentation placeholders (<user-home>, <username>) aren't literal text: keep what's around them
    if _PLACEHOLDER.search(v):
        v = _PLACEHOLDER.sub("", v).strip()
    # Short values are noise, except numbers (ports such as 22)
    return v if len(v) >= 3 or v.isdigit() else None


def clean_indicators(values: Iterable) -> List[str]:
    out: List[str] = []
    for value in values or []:
        cleaned = clean_indicator(value)
        if cleaned and cleaned not in out:
            out.append(cleaned)
    return out


def clean_identifier_map(identifiers: Dict) -> Dict[str, List[str]]:
    """Clean every indicator list; drop types left empty."""
    cleaned = {k: clean_indicators(v if isinstance(v, (list, tuple, set)) else [v])
               for k, v in (identifiers or {}).items()}
    return {k: v for k, v in cleaned.items() if v}
