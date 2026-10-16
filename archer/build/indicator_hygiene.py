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
_PLACEHOLDER = re.compile(r"<[A-Za-z][\w\s|-]*>")
# Where a placeholder stood: "anything here". Builders split on it (KQL has_all fragments,
# SecOps .*?), so the text around a placeholder still has to match, in order
GAP = "\u2026"
# Words that make a bracketed span a stand-in rather than a literal ({default} in bcdedit is real)
_SLOT_WORD = (r"(?:user ?name|user|host ?name|host|ip(?: address)?|domain(?: name)?|computer ?name|computer|"
              r"server|target|victim|attacker|password|pass|path|file ?name|file|dll ?name|dir(?:ectory)?|"
              r"port|share|url|sid|guid|pid|payload|remote|local|name|vault|credentials|id)")
_SLOTS = [
    re.compile(r"\{\s*" + _SLOT_WORD + r"(?:\s*[|/,]\s*" + _SLOT_WORD + r")*\s*\}", re.I),
    re.compile(r"\[\s*" + _SLOT_WORD + r"(?:\s*[|/,]\s*" + _SLOT_WORD + r")*\s*\]", re.I),
    re.compile(r"\(\s*" + _SLOT_WORD + r"\s*\)", re.I),
    # Halves of a split placeholder: "v:{hostname" and "ip}"
    re.compile(r"\{" + _SLOT_WORD + r"\b(?![^{}]*\})|(?<![{\w])" + _SLOT_WORD + r"\}", re.I),
]
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
    # Documentation placeholders (<user-home>, {hostname}, [Username], (username)) aren't
    # literal text: keep what's around them, with a gap where they stood
    for rx in [_PLACEHOLDER] + _SLOTS:
        v = rx.sub(GAP, v)
    if GAP in v:
        v = re.sub(re.escape(GAP) + r"+", GAP, v).strip(GAP + " ")
        if len(re.sub(r"[\W_]", "", v.replace(GAP, ""))) < 3:
            return None
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
