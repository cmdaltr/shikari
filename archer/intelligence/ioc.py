"""
IOC parsing: classify an indicator, refang/defang it, and produce the search variants a report
might have written. No network, no AI.

Threat reports defang indicators so they can't be clicked or auto-harvested — `hxxp`, `1[.]2[.]3[.]4`,
`evil(dot)com`, `user[@]evil.com`. Archer refangs what the user enters, classifies it, normalises it,
and generates the common defanged forms, so an IOC search matches a report however it wrote the
indicator.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List, Optional, Tuple

# ── Refang: turn a defanged indicator back into its real form ────────────────────
# Order matters: scheme first, then the bracketed separators, then the word forms.
_REFANG = [
    (re.compile(r"h\s*x\s*x\s*p", re.I), "http"),   # hxxp / h x x p -> http (covers hxxps too)
    (re.compile(r"\bf\s*x\s*p\b", re.I), "ftp"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*/\s*/\s*\]"), "//"),
    (re.compile(r"[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]", re.I), "."),  # [.] (.) {dot} [dot]
    (re.compile(r"\s+dot\s+", re.I), "."),                          # evil dot com
    (re.compile(r"[\[\(\{]\s*(?:@|at)\s*[\]\)\}]", re.I), "@"),     # [@] (at) [at]
    (re.compile(r"\s+at\s+", re.I), "@"),                            # user at evil.com (last, greedy)
    (re.compile(r"\\\."), "."),                                      # literal backslash-dot
]


def refang(value: str) -> str:
    """A defanged indicator restored to its real form (hxxp -> http, [.] -> ., (at) -> @)."""
    s = (value or "").strip().strip("<>\"'")
    for pat, repl in _REFANG[:-1]:  # the 'at' word form is risky; apply only when it clearly splits an email
        s = pat.sub(repl, s)
    if "@" not in s and re.search(r"\S\s+at\s+\S+\.\S", s, re.I):
        s = _REFANG[-1][0].sub("@", s)
    return s.strip()


# ── Classify ─────────────────────────────────────────────────────────────────────
_CVE = re.compile(r"(?i)^CVE-\d{4}-\d{4,7}$")
_MD5 = re.compile(r"(?i)^[a-f0-9]{32}$")
_SHA1 = re.compile(r"(?i)^[a-f0-9]{40}$")
_SHA256 = re.compile(r"(?i)^[a-f0-9]{64}$")
_EMAIL = re.compile(r"(?i)^[a-z0-9._%+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
_DOMAIN = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

TYPES = ("cve", "sha256", "sha1", "md5", "ipv4", "ipv6", "email", "url", "domain")


def classify(value: str) -> Tuple[Optional[str], str]:
    """
    (ioc_type, normalised_value) for a (possibly defanged) indicator, or (None, refanged) if it
    isn't one Archer recognises. Normalisation: lowercase for host/url/email/hash, compressed IP,
    upper-case CVE.
    """
    s = refang(value)
    if not s:
        return None, s
    if _CVE.match(s):
        return "cve", s.upper()
    if _SHA256.match(s):
        return "sha256", s.lower()
    if _SHA1.match(s):
        return "sha1", s.lower()
    if _MD5.match(s):
        return "md5", s.lower()
    host = s.split("/")[0]  # strip any path for the ip/scheme checks
    try:
        ip = ipaddress.ip_address(host)
        return ("ipv6" if ip.version == 6 else "ipv4"), str(ip)
    except ValueError:
        pass
    if _EMAIL.match(s):
        return "email", s.lower()
    if re.match(r"(?i)^[a-z][a-z0-9+.-]*://", s):
        return "url", s
    if _DOMAIN.match(s):
        return "domain", s.lower()
    return None, s


# ── Search variants: the forms a report might have used ──────────────────────────
_DOT_FORMS = (".", "[.]", "(.)", "[dot]", "(dot)", " dot ")
_AT_FORMS = ("@", "[@]", "(at)", "[at]", " at ")


def _dot_variants(text: str) -> List[str]:
    """Every way the dots in a host/IP are commonly written."""
    return [text.replace(".", f) for f in _DOT_FORMS]


def variants(value: str, ioc_type: str) -> List[str]:
    """
    The distinct strings to search for in page text so a match is found however the report defanged
    the indicator. Hashes and CVEs are matched case-insensitively, so one form is enough.
    """
    out: List[str] = []

    def add(*xs):
        for x in xs:
            if x and x not in out:
                out.append(x)

    if ioc_type in ("ipv4", "ipv6", "domain"):
        add(*_dot_variants(value))
    elif ioc_type == "url":
        add(value)
        add(value.replace("http", "hxxp", 1))              # scheme defang
        for form in _dot_variants(value):
            add(form, form.replace("http", "hxxp", 1))
        host = re.sub(r"(?i)^[a-z][a-z0-9+.-]*://", "", value).split("/")[0]
        add(*_dot_variants(host))                           # the bare host too
    elif ioc_type == "email":
        local, _, host = value.partition("@")
        for at in _AT_FORMS:
            for hostform in _dot_variants(host):
                add(f"{local}{at}{hostform}")
    else:  # cve, md5, sha1, sha256 — matched case-insensitively
        add(value)
    return out


def find_in(text: str, search_variants: List[str]) -> Optional[Tuple[str, int]]:
    """The first variant present in `text` (case-insensitive) and its offset, or None."""
    low = text.lower()
    best: Optional[Tuple[str, int]] = None
    for v in search_variants:
        idx = low.find(v.lower())
        if idx != -1 and (best is None or idx < best[1]):
            best = (v, idx)
    return best


def snippet(text: str, at: int, match_len: int, width: int = 140) -> str:
    """A one-line context window around a match, with surrounding whitespace collapsed."""
    start = max(0, at - width // 2)
    end = min(len(text), at + match_len + width // 2)
    piece = re.sub(r"\s+", " ", text[start:end]).strip()
    return ("…" if start > 0 else "") + piece + ("…" if end < len(text) else "")
