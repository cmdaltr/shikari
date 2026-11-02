"""
A CVE's exploit name and the label its run's detections and correlations start with:
CVE-2026-109618_PHP2Shell, or the bare CVE ID when the exploit has no name.

The name comes from what researchers call it, not from the CVE text: a word in the PoC
repositories' names and the reference URLs' paths (ikow/php2shell-poc, assetnote/php2shell-scanner,
wiz.io/blog/php2shell-php-rce). One researcher's repo name isn't a name, so it takes two
sources, one of them a write-up off the vendor's site, or three repo owners. Product and
vendor words (magento, netscaler), advisory IDs (CTX697096) and PoC vocabulary (poc,
scanner, checker) don't count. No AI.
"""

import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional

_STOP = set("""
poc pocs exploit exploits exploiter scanner scan scanners check checker detect detection detector lab labs
toolkit tool tools proof concept research vuln vulnerability vulnerabilities security advisory advisories
patch patched rce lfi ssrf xss sqli auth bypass remote code execution attack attacks hunt hunting response
windows linux macos zero zeroday guard verifier nuclei template templates python script blog post posts news
update updates release releases notes article articles active actively exploitation exploited timeline
inspector helper threat analysis writeup analyse analyze mitigation workaround upload session cookie
error message public private implant chain chains multi preauth unauthenticated critical announce
package lists mailing pipermail products product support center centre portal takeover inside reversing
silent explain behind""".split())
_ACRONYMS = {"php", "sql", "ssh", "rdp", "smb", "http", "https", "xml", "api", "dns", "ldap", "jndi", "ssl",
             "tls", "vpn", "iis", "rce", "cgi", "jwt", "ntlm", "ftp", "sap", "ios", "os"}
_AGGREGATORS = ("nvd.nist.gov", "cve.org", "cve.mitre.org", "cisa.gov", "github.com", "githubusercontent.com",
                "vuldb.com", "exploit-db.com", "packetstormsecurity.com")


def _words(text: str) -> List[str]:
    return [w for w in re.split(r"[^A-Za-z0-9]+", text or "") if w]


def _product_words(nvd: Dict) -> set:
    cpe_parts = [p for c in nvd.get("cpes") or [] for p in c.split(":")[3:5]]
    text = " ".join([nvd.get("description") or "", nvd.get("vendor") or "", nvd.get("product") or "",
                     " ".join(nvd.get("products") or []), " ".join(cpe_parts)])
    return {w.lower() for w in _words(text)}


def _spell(token: str, texts: Iterable[str]) -> str:
    """As someone wrote it with capitals (MikroTrick), else split at digits: php2shell -> PHP2Shell."""
    for text in texts:
        for m in re.finditer(re.escape(token), text or "", re.I):
            word = m.group(0)
            if word != word.lower() and word != word.upper():
                return word
    return "".join(part.upper() if part.lower() in _ACRONYMS else part[:1].upper() + part[1:].lower()
                   for part in re.findall(r"[A-Za-z]+|\d+", token))


def exploit_name(nvd: Dict, pocs: List[Dict]) -> Optional[str]:
    """The exploit's name (PHP2Shell, Log4Shell), or None."""
    nvd = nvd or {}
    vendor = (nvd.get("vendor") or "").lower()
    owners, writeups, advisories = defaultdict(set), defaultdict(set), defaultdict(set)
    for poc in pocs or []:
        source = poc.get("source") or ""
        if poc.get("type") != "github" or "/" not in source:
            continue
        owner, repo = source.split("/", 1)
        for w in _words(repo):
            owners[w.lower()].add(owner.lower())
    for url in nvd.get("references") or []:
        m = re.match(r"https?://([^/?#]+)([^?#]*)", url)
        if not m:
            continue
        host = m.group(1).lower()
        if any(host == a or host.endswith("." + a) for a in _AGGREGATORS):
            continue
        # The vendor's own advisory names its products, not the exploit: it backs a name, never makes one
        for w in _words(m.group(2)):
            (advisories if vendor and vendor in host else writeups)[w.lower()].add(host)
    products = _product_words(nvd)
    best = None
    for token in set(owners) | set(writeups):
        n_owners, n_writeups = len(owners[token]), len(writeups[token])
        if not ((n_writeups and n_owners + n_writeups + len(advisories[token]) >= 2) or n_owners >= 3):
            continue
        if (len(token) < 5 or token in _STOP or token in products or token.startswith("cve")
                or not re.search(r"[a-z]", token) or re.search(r"\d{4,}", token)):
            continue
        score = (n_owners + n_writeups, token)
        if best is None or score > best[0]:
            best = (score, token)
    if not best:
        return None
    token = best[1]
    texts = [p.get("source") or "" for p in pocs or []] + [p.get("description") or "" for p in pocs or []]
    return _spell(token, texts + list(nvd.get("references") or []))


def label(cve_names: Dict[str, Optional[str]]) -> str:
    """
    The run's label: CVE-2026-109618_PHP2Shell; several CVEs list their IDs and then each
    name once (CVE-2026-96652_CVE-2026-96654_Plex2Shell). Past three CVEs, the first and a count.
    """
    ids = list(cve_names)
    names = list(dict.fromkeys(n for n in cve_names.values() if n))
    head = "_".join(ids) if len(ids) <= 3 else f"{ids[0]}_plus_{len(ids) - 1}"
    return "_".join([head] + names)
