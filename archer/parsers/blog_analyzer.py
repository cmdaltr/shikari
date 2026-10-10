"""
Blog and Threat Report Analyzer

Fetches and analyzes blog posts from security vendors (Crowdstrike, The DFIR Report, etc.)
to extract threat intelligence including:
- Threat group names
- MITRE ATT&CK techniques
- Tactics
- Procedures/TTPs
- IOCs (optional)

This module can be used to:
1. Analyze user-provided blog URLs
2. Automatically search for threat groups not in ATT&CK
"""

import re
import requests
from typing import Dict, List, Optional
from bs4 import BeautifulSoup

# CDN bot filters (e.g. cisa.gov) 403 a browser User-Agent that arrives without the
# Accept headers a real browser sends, so keep the set consistent
FETCH_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-GB,en;q=0.9",
}


def _check_public_url(url: str) -> None:
    """Raise ValueError unless url is http(s) and every address its host resolves to is globally routable."""
    import ipaddress
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid URL scheme. Only HTTP and HTTPS are allowed.")
    if not parsed.hostname:
        raise ValueError("Invalid URL: no hostname found.")
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror:
        raise ValueError("Unable to resolve hostname.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        # is_global excludes RFC1918, loopback, link-local, CGNAT/Tailscale (100.64/10), 0/8, multicast, reserved
        if not ip.is_global:
            raise ValueError("Access to private, internal or reserved addresses is not allowed.")


def _fetch_public_url(url: str, max_redirects: int = 3) -> requests.Response:
    """GET url following redirects manually so each hop is re-validated (requests would skip the check)."""
    from urllib.parse import urljoin

    headers = FETCH_HEADERS
    for _ in range(max_redirects + 1):
        _check_public_url(url)
        response = requests.get(url, headers=headers, timeout=30, allow_redirects=False)
        if not response.is_redirect:
            return response
        url = urljoin(url, response.headers.get("Location", ""))
    raise ValueError(f"Too many redirects (max {max_redirects}).")


def analyze_blog_post(url: str) -> Dict:
    """
    Analyze a blog post URL and extract threat intelligence.

    Args:
        url: URL to the blog post or threat report

    Returns:
        Dict with keys:
        - success: bool
        - group_name: str (if found)
        - group_desc: str
        - techniques: List[str] (T-codes)
        - tactics: List[str]
        - procedures: List[str]
        - error: str (if failed)
    """
    try:
        # SECURITY: every hop (the URL and each redirect) must resolve only to public addresses
        try:
            response = _fetch_public_url(url, max_redirects=3)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        # SECURITY: Limit response size to prevent DoS
        if len(response.content) > 10 * 1024 * 1024:  # 10MB limit
            return {
                "success": False,
                "error": "Response too large (max 10MB allowed)."
            }

        response.raise_for_status()

        # Parse HTML
        soup = BeautifulSoup(response.content, "html.parser")

        # Extract text content - remove ALL non-content elements
        # This ensures we only analyze the blog post content, not HTML/CSS/JS/navigation
        for element in soup([
            "script",      # JavaScript code
            "style",       # CSS code
            "link",        # CSS links
            "meta",        # Meta tags
            "noscript",    # NoScript tags
            "iframe",      # Embedded frames
            "nav",         # Navigation menus
            "footer",      # Page footer
            "header",      # Page header
            "aside",       # Sidebars
            "form",        # Forms
            "button",      # Buttons
            "input",       # Input fields
            "select",      # Select dropdowns
            "textarea",    # Text areas
            "svg",         # SVG graphics
            "canvas",      # Canvas elements
            "code",        # Inline code (may contain HTML examples)
            "pre",         # Preformatted code blocks
        ]):
            element.decompose()

        # Also remove common non-content class/id patterns. Match whole -/_ delimited
        # tokens: a bare substring match let "ad" hit "node-type-advisory" on CISA's
        # <body> and strip the entire page. Never strip the document or article roots.
        boilerplate = re.compile(
            r'(?:^|[-_])(nav|menu|sidebar|footer|header|banner|ads?|advert|advertisement'
            r'|social|share|comments?|related)(?:$|[-_])',
            re.I,
        )
        content_roots = {"html", "body", "main", "article"}
        for attr in ("class_", "id"):
            for element in soup.find_all(**{attr: boilerplate}):
                if element.name not in content_roots and not element.decomposed:
                    element.decompose()

        text = soup.get_text()

        # Clean up text
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = '\n'.join(chunk for chunk in chunks if chunk)

        # Extract intelligence
        result = {
            "success": True,
            "group_name": _extract_group_name(text, soup),
            "group_desc": _extract_description(text)[:500],  # Limit to 500 chars
            "techniques": _extract_techniques(text),
            "tactics": _extract_tactics(text),
            "procedures": _extract_procedures(text),
            "iocs": _drop_publisher_domains(
                _extract_iocs(text),
                # Judge the publisher by where we landed, not the link we were given
                response.url if isinstance(response.url, str) else url,
            ),
        }

        return result

    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "error": f"Failed to fetch URL: {str(e)}"
        }
    except Exception as e:
        import traceback

        traceback.print_exc()
        return {
            "success": False,
            "error": f"Analysis failed: {str(e)}"
        }


def _extract_group_name(text: str, soup: BeautifulSoup) -> str:
    """Extract threat group name from text."""
    # Common threat group patterns
    patterns = [
        r'(APT\d+)',
        r'(UNC\d+)',
        r'(FIN\d+)',
        r'(Lazarus Group)',
        r'(Scattered Spider)',
        r'(BlackCat|ALPHV)',
        r'(LockBit)',
        r'(Conti)',
        r'(REvil)',
        r'(DarkSide)',
        r'(Wizard Spider)',
        r'(Sandworm)',
        r'(Fancy Bear|APT28)',
        r'(Cozy Bear|APT29)',
        r'(Kimsuky)',
        r'(Carbanak)',
        r'(Turla)',
        r'(OilRig)',
        r'(MuddyWater)',
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)

    # Try to extract from title
    title = soup.find('title')
    if title:
        title_text = title.get_text()
        for pattern in patterns:
            match = re.search(pattern, title_text, re.IGNORECASE)
            if match:
                return match.group(1)

    return ""


def _extract_description(text: str) -> str:
    """Extract a brief description of the threat."""
    # Look for paragraphs that describe the threat
    paragraphs = text.split('\n\n')

    for para in paragraphs[:10]:  # Check first 10 paragraphs
        # Skip very short paragraphs
        if len(para) < 50:
            continue

        # Look for descriptive keywords
        if any(keyword in para.lower() for keyword in [
            'threat actor', 'apt', 'campaign', 'attack', 'malware',
            'ransomware', 'espionage', 'targets', 'operates'
        ]):
            # Return first substantial paragraph
            return para[:500]

    # Fallback: return first substantial paragraph
    for para in paragraphs:
        if len(para) >= 100:
            return para[:500]

    return ""


def _extract_techniques(text: str) -> List[str]:
    """Extract MITRE ATT&CK technique IDs."""
    # Pattern for T-codes (T1234 or T1234.001)
    pattern = r'\bT\d{4}(?:\.\d{3})?\b'
    matches = re.findall(pattern, text)

    # Deduplicate and sort
    techniques = sorted(set(matches))

    return techniques


def _extract_tactics(text: str) -> List[str]:
    """Extract MITRE ATT&CK tactics."""
    mitre_tactics = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact"
    ]

    found_tactics = []
    text_lower = text.lower()

    for tactic in mitre_tactics:
        if tactic.lower() in text_lower:
            found_tactics.append(tactic)

    return found_tactics


def _extract_procedures(text: str) -> List[str]:
    """Extract procedure descriptions."""
    procedures = []

    # Look for sentences that describe procedures
    sentences = re.split(r'[.!?]+', text)

    procedure_keywords = [
        'execut', 'run', 'launch', 'creat', 'modif', 'delet',
        'download', 'upload', 'exfiltrat', 'steal', 'dump',
        'inject', 'exploit', 'comprom', 'lateral', 'persist',
        'escalat', 'evad', 'obfuscat', 'encod', 'decode'
    ]

    for sentence in sentences:
        sentence = sentence.strip()

        # Skip very short or very long sentences
        if len(sentence) < 30 or len(sentence) > 300:
            continue

        # Check if sentence describes a procedure
        if any(keyword in sentence.lower() for keyword in procedure_keywords):
            # Clean up the sentence
            sentence = re.sub(r'\s+', ' ', sentence)
            procedures.append(sentence)

            # Limit to 10 procedures
            if len(procedures) >= 10:
                break

    return procedures


def _registrable_domain(host: str) -> str:
    """cisa.gov for www.cisa.gov, blog.co.uk for x.blog.co.uk; '' if not resolvable."""
    import tldextract

    # Bundled public suffix snapshot only: no network fetch from inside a request
    extract = tldextract.TLDExtract(suffix_list_urls=())
    return extract(host.lower().strip(".")).top_domain_under_public_suffix or ""


def _drop_publisher_domains(iocs: Dict[str, List[str]], page_url: str) -> Dict[str, List[str]]:
    """
    Remove the publisher's own domain from extracted domain IOCs.

    Reports routinely mention their own site (contact links, related advisories),
    which is never an indicator for the activity being reported.
    """
    from urllib.parse import urlparse

    publisher = _registrable_domain(urlparse(page_url).hostname or "")
    if not publisher or not iocs.get("domain"):
        return iocs

    def refang(d: str) -> str:
        return d.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")

    iocs["domain"] = [d for d in iocs["domain"] if _registrable_domain(refang(d)) != publisher]
    return iocs


def _extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extract Indicators of Compromise (IOCs) from text using the file intelligence parser.

    Returns:
        Dict with IOC types as keys (ip, domain, hash, cmd, reg, evt, sw, file)
    """
    from archer.parsers.file_intelligence import FileIntelligenceParser

    extractor = FileIntelligenceParser(use_openai=False, use_local_llm=False)
    iocs = extractor._extract_iocs(text)

    return iocs


def search_crowdstrike_blog(group_name: str) -> Optional[str]:
    """
    Search Crowdstrike blog for a threat group.

    Args:
        group_name: Name of the threat group

    Returns:
        URL to the most relevant blog post, or None if not found
    """
    try:
        search_url = f"https://www.crowdstrike.com/blog/?s={group_name}"
        headers = FETCH_HEADERS

        response = requests.get(search_url, headers=headers, timeout=30)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, "html.parser")

        # Look for first article link
        article = soup.find("article") or soup.find("div", class_=re.compile("post|article|entry"))
        if article:
            link = article.find("a", href=True)
            if link:
                href = link["href"]
                if href.startswith("/"):
                    href = "https://www.crowdstrike.com" + href
                return href

    except Exception as e:
        print(f"Crowdstrike search failed: {e}")

    return None


def search_dfir_report(group_name: str) -> Optional[str]:
    """
    Search The DFIR Report for a threat group.

    Args:
        group_name: Name of the threat group

    Returns:
        URL to the most relevant report, or None if not found
    """
    try:
        # The DFIR Report uses a simpler structure
        search_url = f"https://thedfirreport.com/?s={group_name}"
        headers = FETCH_HEADERS

        response = requests.get(search_url, headers=headers, timeout=30)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, "html.parser")

        # Look for first article link
        article = soup.find("article") or soup.find("div", class_=re.compile("post|article|entry"))
        if article:
            link = article.find("a", href=True)
            if link:
                return link["href"]

    except Exception as e:
        print(f"DFIR Report search failed: {e}")

    return None


def auto_search_blogs(group_name: str) -> Dict:
    """
    Automatically search multiple security blogs for a threat group.

    Args:
        group_name: Name of the threat group

    Returns:
        Dict with best result from blog analysis
    """
    print(f"Searching security blogs for: {group_name}")

    # Try Crowdstrike first
    crowdstrike_url = search_crowdstrike_blog(group_name)
    if crowdstrike_url:
        print(f"Found Crowdstrike article: {crowdstrike_url}")
        result = analyze_blog_post(crowdstrike_url)
        if result.get("success"):
            result["source"] = "Crowdstrike"
            result["source_url"] = crowdstrike_url
            return result

    # Try The DFIR Report
    dfir_url = search_dfir_report(group_name)
    if dfir_url:
        print(f"Found DFIR Report article: {dfir_url}")
        result = analyze_blog_post(dfir_url)
        if result.get("success"):
            result["source"] = "The DFIR Report"
            result["source_url"] = dfir_url
            return result

    return {
        "success": False,
        "error": f"No blog posts found for {group_name}"
    }
