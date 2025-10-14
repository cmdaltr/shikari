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
        # Fetch the blog post
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        # Parse HTML
        soup = BeautifulSoup(response.content, "html.parser")

        # Extract text content
        # Remove script and style elements
        for script in soup(["script", "style", "nav", "footer", "header"]):
            script.decompose()

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
        }

        return result

    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "error": f"Failed to fetch URL: {str(e)}"
        }
    except Exception as e:
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
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

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
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

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
