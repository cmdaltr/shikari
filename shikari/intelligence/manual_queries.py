"""
Manual OSINT lookups for a domain (from PRISM): the searches and commands worth running by hand
before an engagement, as links where the service has a search URL and as commands where it doesn't.

Shikari doesn't run any of them; the exposure map shows them beside what the profile found, so the
operator can go further than the automated profile on the sources it doesn't query.
"""

import re
from typing import Dict, List
from urllib.parse import quote_plus

_GOOGLE = "https://www.google.com/search?q="
_HOSTNAME = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _base(domain: str) -> str:
    d = (domain or "").strip().lower()
    return d[4:] if d.startswith("www.") else d


def _dorks(base: str, org: str) -> Dict[str, List[str]]:
    return {
        "Exposed documents and files": [
            f"site:{base} filetype:pdf OR filetype:docx OR filetype:xlsx",
            f"site:{base} filetype:env OR filetype:config OR filetype:cfg",
            f"site:{base} filetype:log OR filetype:bak OR filetype:sql",
            f'site:{base} "index of" (passwords OR credentials OR secret)',
        ],
        "Login and admin panels": [
            f"site:{base} inurl:login OR inurl:admin OR inurl:portal",
            f"site:{base} inurl:wp-admin OR inurl:phpmyadmin OR inurl:cpanel",
            f'site:{base} intext:"Sign in" inurl:auth',
        ],
        "APIs and infrastructure": [
            f"site:{base} inurl:api OR inurl:swagger OR inurl:graphql",
            f"site:{base} inurl:jenkins OR inurl:jira OR inurl:confluence",
            f'"{base}" site:s3.amazonaws.com OR site:blob.core.windows.net',
            f'"{base}" site:github.com OR site:gitlab.com',
        ],
        "People and leaks": [
            f'"@{base}" site:linkedin.com/in',
            f'site:linkedin.com/in "{org}" "CISO" OR "Head of Security" OR "Security Manager"',
            f'site:linkedin.com/in "{org}" "IT" OR "Security" OR "DevOps" OR "Engineer"',
            f'"{base}" site:pastebin.com OR site:hastebin.com',
            f'"{org}" "Splunk" OR "Sentinel" OR "QRadar" OR "Elastic" site:linkedin.com',
        ],
        "Technology and errors": [
            f'site:{base} "Powered by" OR "Built with" OR "Running on"',
            f'site:{base} intext:"error" intext:"stack trace"',
            f'"{base}" site:trello.com OR site:notion.so OR site:airtable.com',
        ],
    }


def queries(domain: str) -> List[Dict]:
    """[{title, items: [{text, url}]}]: url is "" for a command to run in a terminal."""
    base = _base(domain)
    if not _HOSTNAME.match(base):
        return []
    org = base.split(".")[0]
    groups = [{"title": f"Google: {title.lower()}", "items": [{"text": q, "url": _GOOGLE + quote_plus(q)} for q in qs]}
              for title, qs in _dorks(base, org).items()]
    q = quote_plus
    groups += [
        {"title": "Certificates and passive DNS", "items": [
            {"text": f"crt.sh: %.{base}", "url": f"https://crt.sh/?q={q('%.' + base)}"},
            {"text": f"VirusTotal relations: {base}", "url": f"https://www.virustotal.com/gui/domain/{base}/relations"},
            {"text": f"SecurityTrails A history: {base}", "url": f"https://securitytrails.com/domain/{base}/history/a"},
            {"text": f"Hurricane Electric BGP: {base}", "url": f"https://bgp.he.net/dns/{base}"},
        ]},
        {"title": "Internet-facing hosts", "items": [
            {"text": f"Shodan: hostname:{base}", "url": f"https://www.shodan.io/search?query={q('hostname:' + base)}"},
            {"text": f"Shodan: ssl.cert.subject.cn:{base}",
             "url": f"https://www.shodan.io/search?query={q('ssl.cert.subject.cn:' + base)}"},
            {"text": f"Censys: {base}", "url": f"https://search.censys.io/search?resource=hosts&q={q(base)}"},
        ]},
        {"title": "DNS and email posture (terminal)", "items": [
            {"text": f"dig +short MX {base}", "url": ""},
            {"text": f"dig +short NS {base}", "url": ""},
            {"text": f"dig +short TXT {base} | grep -i spf", "url": ""},
            {"text": f"dig +short TXT _dmarc.{base}", "url": ""},
            {"text": f"dig +short TXT selector1._domainkey.{base}", "url": ""},
            {"text": f"subfinder -d {base} -silent | dnsx -silent -a -resp", "url": ""},
        ]},
    ]
    return groups
