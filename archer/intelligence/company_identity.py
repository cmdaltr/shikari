"""
Who is behind a domain: company name, home country, headquarters and sector.

IP geolocation describes the CDN edge, not the company (tesco.com resolved to
an Akamai node in Hesse, Germany), and keyword-matching the domain name finds
no sector for brand names like "tesco". Evidence is gathered from sources that
describe the organisation itself, strongest first:

1. Wikidata, matched on official website (P856) and walked up parent
   organisations (P749) to the most-referenced entity, so tesco.com resolves to
   Tesco plc rather than one of the Tesco Express store brands sharing the URL.
2. The company's homepage: schema.org Organization data, page language/locale
   and visible text. Large retailers often block automated fetches, so this is
   best effort.
3. The country-code TLD.
"""

import json
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional

import requests

WIKIDATA_SPARQL = "https://query.wikidata.org/sparql"
# Wikimedia policy requires an identifying User-Agent for the query service
WIKIDATA_UA = "Archer/1.0 (threat profiling; https://github.com/cmdaltr/archer)"

# Profiler sector key -> phrases found in Wikidata industry/type labels or homepage text
SECTOR_TERMS: Dict[str, List[str]] = {
    "retail": ["retail", "supermarket", "grocery", "groceries", "convenience store", "department store",
               "hypermarket", "e-commerce", "online shop", "store chain", "shopping"],
    "finance": ["bank", "banking", "financial services", "insurance", "investment", "asset management",
                "payment", "credit card", "building society"],
    "healthcare": ["health care", "healthcare", "hospital", "pharmaceutical", "medical", "biotechnology"],
    "technology": ["software", "information technology", "technology company", "cloud computing",
                   "semiconductor", "internet company"],
    "energy": ["energy", "oil and gas", "petroleum", "electric utility", "electricity", "natural gas", "utility"],
    "defense": ["defence", "defense", "arms industry", "aerospace", "military"],
    "government": ["government", "government agency", "ministry", "public body", "local authority"],
    "manufacturing": ["manufacturing", "manufacturer", "automotive", "industrial"],
    "telecommunications": ["telecommunications", "telecom", "mobile network operator", "internet service provider"],
    "media": ["media", "broadcasting", "publishing", "newspaper", "entertainment"],
}

# Two-letter ccTLDs worth trusting as a company-country hint (generic-use ones like .io/.co/.tv excluded)
CCTLD_COUNTRY = {
    "uk": "United Kingdom", "ie": "Ireland", "de": "Germany", "fr": "France", "nl": "Netherlands",
    "be": "Belgium", "es": "Spain", "it": "Italy", "pt": "Portugal", "se": "Sweden", "no": "Norway",
    "dk": "Denmark", "fi": "Finland", "pl": "Poland", "cz": "Czech Republic", "sk": "Slovakia",
    "hu": "Hungary", "at": "Austria", "ch": "Switzerland", "us": "United States", "ca": "Canada",
    "au": "Australia", "nz": "New Zealand", "jp": "Japan", "kr": "South Korea", "cn": "China",
    "in": "India", "sg": "Singapore", "za": "South Africa", "br": "Brazil", "mx": "Mexico",
    "ru": "Russia", "ua": "Ukraine", "il": "Israel", "ae": "United Arab Emirates", "sa": "Saudi Arabia",
}

# Homepage language tags with a region map to a country
LOCALE_COUNTRY = {
    "gb": "United Kingdom", "uk": "United Kingdom", "ie": "Ireland", "us": "United States",
    "au": "Australia", "ca": "Canada", "nz": "New Zealand", "de": "Germany", "fr": "France",
    "nl": "Netherlands", "es": "Spain", "it": "Italy", "in": "India", "sg": "Singapore", "za": "South Africa",
}

# Wikidata labels the profiler's threat maps don't use verbatim
COUNTRY_ALIASES = {"People's Republic of China": "China", "United States of America": "United States"}


def _norm_country(name: Optional[str]) -> Optional[str]:
    return COUNTRY_ALIASES.get(name, name) if name else None


def sector_from_labels(labels: List[str]) -> Optional[str]:
    text = " | ".join(labels).lower()
    scores = {sector: sum(text.count(term) for term in terms) for sector, terms in SECTOR_TERMS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] else None


def _site_variants(domain: str) -> List[str]:
    bare = domain.lower().removeprefix("www.")
    hosts = [bare, f"www.{bare}"]
    return [f"<{scheme}://{host}{slash}>" for scheme in ("https", "http") for host in hosts for slash in ("/", "")]


@lru_cache(maxsize=256)
def lookup_wikidata(domain: str) -> Optional[Dict[str, Any]]:
    """Most-referenced organisation whose official website (or a subsidiary's) is the domain."""
    query = f"""
SELECT ?org ?orgLabel ?links ?countryLabel ?hqLabel ?hqCountryLabel
       (GROUP_CONCAT(DISTINCT ?indLabel; separator="|") AS ?industries)
       (GROUP_CONCAT(DISTINCT ?instLabel; separator="|") AS ?types) WHERE {{
  VALUES ?site {{ {" ".join(_site_variants(domain))} }}
  ?item wdt:P856 ?site .
  ?item wdt:P749* ?org .
  ?org wikibase:sitelinks ?links .
  OPTIONAL {{ ?org wdt:P17 ?country }}
  OPTIONAL {{ ?org wdt:P159 ?hq . OPTIONAL {{ ?hq wdt:P17 ?hqCountry }} }}
  OPTIONAL {{ ?org wdt:P452 ?ind . ?ind rdfs:label ?indLabel FILTER(LANG(?indLabel) = "en") }}
  OPTIONAL {{ ?org wdt:P31 ?inst . ?inst rdfs:label ?instLabel FILTER(LANG(?instLabel) = "en") }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}}
GROUP BY ?org ?orgLabel ?links ?countryLabel ?hqLabel ?hqCountryLabel
ORDER BY DESC(?links) LIMIT 1"""
    try:
        resp = requests.get(
            WIKIDATA_SPARQL,
            params={"query": query, "format": "json"},
            headers={"User-Agent": WIKIDATA_UA, "Accept": "application/sparql-results+json"},
            timeout=20,
        )
        resp.raise_for_status()
        rows = resp.json()["results"]["bindings"]
    except Exception as e:
        print(f"  ⚠ Wikidata lookup failed: {e}")
        return None
    if not rows:
        return None

    row = {k: v["value"] for k, v in rows[0].items()}
    split = lambda key: [x for x in row.get(key, "").split("|") if x]
    return {
        "name": row.get("orgLabel"),
        "qid": row.get("org", "").rsplit("/", 1)[-1],
        # HQ country is the company's home; P17 on multinationals can be any operating country
        "country": _norm_country(row.get("hqCountryLabel") or row.get("countryLabel")),
        "headquarters": row.get("hqLabel"),
        "industries": split("industries"),
        "types": split("types"),
    }


def homepage_signals(domain: str) -> Dict[str, Any]:
    """Best-effort company signals from the homepage (SSRF-checked fetch, every redirect re-validated)."""
    from bs4 import BeautifulSoup
    from archer.parsers.blog_analyzer import _fetch_public_url

    signals: Dict[str, Any] = {"name": None, "country": None, "country_basis": None, "text": ""}
    try:
        resp = _fetch_public_url(f"https://{domain}/")
        if not resp.ok or len(resp.content) > 5 * 1024 * 1024:
            return signals
    except Exception:
        return signals

    soup = BeautifulSoup(resp.content, "html.parser")

    for tag in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(tag.string or "")
        except (ValueError, TypeError):
            continue
        for node in data if isinstance(data, list) else data.get("@graph", [data]) if isinstance(data, dict) else []:
            if not isinstance(node, dict) or "Organization" not in str(node.get("@type", "")) and "Store" not in str(node.get("@type", "")):
                continue
            signals["name"] = signals["name"] or node.get("name")
            address = node.get("address") or {}
            country = address.get("addressCountry") if isinstance(address, dict) else None
            if isinstance(country, dict):
                country = country.get("name")
            if country and not signals["country"]:
                signals["country"] = CCTLD_COUNTRY.get(str(country).lower(), country)
                signals["country_basis"] = "schema.org address"

    site_name = soup.find("meta", attrs={"property": "og:site_name"})
    if site_name and not signals["name"]:
        signals["name"] = site_name.get("content")

    if not signals["country"]:
        locale = (soup.find("meta", attrs={"property": "og:locale"}) or {}).get("content") if soup.find(
            "meta", attrs={"property": "og:locale"}) else (soup.html.get("lang") if soup.html else None)
        region = re.split(r"[-_]", locale or "")[-1].lower() if locale and re.search(r"[-_]", locale) else None
        if region in LOCALE_COUNTRY:
            signals["country"] = LOCALE_COUNTRY[region]
            signals["country_basis"] = f"page locale {locale}"

    desc = soup.find("meta", attrs={"name": "description"})
    title = soup.title.string if soup.title and soup.title.string else ""
    signals["text"] = " ".join(filter(None, [title, desc.get("content") if desc else "", soup.get_text(" ", strip=True)[:5000]]))
    return signals


def resolve_identity(domain: str) -> Dict[str, Any]:
    """
    Company identity with the source of every field, for the profiler and the UI.

    country/sector are None when no source describes the company; callers must not
    substitute hosting IP geolocation.
    """
    domain = domain.lower().strip().removeprefix("www.")
    identity: Dict[str, Any] = {
        "company_name": None, "country": None, "headquarters": None, "sector": None,
        "industry_labels": [], "organisation_types": [], "evidence": [], "confidence": "none",
    }

    wd = lookup_wikidata(domain)
    if wd:
        identity.update(company_name=wd["name"], country=wd["country"], headquarters=wd["headquarters"],
                        industry_labels=wd["industries"], organisation_types=wd["types"])
        identity["sector"] = sector_from_labels(wd["industries"] + wd["types"])
        if identity["sector"]:
            # "supermarket chain" before "public company" / "brick and mortar"
            terms = SECTOR_TERMS[identity["sector"]]
            identity["organisation_types"] = sorted(
                wd["types"], key=lambda t: not any(term in t.lower() for term in terms))
        identity["evidence"].append(f"Wikidata {wd['qid']}: {wd['name']}"
                                    + (f", HQ {wd['headquarters']}" if wd["headquarters"] else "")
                                    + (f", {wd['country']}" if wd["country"] else ""))

    if not (identity["country"] and identity["sector"] and identity["company_name"]):
        page = homepage_signals(domain)
        if page["name"] and not identity["company_name"]:
            identity["company_name"] = page["name"]
            identity["evidence"].append(f"Homepage name: {page['name']}")
        if page["country"] and not identity["country"]:
            identity["country"] = page["country"]
            identity["evidence"].append(f"Homepage {page['country_basis']}: {page['country']}")
        if not identity["sector"] and page["text"]:
            identity["sector"] = sector_from_labels([page["text"]])
            if identity["sector"]:
                identity["evidence"].append(f"Homepage content suggests {identity['sector']}")

    tld = domain.rsplit(".", 1)[-1]
    if not identity["country"] and tld in CCTLD_COUNTRY:
        identity["country"] = CCTLD_COUNTRY[tld]
        identity["evidence"].append(f"Country-code TLD .{tld}")

    if not identity["company_name"]:
        import tldextract
        label = tldextract.TLDExtract(suffix_list_urls=())(domain).domain
        identity["company_name"] = label.replace("-", " ").title() if label else domain

    identity["confidence"] = "high" if wd and identity["country"] and identity["sector"] else (
        "medium" if identity["country"] or identity["sector"] else "none")
    return identity
