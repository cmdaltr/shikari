"""Threat feed: parsing RSS/Atom, and which posts matter to which industries."""

from types import SimpleNamespace

from archer.intelligence import feed

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Lazarus  targets banks</title><link>https://example.com/a</link>
<pubDate>Mon, 12 Oct 2026 09:00:00 +0000</pubDate><description>&lt;p&gt;Read more&lt;/p&gt;</description></item>
<item><title>No link</title><pubDate>Mon, 12 Oct 2026 09:00:00 +0000</pubDate></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Atom post</title><link rel="alternate" href="https://example.com/b"/>
<updated>2026-10-11T08:00:00Z</updated><summary>s</summary></entry></feed>"""


def test_rss_and_atom_are_parsed():
    rss = feed.parse_feed(RSS, "Src")
    assert [(p["title"], p["url"], p["summary"]) for p in rss] == [("Lazarus targets banks", "https://example.com/a", "Read more")]
    assert rss[0]["published"].startswith("2026-10-12T09:00")
    atom = feed.parse_feed(ATOM, "Src")
    assert atom[0]["url"] == "https://example.com/b" and atom[0]["published"].startswith("2026-10-11T08:00")


def _post(**kw):
    return {"title": "t", "techniques": [], "iocs": 0, "cves": [], "groups": [], "sectors": {}, "opportunistic": [], **kw}


def test_classification_by_group_targeting_and_opportunistic_activity():
    apt38 = {"id": "G0082", "name": "APT38", "sectors": ["Finance / Banking"], "opportunistic": False}
    post = _post(groups=[apt38], techniques=["T1059"])
    assert feed.classify(post, ["Finance / Banking"])["industry"] == ["APT38 (G0082) targets Finance / Banking"]
    assert feed.classify(post, ["Government"]) is None
    supply = _post(opportunistic=["supply-chain compromise"], iocs=5)
    assert feed.classify(supply, ["Government"]) == {"industry": [], "opportunistic": ["supply-chain compromise"]}
    assert feed.classify(_post(opportunistic=["botnet"]), ["Government"]) is None  # nothing technical
    assert feed.classify(_post(sectors={"Government": 5}, cves=["CVE-2026-1"]), ["Government"])["industry"] == ["names Government (5×)"]


def test_group_names_match_as_proper_nouns_only():
    bundle = SimpleNamespace(objects=[
        {"type": "intrusion-set", "name": "Silence", "aliases": ["Silence"], "external_references": [{"source_name": "mitre-attack", "external_id": "G0091"}]},
        {"type": "intrusion-set", "name": "APT29", "aliases": ["Cozy Bear"], "external_references": [{"source_name": "mitre-attack", "external_id": "G0016"}]},
    ])
    groups = feed.group_index(bundle, {"G0016": {"target_sectors": "Government", "primary_objectives": "Espionage"}})
    assert [g["name"] for g in groups] == ["APT29"]
    assert groups[0]["pattern"].search("attributed to Cozy Bear.") and not groups[0]["pattern"].search("cozy bear")
    assert groups[0]["sectors"] == ["Government"]


def test_advisory_boilerplate_is_not_reported_exploitation():
    def reasons(text):
        return {r for pattern, r in feed.OPPORTUNISTIC if pattern.search(text)}

    assert "vulnerability exploitation" in reasons("Threat Actors Exploit Critical AhsayCBS Flaws")
    assert "vulnerability exploitation" in reasons("attackers have been exploiting CVE-2026-1234")
    assert not reasons("Successful exploitation of these vulnerabilities could allow an attacker to exploit the device")
