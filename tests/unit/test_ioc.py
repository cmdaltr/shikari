"""IOC parsing (archer.intelligence.ioc) and the IOC-search results cache (ioc_search)."""

import json
from datetime import datetime, timezone
from pathlib import Path

from archer.intelligence import ioc


def test_classify_common_types():
    assert ioc.classify("1.2.3.4") == ("ipv4", "1.2.3.4")
    assert ioc.classify("2001:db8::1")[0] == "ipv6"
    assert ioc.classify("CVE-2021-26855") == ("cve", "CVE-2021-26855")
    assert ioc.classify("44D88612FEA8A8F36DE82E1278ABB02F") == ("md5", "44d88612fea8a8f36de82e1278abb02f")
    assert ioc.classify("evil.com") == ("domain", "evil.com")
    assert ioc.classify("user@evil.com") == ("email", "user@evil.com")
    assert ioc.classify("http://evil.com/x")[0] == "url"
    assert ioc.classify("just some words")[0] is None


def test_refang_restores_defanged_forms():
    assert ioc.classify("hxxp://evil[.]com/path") == ("url", "http://evil.com/path")
    assert ioc.classify("1[.]2[.]3[.]4") == ("ipv4", "1.2.3.4")
    assert ioc.classify("evil(dot)com") == ("domain", "evil.com")
    assert ioc.classify("user[@]bad.co.uk") == ("email", "user@bad.co.uk")


def test_variants_cover_defang_styles_and_match():
    t, v = ioc.classify("evil.com")
    vs = ioc.variants(v, t)
    assert "evil.com" in vs and "evil[.]com" in vs and "evil(dot)com" in vs
    text = "Actor staged on evil[.]com before C2."
    m = ioc.find_in(text, vs)
    assert m and m[0] == "evil[.]com"
    assert "evil[.]com" in ioc.snippet(text, m[1], len(m[0]))


def test_find_in_is_case_insensitive_and_misses_absent():
    t, v = ioc.classify("CVE-2024-3400")
    assert ioc.find_in("patch for cve-2024-3400 released", ioc.variants(v, t))
    assert ioc.find_in("nothing here", ioc.variants(v, t)) is None


def test_results_cache_reuse_and_purge(tmp_path, monkeypatch):
    from archer.intelligence import ioc_search as m
    monkeypatch.setattr(m, "_RESULTS_CACHE", tmp_path / "ioc_results.json")
    monkeypatch.setattr(m, "load_sources", lambda: [{"name": "Talos", "url": "u", "tier": 1}])
    today = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    fixture = (f'<rss version="2.0"><channel><item><title>evil[.]com seen</title>'
               f'<link>https://x/r</link><description>payload on evil[.]com</description>'
               f'<pubDate>{today}</pubDate></item></channel></rss>').encode()
    monkeypatch.setattr(m, "_fetch", lambda url, ttl=0: fixture)

    first = m.search("evil.com")
    assert first["total"] == 1 and first["cached"] is False
    assert m.search("evil.com")["cached"] is True              # served from cache
    assert [r["value"] for r in m.recent_iocs()] == ["evil.com"]

    # An entry older than the retention window is purged on the next access
    cache = json.loads(Path(m._RESULTS_CACHE).read_text())
    cache["ipv4:9.9.9.9:all:7"] = {"value": "9.9.9.9", "ioc_type": "ipv4",
                                   "searched": "2020-01-01T00:00:00+00:00", "total": 1, "result": {}}
    Path(m._RESULTS_CACHE).write_text(json.dumps(cache))
    assert "9.9.9.9" not in [r["value"] for r in m.recent_iocs()]
