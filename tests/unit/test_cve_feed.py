"""The recent-CVE cache: 30 days of NVD and KEV, kept current, researched in advance for KEV and the stack."""

from datetime import datetime, timedelta, timezone

import pytest

from archer.intelligence import cve_feed


def _iso(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000")


def _cve(cid, days_ago, cpes=()):
    return {"id": cid, "published": _iso(days_ago), "lastModified": _iso(days_ago),
            "descriptions": [{"value": f"{cid} description"}],
            "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": c} for c in cpes]}]}]}


class _Resp:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self.body


@pytest.fixture
def feed(tmp_path, monkeypatch):
    monkeypatch.setattr(cve_feed, "CACHE_PATH", str(tmp_path / "cves.json"))
    monkeypatch.setattr(cve_feed.time, "sleep", lambda s: None)
    calls = []
    nvd = {"recent": [_cve("CVE-2026-1000", 3, ["cpe:2.3:a:fortinet:fortios:7.0:*"]), _cve("CVE-2026-1001", 10)],
           "old": [_cve("CVE-2019-0001", 2000)]}

    def get(url, params=None, headers=None, timeout=None):
        calls.append(dict(params or {}))
        if url == cve_feed.KEV_URL:
            return _Resp({"vulnerabilities": [
                {"cveID": "CVE-2026-1001", "dateAdded": _iso(2)[:10]},
                {"cveID": "CVE-2019-0001", "dateAdded": _iso(5)[:10], "knownRansomwareCampaignUse": "Known"},
                {"cveID": "CVE-2018-0001", "dateAdded": _iso(400)[:10]}]})
        if params.get("cveId") == "CVE-2019-0001":
            return _Resp({"totalResults": 1, "vulnerabilities": [{"cve": nvd["old"][0]}]})
        return _Resp({"totalResults": 2, "vulnerabilities": [{"cve": c} for c in nvd["recent"]]})

    monkeypatch.setattr(cve_feed.requests, "get", get)
    return calls


def test_the_window_holds_recent_cves_and_old_ones_kev_just_added(feed):
    counts = cve_feed.refresh(research=False)

    cves = cve_feed._load()["cves"]
    assert set(cves) == {"CVE-2026-1000", "CVE-2026-1001", "CVE-2019-0001"}
    assert cves["CVE-2019-0001"]["kev"]["ransomware"] and counts["kev"] == 2
    assert "pubStartDate" in feed[0]  # the first fill is by publication date
    assert cve_feed.record("cve-2026-1000")["description"] == "CVE-2026-1000 description"


def test_later_refreshes_ask_for_what_nvd_modified(feed):
    cve_feed.refresh(research=False)
    feed.clear()
    cve_feed.refresh(research=False)
    assert "lastModStartDate" in feed[0] and "pubStartDate" not in feed[0]


def test_cves_leave_the_window_unless_hunted_or_newly_in_kev():
    cutoff = _iso(30)[:19]
    assert cve_feed._in_window({"cve_id": "A", "published": _iso(3)}, cutoff, set())
    assert not cve_feed._in_window({"cve_id": "B", "published": _iso(45)}, cutoff, set())
    assert cve_feed._in_window({"cve_id": "B", "published": _iso(45)}, cutoff, {"B"})
    assert cve_feed._in_window({"cve_id": "C", "published": _iso(900), "kev": {"date_added": _iso(4)[:10]}},
                               cutoff, set())


def test_a_hunt_marked_during_a_refresh_survives_it(feed, monkeypatch):
    real = cve_feed._kev

    def kev_and_a_hunt():
        cve_feed.mark_hunted(["CVE-2020-9999"])  # a hunt starts while the refresh is reading
        return real()

    monkeypatch.setattr(cve_feed, "_kev", kev_and_a_hunt)
    cve_feed.refresh(research=False)
    assert "CVE-2020-9999" in cve_feed._load()["hunted"]


def test_kev_comes_first_then_the_stack(monkeypatch):
    monkeypatch.setattr("archer.intelligence.tech_stack.cpe_products",
                        lambda cpes: ["fortigate"] if any("fortinet" in c for c in cpes) else [])
    cves = {"CVE-A": {"published": _iso(1), "cpes": []},
            "CVE-B": {"published": _iso(2), "cpes": ["cpe:2.3:a:fortinet:fortios"]},
            "CVE-C": {"published": _iso(3), "cpes": [], "kev": {"date_added": _iso(1)[:10]}}}
    assert cve_feed.wanted(cves, [["fortigate"]]) == ["CVE-C", "CVE-B"]
    assert cve_feed.wanted(cves, []) == ["CVE-C"]


def test_a_fetch_cut_short_resumes_where_it_was_saved(feed, monkeypatch):
    monkeypatch.setattr(cve_feed, "SAVE_EVERY", 1)
    monkeypatch.setattr(cve_feed, "PAGE", 1)
    real = cve_feed.requests.get
    calls = {"n": 0}

    def drop_the_second_page(url, params=None, **kw):
        if url == cve_feed.NVD_URL and params.get("startIndex") == 1 and not calls["n"]:
            calls["n"] += 1
            raise cve_feed.requests.ConnectionError("dropped")
        return real(url, params=params, **kw)

    monkeypatch.setattr(cve_feed.requests, "get", drop_the_second_page)
    monkeypatch.setattr(cve_feed, "TRIES", 1)
    with pytest.raises(cve_feed.requests.ConnectionError):
        cve_feed.refresh(research=False)
    saved = cve_feed._load()
    assert saved["pending"]["index"] == 1 and saved["cves"] and not saved.get("last_refresh")

    cve_feed.refresh(research=False)  # carries on from the second page
    done = cve_feed._load()
    assert done["pending"] is None and done["last_refresh"]
    assert any(p.get("startIndex") == 1 and "pubStartDate" in p for p in feed)
