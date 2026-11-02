"""The recent-CVE cache: 30 days of NVD and KEV, kept current, researched in advance for KEV and the stack."""

from datetime import datetime, timedelta, timezone

import pytest

from shikari.intelligence import cve_feed

Y = datetime.now(timezone.utc).year  # fixture IDs from this year: older ones aren't recent


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
    nvd = {"recent": [_cve(f"CVE-{Y}-1000", 3, ["cpe:2.3:a:fortinet:fortios:7.0:*"]), _cve(f"CVE-{Y}-1001", 10)],
           "old": [_cve("CVE-2019-0001", 2000)]}

    def get(url, params=None, headers=None, timeout=None):
        calls.append(dict(params or {}))
        if url == cve_feed.KEV_URL:
            return _Resp({"vulnerabilities": [
                {"cveID": f"CVE-{Y}-1001", "dateAdded": _iso(2)[:10]},
                {"cveID": "CVE-2019-0001", "dateAdded": _iso(5)[:10], "knownRansomwareCampaignUse": "Known"},
                {"cveID": "CVE-2018-0001", "dateAdded": _iso(400)[:10]}]})
        if params.get("cveId") == "CVE-2019-0001":
            return _Resp({"totalResults": 1, "vulnerabilities": [{"cve": nvd["old"][0]}]})
        return _Resp({"totalResults": 2, "vulnerabilities": [{"cve": c} for c in nvd["recent"]]})

    monkeypatch.setattr(cve_feed.requests, "get", get)
    return calls


def test_the_window_holds_recent_cves_only_even_ones_kev_just_added(feed):
    counts = cve_feed.refresh(research=False)

    cves = cve_feed._load()["cves"]
    assert set(cves) == {f"CVE-{Y}-1000", f"CVE-{Y}-1001"}  # not 2019's, though KEV added it this week
    assert cves[f"CVE-{Y}-1001"]["kev"] and counts["kev"] == 1
    assert not any(c.get("cveId") for c in feed)  # nor its NVD record asked for
    assert "pubStartDate" in feed[0]  # the first fill is by publication date
    assert cve_feed.record(f"cve-{Y}-1000")["description"] == f"CVE-{Y}-1000 description"


def test_later_refreshes_ask_for_what_nvd_modified(feed):
    cve_feed.refresh(research=False)
    feed.clear()
    cve_feed.refresh(research=False)
    assert "lastModStartDate" in feed[0] and "pubStartDate" not in feed[0]


def test_an_old_id_published_this_month_is_not_recent():
    cutoff = "2026-09-23T15:00:00"
    assert not cve_feed._recent({"cve_id": "CVE-2013-10076", "published": "2026-10-10T09:00:00.000"}, cutoff)
    assert not cve_feed._recent({"cve_id": "CVE-2025-63564", "published": "2026-09-23T16:00:00.000"}, cutoff)
    assert cve_feed._recent({"cve_id": "CVE-2026-109619", "published": "2026-10-21T09:00:00.000"}, cutoff)
    # In January the window starts in December: last year's IDs are recent then
    assert cve_feed._recent({"cve_id": "CVE-2026-50001", "published": "2027-01-05T09:00:00.000"}, "2026-12-06T00:00:00")


def test_cves_leave_the_window_unless_hunted():
    cutoff = _iso(30)[:19]
    year = cutoff[:4]
    a, b, c = f"CVE-{year}-1111", f"CVE-{year}-2222", "CVE-2016-3081"
    assert cve_feed._in_window({"cve_id": a, "published": _iso(3)}, cutoff, set())
    assert not cve_feed._in_window({"cve_id": b, "published": _iso(45)}, cutoff, set())
    assert cve_feed._in_window({"cve_id": b, "published": _iso(45)}, cutoff, {b})
    assert not cve_feed._in_window({"cve_id": c, "published": _iso(900), "kev": {"date_added": _iso(4)[:10]}},
                                   cutoff, set())


def test_the_picker_leaves_out_a_hunted_cve_once_it_is_older_than_the_window(feed):
    cve_feed.refresh(research=False)
    data = cve_feed._load()
    data["cves"][f"CVE-{Y}-1001"] = {**data["cves"][f"CVE-{Y}-1001"], "published": _iso(60)}
    data["hunted"] = [f"CVE-{Y}-1001"]
    cve_feed._save(data)
    assert [c["cve_id"] for c in cve_feed.recent()["cves"]] == [f"CVE-{Y}-1000"]
    assert cve_feed.record(f"CVE-{Y}-1001")  # still there for its results


def test_a_hunt_marked_during_a_refresh_survives_it(feed, monkeypatch):
    real = cve_feed._kev

    def kev_and_a_hunt():
        cve_feed.mark_hunted(["CVE-2020-9999"])  # a hunt starts while the refresh is reading
        return real()

    monkeypatch.setattr(cve_feed, "_kev", kev_and_a_hunt)
    cve_feed.refresh(research=False)
    assert "CVE-2020-9999" in cve_feed._load()["hunted"]


def test_kev_comes_first_then_the_stack(monkeypatch):
    monkeypatch.setattr("shikari.intelligence.tech_stack.cpe_products",
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


def test_a_cve_nvd_has_not_analysed_is_matched_on_its_description():
    assert "wordpress" in cve_feed.products({"cpes": [], "description": "The Masteriyo LMS WordPress plugin before 3.4.2 ..."})


def test_stack_cves_are_researched_highest_score_first():
    cves = {"CVE-LOW": {"published": _iso(1), "products": ["linux"], "cvss_v3": None},
            "CVE-HIGH": {"published": _iso(9), "products": ["linux"], "cvss_v3": {"score": 9.8}},
            "CVE-KEV": {"published": _iso(20), "products": [], "kev": {"date_added": _iso(2)[:10]}}}
    assert cve_feed.wanted(cves, [["linux"]]) == ["CVE-KEV", "CVE-HIGH", "CVE-LOW"]


def test_the_picker_filters_and_pages(feed):
    cve_feed.refresh(research=False)
    everything = cve_feed.recent()
    assert everything["total"] == 2 and [c["cve_id"] for c in everything["cves"]][0] == f"CVE-{Y}-1000"
    assert cve_feed.recent(kev_only=True)["total"] == 1
    assert cve_feed.recent(q="1001 description")["total"] == 1
    assert cve_feed.recent(offset=1, limit=1)["cves"][0]["cve_id"] == f"CVE-{Y}-1001"
    row = everything["cves"][0]
    assert set(row) >= {"cve_id", "published", "description", "cvss_v3", "kev", "products", "on_stack", "researched"}


def test_the_api_passes_the_filters_and_caps_the_page(feed, monkeypatch):
    from types import SimpleNamespace

    from fastapi.testclient import TestClient

    import shikari.app as web

    cve_feed.refresh(research=False)
    user = SimpleNamespace(tech_stack='["fortigate"]')
    monkeypatch.setattr(web, "require_auth", lambda request, session: (user, SimpleNamespace(close=lambda: None)))
    monkeypatch.setattr("shikari.intelligence.tech_stack.as_stack", lambda ids: list(ids))
    client = TestClient(web.app)  # no startup: no refresh thread

    body = client.get("/api/cves/recent", params={"kev": "true", "limit": 999}).json()
    assert body["total"] == 1 and body["limit"] == 200 and body["has_stack"] and body["window_days"] == 30
    assert client.get("/api/cves/recent", params={"q": "CVE-2019"}).json()["total"] == 0
