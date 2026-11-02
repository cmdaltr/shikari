"""
The server asks for the latest ATT&CK on every start, cheaply (shikari.mitre.enterprise),
and the Library lists every SIEM in Shikari's order.
"""
import json

import requests

from shikari.mitre import enterprise

BUNDLE = json.dumps({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000", "objects": [
    {"type": "x-mitre-collection", "id": "x-mitre-collection--00000000-0000-4000-8000-000000000001",
     "spec_version": "2.1", "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
     "name": "Enterprise ATT&CK", "x_mitre_version": "19.2"}]})


class _Resp:
    def __init__(self, status, text="", headers=None):
        self.status_code, self.text, self.headers = status, text, headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(self.status_code)


def _setup(tmp_path, monkeypatch, responses):
    calls = []
    monkeypatch.setattr(enterprise, "_cache_path", lambda url: tmp_path / "enterprise-attack.json")
    monkeypatch.setattr(enterprise.requests, "get", lambda url, **kw: (calls.append(kw.get("headers")), responses.pop(0))[1])
    return calls


def test_first_start_downloads_and_records_the_version(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, [_Resp(200, BUNDLE, {"ETag": '"abc"'})])
    enterprise.get_stix_data("https://x/enterprise-attack.json", check_latest=True)
    assert enterprise.LAST_LOAD["version"] == "19.2" and enterprise.LAST_LOAD["source"] == "network"
    meta = json.loads((tmp_path / "enterprise-attack.json.meta.json").read_text())
    assert meta["etag"] == '"abc"' and meta["version"] == "19.2"


def test_unchanged_upstream_uses_the_cache(tmp_path, monkeypatch):
    calls = _setup(tmp_path, monkeypatch, [_Resp(200, BUNDLE, {"ETag": '"abc"'}), _Resp(304)])
    enterprise.get_stix_data("https://x/enterprise-attack.json", check_latest=True)
    enterprise.get_stix_data("https://x/enterprise-attack.json", check_latest=True)
    assert calls[1]["If-None-Match"] == '"abc"'
    assert enterprise.LAST_LOAD["source"] == "cache" and not enterprise.LAST_LOAD["updated"]


def test_a_new_version_is_reported(tmp_path, monkeypatch):
    newer = BUNDLE.replace('"19.2"', '"20.0"')
    _setup(tmp_path, monkeypatch, [_Resp(200, BUNDLE, {"ETag": '"a"'}), _Resp(200, newer, {"ETag": '"b"'})])
    enterprise.get_stix_data("https://x/enterprise-attack.json", check_latest=True)
    enterprise.get_stix_data("https://x/enterprise-attack.json", check_latest=True)
    assert enterprise.LAST_LOAD["version"] == "20.0" and enterprise.LAST_LOAD["previous"] == "19.2"
    assert enterprise.LAST_LOAD["updated"]


def test_offline_falls_back_to_the_cache(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, [_Resp(200, BUNDLE, {"ETag": '"a"'})])
    enterprise.get_stix_data("https://x/enterprise-attack.json", check_latest=True)

    def offline(url, **kw):
        raise requests.ConnectionError("offline")
    monkeypatch.setattr(enterprise.requests, "get", offline)
    enterprise.get_stix_data("https://x/enterprise-attack.json", check_latest=True)
    assert enterprise.LAST_LOAD["source"] == "cache"


def test_library_lists_every_siem_in_order():
    from shikari.app import _library_vendor_slots

    slots = _library_vendor_slots([{"name": "splunk", "display_name": "Splunk", "count": 1, "detections": ["x"]},
                                   {"name": "microsoft", "display_name": "MDE", "count": 2, "detections": ["a", "b"]}],
                                  "detections")
    assert [s["display_name"] for s in slots] == ["Google SecOps", "Defender XDR", "Splunk", "Elastic"]
    assert slots[0].get("empty_state") and not slots[0].get("coming_soon")
    # Elastic now generates ES|QL — live, no longer Coming Soon
    assert slots[1]["count"] == 2 and not slots[3].get("coming_soon")
