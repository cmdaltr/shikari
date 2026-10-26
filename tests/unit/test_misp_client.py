"""MISP instance client (#19): restSearch response -> merged extraction, with requests mocked."""

import archer.parsers.misp_client as mc

EVENTS = {"response": [
    {"Event": {"info": "APT intrusion", "Attribute": [{"type": "ip-dst", "value": "203.0.113.9"}],
               "Galaxy": [{"type": "mitre-attack-pattern",
                           "GalaxyCluster": [{"value": "PowerShell", "meta": {"external_id": ["T1059.001"]}}]},
                          {"type": "threat-actor", "GalaxyCluster": [{"value": "FIN7"}]}]}},
    {"Event": {"info": "second", "Attribute": [{"type": "domain", "value": "bad.example"},
                                               {"type": "ip-dst", "value": "203.0.113.9"}],
               "Tag": [{"name": 'misp-galaxy:mitre-attack-pattern="T1566.001"'}]}},
]}


class _Resp:
    def __init__(self, payload):
        self._p = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


def test_import_events_merges(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None, verify=None):
        captured.update(url=url, json=json, headers=headers)
        return _Resp(EVENTS)

    monkeypatch.setattr(mc.requests, "post", fake_post)
    out = mc.import_events("https://misp.example/", "KEY123", last="7d")

    assert out["success"] and out["event_count"] == 2
    assert captured["url"] == "https://misp.example/events/restSearch"
    assert captured["headers"]["Authorization"] == "KEY123"
    assert captured["json"]["last"] == "7d"
    assert set(out["techniques"]) == {"T1059.001", "T1566.001"}
    assert out["iocs"]["ip"] == ["203.0.113.9"]  # deduped across the two events
    assert "bad.example" in out["iocs"]["domain"]
    assert out["group_name"] == "FIN7"
    assert "misp.example" in out["title"]


def test_bare_list_response(monkeypatch):
    monkeypatch.setattr(mc.requests, "post",
                        lambda *a, **k: _Resp(EVENTS["response"]))
    out = mc.import_events("https://misp.example", "KEY")
    assert out["success"] and out["event_count"] == 2


def test_empty_url():
    assert mc.import_events("  ", "KEY")["success"] is False
