"""MISP export (#19): run -> MISP event, and round-trip back through the importer."""

import json

from archer.parsers.misp_export import run_to_misp
from archer.parsers.misp_import import parse_misp_event

DETS = [
    {"name": "PowerShell download cradle", "technique_id": "T1059.001", "technique_name": "PowerShell",
     "siem": "mde", "indicators": {"domain": ["evil.example"], "ip": ["203.0.113.5"],
                                    "hash": ["a" * 64], "file": ["beacon.exe"]}},
    {"name": "Service install", "technique_id": "T1543.003", "technique_name": "Windows Service",
     "siem": "secops", "indicators": {"sw": ["EvilSvc"], "reg": ["HKLM\\System\\Foo"]}},
]


def _event():
    return json.loads(run_to_misp("Scattered Spider", DETS))


def test_wraps_in_event_with_info():
    ev = _event()["Event"]
    assert "Scattered Spider" in ev["info"]
    assert ev["date"] and ev["Attribute"] and ev["Galaxy"]


def test_attributes_typed_by_kind():
    attrs = {(a["type"], a["value"]) for a in _event()["Event"]["Attribute"]}
    assert ("domain", "evil.example") in attrs
    assert ("ip-dst", "203.0.113.5") in attrs
    assert ("sha256", "a" * 64) in attrs
    assert ("filename", "beacon.exe") in attrs
    assert ("windows-service-name", "EvilSvc") in attrs
    assert ("regkey", "HKLM\\System\\Foo") in attrs


def test_techniques_as_galaxy_and_tags():
    ev = _event()["Event"]
    ap = [g for g in ev["Galaxy"] if g["type"] == "mitre-attack-pattern"][0]
    ids = {c["meta"]["external_id"][0] for c in ap["GalaxyCluster"]}
    assert ids == {"T1059.001", "T1543.003"}
    assert any('threat-actor="Scattered Spider"' in t["name"] for t in ev["Tag"])


def test_round_trips_through_importer():
    ev = _event()
    back = parse_misp_event(ev)
    assert back["success"]
    assert set(back["techniques"]) == {"T1059.001", "T1543.003"}
    assert back["group_name"] == "Scattered Spider"
    assert "evil.example" in back["iocs"].get("domain", [])
    assert "203.0.113.5" in back["iocs"].get("ip", [])
    assert ("a" * 64) in back["iocs"].get("hash", [])


def test_no_group_still_valid():
    ev = json.loads(run_to_misp("", DETS))["Event"]
    assert not any(g["type"] == "threat-actor" for g in ev["Galaxy"])
    assert ev["Attribute"]


def test_dedupes_iocs_across_detections():
    dets = DETS + [{"name": "dup", "technique_id": "T1059.001", "indicators": {"domain": ["evil.example"]}}]
    attrs = [a for a in json.loads(run_to_misp("G", dets))["Event"]["Attribute"]
             if a["value"] == "evil.example"]
    assert len(attrs) == 1
