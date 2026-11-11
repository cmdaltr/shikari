"""STIX/MISP import and STIX export (#19)."""

import json

from shikari.parsers.stix_import import parse_stix_bundle
from shikari.parsers.misp_import import parse_misp_event
from shikari.parsers.stix_export import run_to_stix


STIX_BUNDLE = {"type": "bundle", "objects": [
    {"type": "intrusion-set", "name": "APT29", "description": "Cozy Bear"},
    {"type": "attack-pattern", "name": "LSASS Memory",
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1003.001"}]},
    {"type": "indicator", "name": "mimikatz", "pattern_type": "stix",
     "pattern": "[process:command_line = 'mimikatz sekurlsa::logonpasswords']"},
    {"type": "indicator", "pattern_type": "stix",
     "pattern": "[ipv4-addr:value = '10.0.0.5'] OR [domain-name:value = 'evil.example']"},
    {"type": "file", "name": "bad.exe", "hashes": {"SHA-256": "abc123"}},
    {"type": "url", "value": "http://evil.example/path"},
]}

MISP_EVENT = {"Event": {"info": "APT29 campaign", "Attribute": [
    {"type": "ip-dst", "value": "10.0.0.9"},
    {"type": "domain", "value": "evil2.example"},
    {"type": "sha256", "value": "deadbeef"},
    {"type": "filename|md5", "value": "x.exe|1234"},
    {"type": "regkey", "value": r"HKLM\Software\Run"},
], "Galaxy": [{"type": "mitre-attack-pattern", "GalaxyCluster": [
    {"value": "LSASS Memory - T1003.001", "meta": {"external_id": "T1003.001"}}]}],
    "Tag": [{"name": 'misp-galaxy:mitre-attack-pattern="Kerberoasting - T1558.003"'}]}}


def test_stix_import_techniques_and_group():
    r = parse_stix_bundle(STIX_BUNDLE)
    assert r["success"] and r["group_name"] == "APT29"
    assert r["techniques"] == ["T1003.001"]


def test_stix_import_iocs_by_kind():
    iocs = parse_stix_bundle(STIX_BUNDLE)["iocs"]
    assert "10.0.0.5" in iocs["ip"]
    assert "evil.example" in iocs["domain"]          # bare domain and the URL host both normalise here
    assert "abc123" in iocs["hash"] and "bad.exe" in iocs["file"]
    assert "mimikatz sekurlsa::logonpasswords" in iocs["cmd"]


def test_stix_import_accepts_json_string():
    assert parse_stix_bundle(json.dumps(STIX_BUNDLE))["techniques"] == ["T1003.001"]


def test_stix_import_rejects_non_bundle():
    assert parse_stix_bundle({"foo": "bar"})["success"] is False


def test_misp_import_techniques_from_galaxy_and_tags():
    r = parse_misp_event(MISP_EVENT)
    assert r["success"]
    assert "T1003.001" in r["techniques"] and "T1558.003" in r["techniques"]


def test_misp_import_iocs_including_composite():
    iocs = parse_misp_event(MISP_EVENT)["iocs"]
    assert "10.0.0.9" in iocs["ip"] and "deadbeef" in iocs["hash"]
    assert "x.exe" in iocs["file"] and "1234" in iocs["hash"]   # filename|md5 split both ways
    assert r"HKLM\Software\Run" in iocs["reg"]


def test_stix_export_has_expected_objects():
    dets = [{"name": "LSASS Memory", "technique_id": "T1003.001", "siem": "mde",
             "query": "DeviceProcessEvents | where x", "indicators": {"cmd": ["mimikatz"], "ip": ["10.0.0.5"]}}]
    bundle = json.loads(run_to_stix("APT29", dets, "Cozy Bear"))
    types = [o["type"] for o in bundle["objects"]]
    assert "x-shikari-detection" in types and "attack-pattern" in types
    assert "intrusion-set" in types and "indicator" in types and "relationship" in types
    det = next(o for o in bundle["objects"] if o["type"] == "x-shikari-detection")
    assert det["siem"] == "mde" and det["technique_id"] == "T1003.001"


def test_stix_roundtrip_techniques():
    # Export a run, re-import the bundle: the technique survives the round trip
    dets = [{"name": "Kerberoasting", "technique_id": "T1558.003", "siem": "secops",
             "query": "x", "indicators": {"ip": ["1.2.3.4"]}}]
    bundle = run_to_stix("APT29", dets)
    back = parse_stix_bundle(bundle)
    assert "T1558.003" in back["techniques"] and "1.2.3.4" in back["iocs"]["ip"]


def test_stix_import_undoes_escapes_in_patterns():
    # samarkand's reader (its docs/DIFFERENCES.md, STIX): \' and \\ in a pattern string are escapes
    bundle = {"type": "bundle", "objects": [
        {"type": "indicator", "id": "indicator--1", "pattern_type": "stix",
         "pattern": r"[file:name = 'it\'s.exe'] OR [windows-registry-key:key = 'HKLM\\Software\\Run']"}]}
    iocs = parse_stix_bundle(bundle)["iocs"]
    assert iocs["file"] == ["it's.exe"] and iocs["reg"] == ["HKLM\\Software\\Run"]

