"""Wazuh rules from detection indicators (#41)."""

import io
import json
import re
import xml.etree.ElementTree as ET
import zipfile

import yaml

from shikari.build import wazuh
from shikari.export import siem_pack

DOCS = [
    {"technique_id": "T1016", "name": "Find Domain", "severity": "Medium",
     "indicators": {"cmd": ["nbtstat -n", "ipconfig /all", "NBTSTAT -N", "ab"], "protocol": ["SMB"]}},
    {"technique_id": "T1016", "name": "Find Domain", "severity": "High",
     "indicators": {"reg": [r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\x"],
                    "network": ["evil.example.com", "user_managed", "<operator URL>"],
                    "ip": ["10.1.2.3", "999.1.1.1"], "sha256": ["a" * 64, "nothex"]}},
    {"technique_id": "not-a-technique", "indicators": {"cmd": ["whoami"]}},
]


def test_pool_merges_dedupes_and_cleans():
    pooled = wazuh.pool(DOCS)
    assert list(pooled) == ["T1016"]
    entry = pooled["T1016"]
    assert entry["severity"] == "high"  # the highest of its detections
    ind = entry["indicators"]
    assert ind["cmd"] == ["nbtstat -n", "ipconfig /all"]  # deduped without case; "ab" too short
    assert ind["domain"] == ["evil.example.com"]  # network folded in, non-domains dropped
    assert ind["ip"] == ["10.1.2.3"] and ind["hash"] == ["A" * 64]
    assert "protocol" not in ind


def test_pcre_escaping():
    assert wazuh._pcre(r"C:\Windows\a.exe") == r"C:\\{1,2}Windows\\{1,2}a\.exe"
    # one backslash (json decoder) or two (eventchannel decoder)
    for value in (r"C:\Windows\a.exe", r"C:\\Windows\\a.exe"):
        assert re.search(wazuh._pcre(r"C:\Windows\a.exe"), value)
    assert wazuh._pcre("a(b)|c*") == r"a\(b\)\|c\*"
    assert wazuh._pattern(["10.1.2.3"], exact=True) == r"(?i)^(?:10\.1\.2\.3)$"


def test_bounded_matches_words_not_parts():
    pat = wazuh._pattern(["dir", ".wll", "nbtstat -n"], exact=False)
    for text, hit in [("cmd /c dir", True), ("mkdir x", False), ("dirx", False), ("addin.wll", True),
                      ("x.wllx", False), ("NBTSTAT -N", True)]:
        assert bool(re.search(pat, text)) is hit, text
    assert wazuh._clean("cmd", ".exe") is None and wazuh._clean("cmd", ".wll") == ".wll"


def test_rules_ids_are_stable(tmp_path):
    path = str(tmp_path / "ids.json")
    pooled = wazuh.pool(DOCS)
    ids = wazuh.RuleIds(path)
    first = wazuh.rules(pooled, ids)
    ids.save()
    assert all(wazuh.FIRST_ID <= r["id"] <= wazuh.LAST_ID for r in first)
    assert len({r["id"] for r in first}) == len(first)
    # a new indicator kind on a later export gets a new ID; the existing rules keep theirs
    more = wazuh.pool(DOCS + [{"technique_id": "T1016", "indicators": {"sw": ["nbtstat.exe"]}}])
    second = wazuh.rules(more, wazuh.RuleIds(path))
    by_key = {(r["source"], r["field"]): r["id"] for r in second}
    for r in first:
        assert by_key[(r["source"], r["field"])] == r["id"]
    assert len(second) > len(first)


def test_many_indicators_split_across_rules():
    pooled = {"T1059": {"name": "x", "severity": "low",
                        "indicators": {"ip": [f"10.0.{i // 250}.{i % 250}" for i in range(wazuh.MAX_ALTERNATIVES + 5)]}}}
    rs = wazuh.rules(pooled, wazuh.RuleIds())
    assert [r["count"] for r in rs] == [wazuh.MAX_ALTERNATIVES, 5]


def test_xml_is_well_formed_and_chained():
    xml = wazuh.to_xml(wazuh.rules(wazuh.pool(DOCS), wazuh.RuleIds(), {"T1016": "System Network Configuration Discovery"}),
                       header="Shikari test -- header")
    root = ET.fromstring(xml[xml.index("<group"):])
    rules = root.findall("rule")
    assert rules and root.get("name") == "shikari,attack,"
    cmd = next(r for r in rules if r.find("field[@name='win.eventdata.commandLine']") is not None
               and r.find("if_group").text == "sysmon_event1")
    assert cmd.get("level") == "10"
    assert cmd.find("mitre/id").text == "T1016"
    assert "System Network Configuration Discovery" in cmd.find("description").text
    assert cmd.find("field[@name='win.system.eventID']").text == "^(?:1)$"
    pattern = cmd.find("field[@name='win.eventdata.commandLine']").text
    assert re.search(pattern.replace("(?i)", ""), "nbtstat -n", re.I)
    reg = next(r for r in rules if r.find("field[@name='win.eventdata.targetObject']") is not None)
    assert "\\\\{1,2}CurrentVersion" in reg.find("field[@name='win.eventdata.targetObject']").text
    # Wazuh 4.14's pcre2 fields refuse lookbehinds and named groups: one stops every rule loading
    assert "(?<" not in xml


def test_wazuh_pack(tmp_path):
    gdir = tmp_path / "groups"
    gdir.mkdir()
    for i, doc in enumerate(DOCS):
        with open(gdir / f"d{i}.yaml", "w") as fh:
            yaml.safe_dump({"id": f"id{i}", "requiredDataConnectors": [{"connectorId": "Splunk"}], **doc}, fh)
    data, manifest = siem_pack.build("wazuh", None, str(gdir), lambda g, d: [],
                                     exclude_unavailable=False, wazuh_ids=str(tmp_path / "ids.json"))
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        files = {n: zf.read(n).decode() for n in zf.namelist()}
    assert set(files) == {"shikari_rules.xml", "README.txt", "manifest.json"}
    assert manifest["techniques"] == ["T1016"] and manifest["rules"] > 0
    assert f"{manifest['rules']} rules over 1 techniques" in files["README.txt"]
    assert json.loads(files["manifest.json"])["siem"] == "wazuh"
    assert (tmp_path / "ids.json").exists()


def test_practice_rules_give_json_events_the_parent_groups():
    root = ET.fromstring(wazuh.practice_xml())
    rules = root.findall("rule")
    assert len(rules) == len(wazuh.SOURCES)
    assert all(int(r.get("id")) < wazuh.FIRST_ID and r.find("decoded_as").text == "json" for r in rules)
    groups = {r.find("group").text.rstrip(",") for r in rules}
    assert groups == {s["parent"] for s in wazuh.SOURCES.values()}
