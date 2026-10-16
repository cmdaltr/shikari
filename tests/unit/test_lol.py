import json

import pytest

from archer.build import lol
from archer.build import osint_index


@pytest.fixture
def datasets(tmp_path, monkeypatch):
    monkeypatch.setattr(lol, "LOL_DIR", tmp_path / "lol")
    monkeypatch.setattr(lol, "INDEX_PATH", tmp_path / "lol_index.json")
    monkeypatch.setitem(lol._cache, "mtime", None)
    (tmp_path / "lol").mkdir()
    data = {
        "lolbas": [
            {"Name": "Certutil.exe", "url": "https://lolbas-project.github.io/lolbas/Binaries/Certutil/",
             "Full_Path": [{"Path": "C:\\Windows\\System32\\certutil.exe"}],
             "Commands": [
                 {"Command": "certutil.exe -urlcache -f {REMOTEURL:.exe} {PATH:.exe}", "MitreID": "T1105"},
                 {"Command": "certutil -encode {PATH} {PATH:.base64}", "MitreID": "T1027"}]},
            {"Name": "Mshta.exe", "Commands": [{"Command": "mshta.exe {PATH:.hta}", "MitreID": "T1218.005"}]},
        ],
        "lolrmm": [
            {"Name": "AnyDesk",
             "Details": {"PEMetadata": [{"Filename": "AnyDesk.exe"}]},
             "Artifacts": {"Network": [{"Domains": ["relay.anydesk.com", "*.net.anydesk.com"]}],
                           "Registry": [{"Path": "HKLM\\SOFTWARE\\Clients\\Media\\AnyDesk"},
                                        {"Path": "HKLM\\System\\CurrentControlSet\\Control\\Lsa"}]}},
        ],
        "loldrivers": [
            {"Id": "abc", "Category": "vulnerable driver", "MitreID": "T1068",
             "KnownVulnerableSamples": [{"Filename": "RTCore64.sys", "SHA256": "01aa"}]},
        ],
    }
    for name, content in data.items():
        (tmp_path / "lol" / f"{name}.json").write_text(json.dumps(content))
    lol.build_index()
    return tmp_path


def test_lolbas_adds_switches_for_the_same_technique(datasets):
    added, refs = lol.enrich({"sw": ["certutil.exe"]}, "T1105")
    assert added["cmd"] == ["Certutil.exe -urlcache"]
    assert refs[0]["source"] == "LOLBAS"


def test_lolbas_ignores_other_techniques(datasets):
    assert lol.enrich({"sw": ["certutil.exe"]}, "T1059.001") == ({}, [])


def test_lolbas_binary_without_switches_still_counts(datasets):
    added, _ = lol.enrich({}, "T1218", "The group used mshta.exe to run an HTA")
    assert added == {"sw": ["Mshta.exe"]}


def test_lolrmm_named_in_the_procedure(datasets):
    added, refs = lol.enrich({}, "T1219", "They installed AnyDesk for persistence")
    assert added["sw"] == ["AnyDesk.exe"]
    assert added["network"] == ["relay.anydesk.com"]  # no wildcards
    assert added["reg"] == ["HKLM\\SOFTWARE\\Clients\\Media\\AnyDesk"]  # shared keys dropped
    assert refs[0]["url"] == "https://lolrmm.io/tools/anydesk"


def test_loldrivers_hash_goes_to_the_reference(datasets):
    added, refs = lol.enrich({"sw": ["rtcore64.sys"]}, "T1068")
    assert added == {}  # already present
    assert "01aa" in refs[0]["detail"]


def test_unnamed_tools_add_nothing(datasets):
    assert lol.enrich({"cmd": ["remote update"]}, "T1105", "certutilities") == ({}, [])


def test_false_positive_boilerplate_dropped():
    assert osint_index._false_positives(["None identified.", "No false positives have been identified at this time.",
                                         "False positives should be very unlikely.",
                                         "Administrators may run procdump against lsass for debugging."]) == [
        "Administrators may run procdump against lsass for debugging."]


def test_known_false_positives_only_for_the_named_tools(monkeypatch):
    fp = lambda name, text: {"name": name, "source_url": "u", "query_snippet": "", "false_positives": [text]}
    monkeypatch.setattr(osint_index, "_index_cache", {"techniques": {
        "T1003.001": {"elastic": [fp("Gitleaks", "Gitleaks is a legitimate scanner used by developers."),
                                  fp("Procdump LSASS", "Support staff may dump processes with procdump.")]},
        "T1003": {"splunk": [fp("Any", "Backup software reads credential stores on schedule.")]},
    }})
    fps = osint_index.known_false_positives("T1003.001", terms=["procdump.exe"])
    assert [f["rule"] for f in fps] == ["Procdump LSASS"]
    assert len(osint_index.known_false_positives("T1003.001")) == 3


def test_lol_enrichment_off_skips_the_lookup(monkeypatch):
    from archer.build import detections, lol

    monkeypatch.setattr(lol, "enrich", lambda *a: (_ for _ in ()).throw(AssertionError("looked up")))
    ids = {"sw": ["certutil.exe"]}
    assert detections.lol_enrichment(ids, "T1105", "", enabled=False) == (ids, [])


def test_lol_enrichment_on_adds_without_touching_the_original(monkeypatch):
    from archer.build import detections, lol

    ref = {"source": "LOLBAS", "name": "Certutil.exe"}
    monkeypatch.setattr(lol, "enrich", lambda ids, tid, text: ({"cmd": ["Certutil.exe -urlcache"], "hash": ["abc"]}, [ref]))
    ids = {"sw": ["certutil.exe"], "cmd": ["certutil -f"]}
    out, refs = detections.lol_enrichment(ids, "T1105", "used certutil")
    assert out == {"sw": ["certutil.exe"], "cmd": ["certutil -f", "Certutil.exe -urlcache"], "hash": ["abc"]}
    assert refs == [ref]
    assert ids == {"sw": ["certutil.exe"], "cmd": ["certutil -f"]}
