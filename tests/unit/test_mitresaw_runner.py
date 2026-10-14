"""
Archer runs MITRESaw on its own ATT&CK bundle, with MITRESaw's current flags, one run at
a time, only accepts output from that run, and checks it against its own walk of ATT&CK
(archer.mitre.procedures).
"""
import json
import os
import subprocess
import time
from types import SimpleNamespace

import pytest

from archer.mitre import procedures as p


@pytest.fixture
def saw(tmp_path, monkeypatch):
    mitresaw, archer = tmp_path / "MITRESaw", tmp_path / "archer"
    mitresaw.mkdir()
    (mitresaw / "MITRESaw.py").write_text("")
    bundle = archer / "enterprise-attack.json"
    bundle.parent.mkdir()
    bundle.write_text('{"objects": []}')
    monkeypatch.setattr(p, "_MITRESAW_DIR", mitresaw)
    monkeypatch.setattr(p, "_ARCHER_BUNDLE", bundle)
    monkeypatch.setattr(p, "_mitresaw_python", lambda: "python")
    monkeypatch.setattr(p, "_LOCK", tmp_path / ".mitresaw.lock")
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        out = mitresaw / "data" / time.strftime("%Y-%m-%d")
        out.mkdir(parents=True, exist_ok=True)
        (out / "mitre_procedures.csv").write_text("group_sw_id\n")
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(p, "_run_command", run)
    return SimpleNamespace(dir=mitresaw, calls=calls, out=tmp_path / "out.csv")


def test_shares_the_bundle_and_skips_fetch(saw):
    csv, _ = p.run_mitresaw_detection(output_csv=saw.out, force=True)
    assert (saw.dir / "data" / "stix" / "enterprise-attack.json").read_text() == '{"objects": []}'
    flags = saw.calls[0][2:]
    assert "-F" not in flags and "-A" in flags and "-S" in flags and flags[:2] == ["-f", "Enterprise"]
    assert csv.read_text() == "group_sw_id\n"


def test_fetches_when_archer_has_no_bundle(saw, monkeypatch, tmp_path):
    monkeypatch.setattr(p, "_ARCHER_BUNDLE", tmp_path / "missing.json")
    p.run_mitresaw_detection(output_csv=saw.out, force=True)
    assert "-F" in saw.calls[0]


def test_old_output_is_not_taken_for_a_rebuild(saw, monkeypatch):
    stale = saw.dir / "data" / "2026-01-01" / "mitre_procedures.csv"
    stale.parent.mkdir(parents=True)
    stale.write_text("old\n")
    old = time.time() - 86400
    os.utime(stale, (old, old))
    monkeypatch.setattr(p, "_run_command", lambda cmd, **kw: SimpleNamespace(returncode=0, stdout="", stderr=""))
    with pytest.raises(FileNotFoundError, match="no new mitre_procedures.csv"):
        p.run_mitresaw_detection(output_csv=saw.out)


def test_one_rebuild_at_a_time(saw):
    with p._mitresaw_lock():
        with pytest.raises(p.MitresawBusy):
            p.run_mitresaw_detection(output_csv=saw.out)
    assert not saw.calls
    p.run_mitresaw_detection(output_csv=saw.out)   # free again
    assert len(saw.calls) == 1


def _obj(type_, stix_id, ext=None, **kw):
    o = {"type": type_, "id": stix_id, **kw}
    if ext:
        o["external_references"] = [{"source_name": "mitre-attack", "external_id": ext}]
    return o


def _uses(src, tgt, rel="uses"):
    return {"type": "relationship", "id": f"relationship--{src}-{tgt}", "relationship_type": rel,
            "source_ref": src, "target_ref": tgt, "description": ""}


@pytest.fixture
def bundle(tmp_path):
    objects = [
        _obj("intrusion-set", "intrusion-set--g", "G0001", name="Group"),
        _obj("attack-pattern", "attack-pattern--a", "T1001", name="Own"),
        _obj("attack-pattern", "attack-pattern--b", "T1002", name="From software"),
        _obj("attack-pattern", "attack-pattern--c", "T1003", name="From a campaign"),
        _obj("attack-pattern", "attack-pattern--r", "T1004", name="Revoked", revoked=True),
        _obj("attack-pattern", "attack-pattern--d", "T1005", name="From campaign software"),
        _obj("tool", "tool--t", "S0002", name="Tool"),
        _obj("malware", "malware--m", "S0001", name="Malware"),
        _obj("campaign", "campaign--c", "C0001", name="Campaign"),
        _uses("intrusion-set--g", "attack-pattern--a"),
        _uses("intrusion-set--g", "attack-pattern--r"),
        _uses("intrusion-set--g", "malware--m"),
        _uses("malware--m", "attack-pattern--b"),
        _uses("campaign--c", "attack-pattern--c"),
        _uses("campaign--c", "intrusion-set--g", rel="attributed-to"),
        _uses("campaign--c", "tool--t"),
        _uses("tool--t", "attack-pattern--d"),
    ]
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"objects": objects}))
    return path


def _csv(tmp_path, pairs):
    path = tmp_path / "procedures.csv"
    path.write_text("group_sw_id,technique_id,procedure_example\n" +
                    "".join(f'{g},{t},"multi\nline"\n' for g, t in pairs))
    return path


def test_check_matches_every_path_and_ignores_revoked(tmp_path, bundle):
    pairs = [("G0001", "T1001"), ("G0001", "T1002"), ("G0001", "T1003"), ("G0001", "T1005")]
    check = p.check_procedures(_csv(tmp_path, pairs), bundle)
    assert check["ok"] and check["groups"] == 1 and check["techniques"] == 4
    assert "match" in p.describe_check(check)


def test_check_reports_what_differs(tmp_path, bundle):
    check = p.check_procedures(_csv(tmp_path, [("G0001", "T1001"), ("G0001", "T1999")]), bundle)
    assert not check["ok"]
    assert check["missing"] == {"G0001": ["T1002", "T1003", "T1005"]}
    assert check["extra"] == {"G0001": ["T1999"]}
    assert "3 group-technique links missing" in p.describe_check(check)


def test_software_used_in_a_groups_campaign_is_labelled_with_it(bundle):
    objects = json.loads(bundle.read_text())["objects"]
    groups, techniques, software, campaigns = p._build_indexes(objects)
    rows, seen = [], set()
    p._walk_path2(objects, groups, techniques, software, rows, seen)
    assert {(r["technique_id"], r["attribution_type"]) for r in rows} == {
        ("T1002", "via_software:Malware"), ("T1005", "via_software:Tool via Campaign")}


def test_attribution_comes_from_mitresaws_label():
    assert p._attribution("[Software: Mimikatz] dumps credentials") == "via_software:Mimikatz"
    assert p._attribution("[Campaign: C0017] used X") == "via_campaign:C0017"
    assert p._attribution("[APT28](https://attack.mitre.org/groups/G0007) has used X") == "direct"


def test_the_briefing_sees_how_each_technique_is_attributed(tmp_path, monkeypatch):
    path = tmp_path / "procedures.csv"
    path.write_text(
        "group_sw_id,group_sw_name,technique_id,technique_name,tactic,procedure_example\n"
        "G0001,Group,T1001,Own,Execution,[Group](https://attack.mitre.org/groups/G0001) did it\n"
        "G0001,Group,T1002,Tool,Execution,[Software: Mimikatz] did it\n"
        "G0001,Group,T1003,Op,Execution,[Campaign: C0017] did it\n")
    monkeypatch.setattr(p, "_DEFAULT_CSV", path)
    coverage = p.get_group_coverage("G0001", tmp_path)
    assert {t["technique_id"]: t["attribution_type"] for t in coverage["gaps"]} == {
        "T1001": "direct", "T1002": "via_software:Mimikatz", "T1003": "via_campaign:C0017"}
