"""
Only the groups an ATT&CK release changes are collected again (shikari.mitre.attack_delta),
and the runner merges them into the procedures CSV (shikari.mitre.procedures).
"""
import copy
import csv
import json
import time
from types import SimpleNamespace

import pytest

from shikari.mitre import attack_delta as d
from shikari.mitre import procedures as p


def _obj(type_, stix_id, ext=None, **kw):
    o = {"type": type_, "id": stix_id, "modified": "2026-01-01T00:00:00Z", "x_mitre_version": "1.0", **kw}
    if ext:
        o["external_references"] = [{"source_name": "mitre-attack", "external_id": ext}]
    return o


def _rel(src, tgt, rel="uses", desc=""):
    return {"type": "relationship", "id": f"relationship--{src}--{tgt}", "relationship_type": rel,
            "source_ref": src, "target_ref": tgt, "description": desc}


def _bundle():
    return [
        _obj("intrusion-set", "intrusion-set--a", "G0001", name="Alpha", description="A"),
        _obj("intrusion-set", "intrusion-set--b", "G0002", name="Bravo", description="B"),
        _obj("intrusion-set", "intrusion-set--c", "G0003", name="Charlie", description="C"),
        _obj("attack-pattern", "attack-pattern--1", "T1001", name="One", description="1"),
        _obj("attack-pattern", "attack-pattern--2", "T1002", name="Two", description="2"),
        _obj("attack-pattern", "attack-pattern--3", "T1003", name="Three", description="3"),
        _obj("malware", "malware--m", "S0001", name="Malware"),
        _obj("campaign", "campaign--k", "C0001", name="Campaign"),
        _rel("intrusion-set--a", "attack-pattern--1", desc="Alpha uses one"),
        _rel("intrusion-set--b", "malware--m"),
        _rel("malware--m", "attack-pattern--2", desc="Malware does two"),
        _rel("campaign--k", "intrusion-set--c", rel="attributed-to"),
        _rel("campaign--k", "attack-pattern--3", desc="Campaign does three"),
        _obj("tool", "tool--t", "S0002", name="Tool"),
        _obj("attack-pattern", "attack-pattern--4", "T1004", name="Four", description="4"),
        _rel("campaign--k", "tool--t"),
        _rel("tool--t", "attack-pattern--4", desc="Tool does four"),
    ]


def _plan(change):
    old = _bundle()
    new = copy.deepcopy(old)
    change(new)
    return d.plan(d.build_index(old), d.build_index(new))


def _find(objects, stix_id):
    return next(o for o in objects if o["id"] == stix_id)


def test_patches_touch_nothing():
    def patch(objs):
        for o in objs:
            o["modified"] = "2026-08-06T00:00:00Z"
            o["x_mitre_version"] = "1.1"
            o["x_mitre_attack_spec_version"] = "3.3.0"
    assert _plan(patch) == {"run": [], "drop": []}


def test_a_changed_group_is_collected_again():
    assert _plan(lambda o: _find(o, "intrusion-set--a").update(description="New")) == {"run": ["G0001"], "drop": []}


def test_a_new_procedure_touches_its_group():
    assert _plan(lambda o: o.append(_rel("intrusion-set--c", "attack-pattern--1")))["run"] == ["G0003"]


def test_software_changes_reach_the_groups_using_it():
    assert _plan(lambda o: _find(o, "malware--m").update(name="Renamed"))["run"] == ["G0002"]
    assert _plan(lambda o: _find(o, "relationship--malware--m--attack-pattern--2").update(description="x"))["run"] == ["G0002"]


def test_campaign_changes_reach_the_attributed_group():
    assert _plan(lambda o: _find(o, "campaign--k").update(name="Renamed"))["run"] == ["G0003"]


def test_software_in_a_campaign_reaches_the_attributed_group():
    assert _plan(lambda o: _find(o, "tool--t").update(name="Renamed"))["run"] == ["G0003"]
    assert _plan(lambda o: _find(o, "attack-pattern--4").update(description="new"))["run"] == ["G0003"]


def test_a_technique_change_reaches_every_path():
    def edit(objs):
        _find(objs, "attack-pattern--3").update(description="new")
        _find(objs, "attack-pattern--2").update(name="new")
    assert _plan(edit)["run"] == ["G0002", "G0003"]


def test_a_revoked_group_is_dropped():
    assert _plan(lambda o: _find(o, "intrusion-set--a").update(revoked=True)) == {"run": [], "drop": ["G0001"]}


def test_nothing_to_compare_means_full():
    assert d.plan(None, d.build_index(_bundle())) is None


# ---- the runner ----------------------------------------------------------------------

HEADER = ["group_sw_id", "group_sw_name", "group_sw_description", "technique_id", "procedure_example"]


def _write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=HEADER)
        w.writeheader()
        w.writerows(rows)


def _row(g, name, t, text="old"):
    return {"group_sw_id": g, "group_sw_name": name, "group_sw_description": "long", "technique_id": t,
            "procedure_example": text}


@pytest.fixture
def saw(tmp_path, monkeypatch):
    mitresaw = tmp_path / "MITRESaw"
    mitresaw.mkdir()
    (mitresaw / "MITRESaw.py").write_text("")
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps({"objects": _bundle()}))
    monkeypatch.setattr(p, "_MITRESAW_DIR", mitresaw)
    monkeypatch.setattr(p, "_SHIKARI_BUNDLE", bundle)
    monkeypatch.setattr(p, "_mitresaw_python", lambda: "python")
    monkeypatch.setattr(p, "_LOCK", tmp_path / ".mitresaw.lock")
    calls = []
    full_rows = [_row("G0001", "Alpha", "T1001"), _row("G0002", "Bravo", "T1002"), _row("G0003", "Charlie", "T1003")]

    def run(cmd, **kw):
        calls.append(cmd)
        groups = cmd[cmd.index("-g") + 1].split(",") if "-g" in cmd else None
        out = mitresaw / "data" / time.strftime("%Y-%m-%d") / ("__" + "-".join(groups) if groups else "")
        rows = [dict(r, procedure_example="new") for r in full_rows if not groups or r["group_sw_id"] in groups]
        _write_csv(out / "mitre_procedures.csv", rows)
        (out / "mitre_procedures.xlsx").write_text("xlsx")
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(p, "_run_command", run)
    return SimpleNamespace(calls=calls, bundle=bundle, out=tmp_path / "out" / "mitre_procedures.csv",
                           xlsx=tmp_path / "out" / "mitre_procedures.xlsx")


def _read(path):
    with open(path, newline="") as fh:
        return [(r["group_sw_id"], r["procedure_example"]) for r in csv.DictReader(fh)]


def _groups(cmd):
    return cmd[cmd.index("-g") + 1].split(",")


def test_first_build_is_full_then_only_changed_groups(saw):
    p.run_mitresaw_detection(output_csv=saw.out, output_xlsx=saw.xlsx)
    assert [_groups(c) for c in saw.calls] == [["G0001", "G0002", "G0003"]] and p.LAST_PLAN is None
    assert json.loads(p._meta_path(saw.out).read_text())["mode"] == "full"
    assert _read(saw.out) == [("G0001", "new"), ("G0002", "new"), ("G0003", "new")]
    # Descriptions aren't stored (Shikari reads them from ATT&CK)
    assert saw.out.read_text().splitlines()[0] == "group_sw_id,group_sw_name,technique_id,procedure_example"

    # Nothing changed: no MITRESaw run at all
    p.run_mitresaw_detection(output_csv=saw.out, output_xlsx=saw.xlsx)
    assert len(saw.calls) == 1 and p.LAST_PLAN == {"run": [], "drop": []}

    # Bravo's software renamed, Alpha revoked: Bravo collected again, Alpha dropped
    objects = _bundle()
    _find(objects, "malware--m")["name"] = "Renamed"
    _find(objects, "intrusion-set--a")["revoked"] = True
    saw.bundle.write_text(json.dumps({"objects": objects}))
    _write_csv(saw.out, [_row("G0001", "Alpha", "T1001"), _row("G0002", "Bravo", "T1002"), _row("G0003", "Charlie", "T1003")])
    p.run_mitresaw_detection(output_csv=saw.out, output_xlsx=saw.xlsx)
    assert _groups(saw.calls[-1]) == ["G0002"]
    assert _read(saw.out) == [("G0002", "new"), ("G0003", "old")]
    assert json.loads(p._meta_path(saw.out).read_text())["mode"] == "incremental"


def test_full_collects_every_group_in_batches(saw, monkeypatch):
    monkeypatch.setattr(p, "_BATCH_SIZE", 2)
    p.run_mitresaw_detection(output_csv=saw.out, output_xlsx=saw.xlsx)
    p.run_mitresaw_detection(output_csv=saw.out, output_xlsx=saw.xlsx, full=True)
    assert [_groups(c) for c in saw.calls] == [["G0001", "G0002"], ["G0003"]] * 2
    assert not list(saw.out.parent.glob("*.building.*"))


def test_an_interrupted_collection_resumes(saw, monkeypatch):
    monkeypatch.setattr(p, "_BATCH_SIZE", 2)
    real = p._run_command

    def dies_on_second_batch(cmd, **kw):
        if _groups(cmd) == ["G0003"]:
            raise p.subprocess.TimeoutExpired(cmd, 1)
        return real(cmd, **kw)
    monkeypatch.setattr(p, "_run_command", dies_on_second_batch)
    with pytest.raises(p.subprocess.TimeoutExpired):
        p.run_mitresaw_detection(output_csv=saw.out, output_xlsx=saw.xlsx)
    assert not saw.out.exists()

    monkeypatch.setattr(p, "_run_command", real)
    p.run_mitresaw_detection(output_csv=saw.out, output_xlsx=saw.xlsx)
    # The first batch isn't collected again
    assert [_groups(c) for c in saw.calls] == [["G0001", "G0002"], ["G0003"]]
    assert _read(saw.out) == [("G0001", "new"), ("G0002", "new"), ("G0003", "new")]


def test_a_changed_attack_starts_the_collection_over(saw, monkeypatch):
    monkeypatch.setattr(p, "_BATCH_SIZE", 2)
    real = p._run_command
    monkeypatch.setattr(p, "_run_command", lambda cmd, **kw: (_ for _ in ()).throw(RuntimeError("down"))
                        if _groups(cmd) == ["G0003"] else real(cmd, **kw))
    with pytest.raises(RuntimeError):
        p.run_mitresaw_detection(output_csv=saw.out, output_xlsx=saw.xlsx)
    objects = _bundle()
    _find(objects, "intrusion-set--a")["description"] = "Changed"
    saw.bundle.write_text(json.dumps({"objects": objects}))
    monkeypatch.setattr(p, "_run_command", real)
    p.run_mitresaw_detection(output_csv=saw.out, output_xlsx=saw.xlsx)
    assert [_groups(c) for c in saw.calls] == [["G0001", "G0002"], ["G0001", "G0002"], ["G0003"]]


def test_other_flags_mean_a_full_collection(saw, monkeypatch):
    p.run_mitresaw_detection(output_csv=saw.out, output_xlsx=saw.xlsx)
    monkeypatch.setattr(p, "_MITRESAW_FLAGS", p._MITRESAW_FLAGS + ["-x", "csv"])
    p.run_mitresaw_detection(output_csv=saw.out, output_xlsx=saw.xlsx)
    assert _groups(saw.calls[1]) == ["G0001", "G0002", "G0003"]
