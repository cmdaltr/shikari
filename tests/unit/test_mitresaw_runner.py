"""
Archer runs MITRESaw on its own ATT&CK bundle, with MITRESaw's current flags, and only
accepts output from that run (archer.mitre.procedures).
"""
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
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        out = mitresaw / "data" / time.strftime("%Y-%m-%d")
        out.mkdir(parents=True, exist_ok=True)
        (out / "mitre_procedures.csv").write_text("group_sw_id\n")
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(p.subprocess, "run", run)
    return SimpleNamespace(dir=mitresaw, calls=calls, out=tmp_path / "out.csv")


def test_shares_the_bundle_and_skips_fetch(saw):
    csv, _ = p.run_mitresaw_detection(output_csv=saw.out, force=True)
    assert (saw.dir / "data" / "stix" / "enterprise-attack.json").read_text() == '{"objects": []}'
    flags = saw.calls[0][2:]
    assert "-F" not in flags and "-A" in flags and flags[:2] == ["-f", "Enterprise"]
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
    monkeypatch.setattr(p.subprocess, "run", lambda cmd, **kw: SimpleNamespace(returncode=0, stdout="", stderr=""))
    with pytest.raises(FileNotFoundError, match="no new mitre_procedures.csv"):
        p.run_mitresaw_detection(output_csv=saw.out)
