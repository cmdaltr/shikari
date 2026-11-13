"""Coverage gaps between the user's SIEMs."""

from shikari.build.siem_gaps import siem_gaps, siem_index

ATTACK = {
    "T1003.001": {"name": "LSASS Memory", "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}]},
    "T1003": {"name": "OS Credential Dumping", "kill_chain_phases": []},
    "T1059.001": {"name": "PowerShell", "kill_chain_phases": []},
}


def _write(tmp_path, name, text):
    (tmp_path / name).write_text(text)


def _library(tmp_path):
    _write(tmp_path, "lsass_secops.yaml", "technique_id: T1003.001\nconnectorId: GoogleSecOps\n")
    _write(tmp_path, "lsass_kql.yaml", "technique_id: T1003.001\nconnectorId: MicrosoftThreatProtection\n")
    _write(tmp_path, "ps_secops.yaml", "technique_id: T1059.001\nconnectorId: GoogleSecOps\n")
    _write(tmp_path, "ps_kql.yaml", "technique_id: T1059.001\nconnectorId: MicrosoftThreatProtection\n")
    _write(tmp_path, "ps_splunk.yaml", "technique_id: T1059.001\nquery: index=win\n")
    _write(tmp_path, "ps_esql.yaml", "technique_id: T1059.001\n")
    _write(tmp_path, "unknown_secops.yaml", "technique_id: T9999\nconnectorId: GoogleSecOps\n")


def test_index_by_own_id(tmp_path):
    _library(tmp_path)
    index = siem_index(str(tmp_path))
    assert index["T1003.001"] == {"SecOps", "Defender XDR"}
    # A sub-technique's detection doesn't cover its parent
    assert "T1003" not in index


def test_gaps_across_all_four(tmp_path):
    _library(tmp_path)
    out = siem_gaps(str(tmp_path), ATTACK)
    assert [s["id"] for s in out["siems"]] == ["secops", "mde", "splunk", "elastic"]
    # Covered in every SIEM, or not in ATT&CK: not a gap
    assert [t["technique_id"] for t in out["techniques"]] == ["T1003.001"]
    assert out["techniques"][0]["coverage"] == {"secops": True, "mde": True, "splunk": False, "elastic": False}
    assert out["summary"] == {"secops": 0, "mde": 0, "splunk": 1, "elastic": 1}


def test_only_the_users_siems(tmp_path):
    _library(tmp_path)
    out = siem_gaps(str(tmp_path), ATTACK, ["mde", "secops"])
    assert [s["id"] for s in out["siems"]] == ["secops", "mde"]
    assert out["techniques"] == []


def test_missing_library(tmp_path):
    out = siem_gaps(str(tmp_path / "none"), ATTACK)
    assert out["techniques"] == [] and out["summary"]["splunk"] == 0
