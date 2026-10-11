"""Progress records: a fresh start per run, and phase start stamps."""

import pytest

from archer.build import progress


@pytest.fixture(autouse=True)
def progress_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(progress, "PROGRESS_DIR", str(tmp_path))


def test_start_progress_drops_previous_run():
    progress.write_progress("APT29", {"status": "complete", "phase": "complete",
                                      "processed": 9000, "total_pairs": 9000, "vendor_count": 40})
    progress.start_progress("APT29", {"stage": "queued", "created_yaml": 0})
    rec = progress.read_progress("APT29")
    assert rec["phase"] == "preparing" and rec["status"] == "started"
    for stale in ("processed", "total_pairs", "vendor_count"):
        assert stale not in rec


def test_phase_change_is_stamped_once():
    progress.start_progress("APT29", {})
    progress.write_progress("APT29", {"phase": "detections", "processed_yaml": 1})
    first = progress.read_progress("APT29")["phase_started"]["detections"]
    progress.write_progress("APT29", {"phase": "detections", "processed_yaml": 2})
    rec = progress.read_progress("APT29")
    assert rec["phase_started"]["detections"] == first
    assert "preparing" in rec["phase_started"]


def test_updates_without_phase_keep_it():
    progress.start_progress("APT29", {})
    progress.write_progress("APT29", {"phase": "correlations"})
    progress.write_progress("APT29", {"processed": 10, "total_pairs": 100})
    rec = progress.read_progress("APT29")
    assert rec["phase"] == "correlations" and set(rec["phase_started"]) == {"preparing", "correlations"}


def test_ioc_only_report_completes_with_its_sweeps(monkeypatch):
    from archer import app as app_module
    from archer.build import ioc_sweep

    monkeypatch.setattr(app_module, "write_progress", progress.write_progress)
    monkeypatch.setattr(ioc_sweep, "write_ioc_sweeps", lambda *a, **k: ["IOCSweepX_GoogleSecOps.yaml", "IOCSweepX_MicrosoftThreatProtection.yaml"])
    monkeypatch.setattr(app_module, "modified_process_group_wrapper",
                        lambda *a, **k: pytest.fail("no techniques: nothing to generate"))
    progress.start_progress("UNC3944", {})
    app_module._run_report_generation("UNC3944", [], {"domain": ["evil[.]com"]}, "report", None, "UNC3944", "desc")
    rec = progress.read_progress("UNC3944")
    assert rec["phase"] == "complete" and rec["ioc_sweeps"] == 2 and "error" not in rec


def test_report_with_nothing_to_sweep_or_build_says_why(monkeypatch):
    from archer import app as app_module
    from archer.build import ioc_sweep

    monkeypatch.setattr(app_module, "write_progress", progress.write_progress)
    monkeypatch.setattr(ioc_sweep, "write_ioc_sweeps", lambda *a, **k: [])
    progress.start_progress("UNC3944", {})
    app_module._run_report_generation("UNC3944", [], {}, "report", None, "UNC3944", "desc")
    rec = progress.read_progress("UNC3944")
    assert rec["phase"] == "complete" and rec["ioc_sweeps"] == 0 and rec["error"]
