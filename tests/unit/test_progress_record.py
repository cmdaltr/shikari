"""Progress records: a fresh start per run, and phase start stamps."""

import pytest

from archer.build import progress


@pytest.fixture(autouse=True)
def progress_dir(tmp_path, monkeypatch):
    from archer.build import run_files

    monkeypatch.setattr(progress, "PROGRESS_DIR", str(tmp_path))
    monkeypatch.setattr(run_files, "RUNS_DIR", str(tmp_path / "runs"))


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


def test_run_records_the_files_it_wrote_or_retagged():
    from archer.build import run_files

    progress.start_progress("UNC3944", {})
    run_files.note("data/groups/T1566_GoogleSecOps.yaml", "UNC3944")
    run_files.note("data/groups/T1566_GoogleSecOps.yaml", "UNC3944")
    run_files.note("data/groups/T1078_DeviceLogonEvents.yaml", "APT29")  # another group's run
    assert run_files.latest_run("UNC3944") is None  # nothing saved until the run completes
    progress.write_progress("UNC3944", {"phase": "complete", "status": "complete"})
    assert run_files.latest_run("UNC3944")["files"] == ["T1566_GoogleSecOps.yaml"]


def test_writes_outside_a_run_keep_the_last_manifest():
    from archer.build import run_files

    progress.start_progress("UNC3944", {})
    run_files.note("IOCSweepUNC3944_GoogleSecOps.yaml", "UNC3944")
    progress.write_progress("UNC3944", {"phase": "complete"})
    run_files.note("T1003_DeviceEvents.yaml", "UNC3944")  # no run in progress: ignored
    progress.write_progress("UNC3944", {"phase": "complete", "status": "complete"})
    assert run_files.latest_run("UNC3944")["files"] == ["IOCSweepUNC3944_GoogleSecOps.yaml"]


def test_latest_run_keeps_only_correlations_between_its_files():
    from archer.app import _run_correlations

    corrs = [
        {"a": "data/groups/A_GoogleSecOps.yaml", "b": "data/groups/B_GoogleSecOps.yaml"},
        {"a": "data/groups/A_GoogleSecOps.yaml", "b": "data/groups/Old_GoogleSecOps.yaml"},
        {"a": "data/groups/Old_GoogleSecOps.yaml", "b": None},
    ]
    assert _run_correlations(corrs, None) == corrs
    assert _run_correlations(corrs, {"A_GoogleSecOps.yaml", "B_GoogleSecOps.yaml"}) == corrs[:1]


def test_osint_snippets_do_not_hide_a_broken_detection_query(tmp_path):
    # The OSINT snippet loop used to reuse the name "query", so the write guard checked
    # the last snippet instead of the detection
    from archer.build.yaml import write_yaml

    path = tmp_path / "X_DeviceEvents.yaml"
    osint = {"osint_compared": True, "comparison_date": "2026-10-11",
             "osint_indicators": {"query_snippets": ["[Sigma] ProcessCommandLine has 'x'|||https://example.org"]}}
    write_yaml(str(path), "X", "T1098.001", "desc", "MicrosoftThreatProtection", ["Persistence"], "FIN13",
               'DeviceEvents\n| where ())))) or (ActionType has "a")', datatype="DeviceEvents", osint_data=osint)
    assert not path.exists()


def test_a_technique_counts_only_if_it_wrote_or_tagged_a_file():
    from archer.build import run_files
    from archer.build.orchestrator import _produced

    assert _produced("CVE-2024-3400", None)  # untracked (CLI): trust compile_query
    progress.start_progress("CVE-2024-3400", {})
    before = run_files.touches("CVE-2024-3400")
    assert not _produced("CVE-2024-3400", before)  # "No identifiers found": nothing written
    run_files.note("ExploitPublic-FacingApplication_GoogleSecOps.yaml", "CVE-2024-3400")
    assert _produced("CVE-2024-3400", before)


def test_brackets_inside_an_indicator_string_are_not_an_empty_group(tmp_path):
    # "()" in query used to refuse every query hunting for an API call by name
    from archer.build.yaml import write_yaml

    path = tmp_path / "DomainTrustDiscovery_DeviceProcessEvents.yaml"
    write_yaml(str(path), "Domain Trust Discovery", "T1482", "desc", "MicrosoftThreatProtection", ["Discovery"], "FIN13",
               'DeviceProcessEvents\n| where (ProcessCommandLine has "DSEnumerateDomainTrusts()")', datatype="DeviceProcessEvents")
    assert path.exists()


def test_technique_hunt_threshold_reaches_the_wrapper(monkeypatch):
    # /hunt/technique passed correlation_min_relevance, which the wrapper didn't take:
    # every technique hunt failed with a TypeError before generating anything
    import inspect

    from archer import app as app_module

    assert "correlation_min_relevance" in inspect.signature(app_module.modified_process_group_wrapper).parameters

