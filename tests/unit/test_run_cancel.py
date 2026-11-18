"""Cancelling a run: the record says so at once, and the run's own thread stops at its next write."""

import threading

import pytest

from shikari.build import progress


@pytest.fixture(autouse=True)
def progress_dir(tmp_path, monkeypatch):
    from shikari.build import run_files

    monkeypatch.setattr(progress, "PROGRESS_DIR", str(tmp_path))
    monkeypatch.setattr(run_files, "RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setattr(progress, "_notify", lambda *a: None)


def test_the_run_thread_stops_and_the_record_stays_cancelled():
    progress.start_progress("APT29", {})
    assert progress.cancel_run("APT29")
    assert progress.read_progress("APT29")["status"] == "cancelled"

    seen = {}

    def run():
        try:
            progress.write_progress("APT29", {"phase": "detections", "processed_yaml": 3})
        except progress.RunCancelled:
            seen["stopped"] = True
        # The run's own failure handler writes "failed": still cancelled
        try:
            progress.write_progress("APT29", {"status": "failed", "error": "x"})
        except progress.RunCancelled:
            pass

    t = threading.Thread(target=run, name=progress.RUN_THREAD)
    t.start(); t.join()
    rec = progress.read_progress("APT29")
    assert seen == {"stopped": True} and rec["status"] == "cancelled" and rec["processed_yaml"] == 3


def test_other_threads_write_without_stopping():
    progress.start_progress("APT29", {})
    progress.cancel_run("APT29")
    progress.write_progress("APT29", {"processed": 5})  # a page request or a worker: no raise
    assert progress.read_progress("APT29")["status"] == "cancelled"


def test_a_finished_run_cant_be_cancelled():
    progress.write_progress("APT29", {"status": "complete", "phase": "complete"})
    assert not progress.cancel_run("APT29")
    assert not progress.cancel_run("NeverRan")
