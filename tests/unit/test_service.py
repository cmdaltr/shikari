"""archer-cli start/stop/status (archer/service.py): crash restarts and the Ollama models folder."""

import importlib.util
import sys
import time
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("archer_service", Path(__file__).parents[2] / "archer" / "service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


@pytest.fixture(autouse=True)
def logs(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "LOG_DIR", tmp_path)


def _until(child, cond, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline and not cond():
        child.check()
        time.sleep(0.05)


@pytest.mark.unit
def test_a_crashed_child_is_restarted(monkeypatch):
    child = service.Child("t", [sys.executable, "-c", "import time; time.sleep(30)"])
    child.check()
    first = child.proc.pid
    child.proc.kill()
    monkeypatch.setattr(service, "BACKOFF_MAX", 0)
    _until(child, lambda: child.proc is not None and child.proc.pid != first)
    assert child.restarts == 1 and child.last_exit["code"] != 0 and child.proc.poll() is None
    child.stop()
    assert child.proc.poll() is not None


@pytest.mark.unit
def test_a_child_that_keeps_failing_to_start_is_given_up(monkeypatch):
    monkeypatch.setattr(service, "BACKOFF_MAX", 0)
    monkeypatch.setattr(service, "MAX_QUICK_EXITS", 3)
    child = service.Child("t", [sys.executable, "-c", "raise SystemExit(3)"])
    _until(child, lambda: child.failed)
    assert child.failed and child.restarts == 2 and child.last_exit["code"] == 3
    assert child.check() is False


@pytest.mark.unit
def test_ollama_models_on_an_unmounted_volume_fall_back_to_the_default(tmp_path):
    assert service.ollama_models_dir(str(tmp_path)) == (str(tmp_path), "")
    models, warning = service.ollama_models_dir("/Volumes/No Such Disk/ollama")
    assert models is None and "isn't mounted" in warning
    assert service.ollama_models_dir("")[0] is None
