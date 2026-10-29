"""
Unit tests for the lab/caldera console module (archer.cli.modules.lab).

The module is a thin console front for archer.lab.caldera, so these mock the caldera functions and
assert the module dispatches to them correctly and never talks to a live server itself.
"""

import pytest

from archer.cli.modules import MODULE_REGISTRY
from archer.lab import caldera
from archer.lab.runner import LabError


@pytest.fixture
def module():
    return MODULE_REGISTRY["lab/caldera"]()


@pytest.fixture(autouse=True)
def fake_client(monkeypatch):
    """A client that never connects; from_settings() returns it."""
    class FakeClient:
        url = "https://caldera.test"
        def agents(self):
            return [{"group": "disposable", "platform": "linux", "paw": "a1"}]
        def abilities(self):
            return []
    monkeypatch.setattr(caldera.Client, "from_settings", staticmethod(lambda: FakeClient()))
    monkeypatch.setattr(caldera, "configured", lambda: True)
    return FakeClient


def test_registered():
    assert "lab/caldera" in MODULE_REGISTRY


def test_no_required_options(module):
    # Every action validates its own inputs inside run(), so none are globally required.
    assert module.validate() == []


def test_not_configured_prints_hint(monkeypatch, module, capsys):
    monkeypatch.setattr(caldera, "configured", lambda: False)
    called = {"from_settings": False}
    monkeypatch.setattr(caldera.Client, "from_settings",
                        staticmethod(lambda: called.__setitem__("from_settings", True)))
    module.run()
    out = capsys.readouterr().out
    assert "isn't configured" in out
    assert called["from_settings"] is False  # returns before touching the client


def test_status_lists_groups(module, capsys):
    module.set_option("ACTION", "status")
    module.run()
    out = capsys.readouterr().out
    assert "disposable" in out and "linux" in out


def test_run_dry_run_does_not_execute(monkeypatch, module, capsys):
    monkeypatch.setattr(caldera, "resolve_techniques", lambda *a, **k: ["T1033"])
    monkeypatch.setattr(caldera, "plan", lambda *a, **k: {"steps": [{"ability_id": "x"}], "gaps": [], "warnings": []})
    monkeypatch.setattr(caldera, "plan_lines", lambda plan, label: [f"plan for {label}"])
    boom = lambda *a, **k: pytest.fail("operate must not run on a dry run")
    monkeypatch.setattr(caldera, "operate", boom)

    module.set_option("ACTION", "run")
    module.set_option("TARGET", "T1033")
    module.set_option("GROUP", "disposable")
    module.run()
    out = capsys.readouterr().out
    assert "dry run" in out.lower()
    assert "EXECUTE true" in out


def test_run_execute_runs_pipeline_and_captures(monkeypatch, module, capsys):
    order = []
    monkeypatch.setattr(caldera, "resolve_techniques", lambda *a, **k: ["T1033"])
    monkeypatch.setattr(caldera, "plan", lambda *a, **k: {"steps": [{"ability_id": "x"}], "gaps": [], "warnings": []})
    monkeypatch.setattr(caldera, "plan_lines", lambda plan, label: ["line"])
    monkeypatch.setattr(caldera, "operate", lambda *a, **k: order.append("operate") or {"operation_id": "op1"})
    monkeypatch.setattr(caldera, "wait", lambda *a, **k: order.append("wait") or "finished")
    def fake_collect(client, op_id, rebuild=False):
        order.append(("collect", rebuild))
        return {"name": "op1", "steps": []}
    monkeypatch.setattr(caldera, "collect", fake_collect)
    monkeypatch.setattr(caldera, "capture_via_agent", lambda *a, **k: order.append("capture"))
    monkeypatch.setattr(caldera, "check_operation", lambda *a, **k: {"operation": "op1", "evidence": "captured logs",
                                                                     "summary": {"techniques": 1, "matched": 1, "missed": 0, "no_detections": 0},
                                                                     "techniques": [{"technique_id": "T1033", "technique_name": "whoami", "status": "matched"}]})
    monkeypatch.setattr(caldera, "check_correlations", lambda *a, **k: {"summary": {"testable": 0, "fired": 0, "half_fired": 0, "missed": 0}, "correlations": []})

    module.set_option("ACTION", "run")
    module.set_option("TARGET", "T1033")
    module.set_option("GROUP", "disposable")
    module.set_option("EXECUTE", "true")
    module.set_option("CAPTURE", "caldera")
    module.run()

    # capture=caldera means collect(rebuild=False) then capture_via_agent, then the check
    assert order == ["operate", "wait", ("collect", False), "capture"]
    out = capsys.readouterr().out
    assert "matched" in out and "T1033" in out


def test_check_without_name_lists_collected(monkeypatch, module, capsys):
    monkeypatch.setattr(caldera, "collected", lambda: [{"name": "run-a", "operation_id": "op1"}])
    module.set_option("ACTION", "check")
    module.run()
    out = capsys.readouterr().out
    assert "run-a" in out and "op1" in out


def test_laberror_is_caught(monkeypatch, module, capsys):
    class Boom:
        def agents(self):
            raise LabError("Could not reach CALDERA", "connection refused")
    monkeypatch.setattr(caldera.Client, "from_settings", staticmethod(lambda: Boom()))
    module.set_option("ACTION", "status")
    module.run()  # must not raise
    out = capsys.readouterr().out
    assert "CALDERA error" in out and "connection refused" in out
