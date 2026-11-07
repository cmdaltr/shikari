"""Docker status re-checks while unavailable, so Docker started after the server is picked up."""
from shikari.validation import orchestrator as orch


def test_docker_started_after_server_is_seen(monkeypatch):
    answers = iter([(False, "Docker is installed but not running."), (True, "Docker is available.")])
    monkeypatch.setattr(orch, "check_docker_available", lambda: next(answers))
    monkeypatch.setattr(orch.ValidationOrchestrator, "_init_components", lambda self: None)

    o = orch.ValidationOrchestrator()
    assert o.docker_available is False
    assert o.get_docker_status()["available"] is True
