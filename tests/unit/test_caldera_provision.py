"""Stage 1 of in-app CALDERA provisioning (archer.lab.caldera_provision): the host/role/opt-in
gate, the config parse, and the task flow with the host calls mocked out."""

import archer.lab.caldera_provision as p


def test_can_provision_requires_macos(monkeypatch):
    monkeypatch.setattr(p.hosts, "os_name", lambda: "linux")
    monkeypatch.setenv("ARCHER_ALLOW_LAB_PROVISION", "1")
    ok, why = p.can_provision(True)
    assert not ok and "macOS" in why


def test_can_provision_requires_admin(monkeypatch):
    monkeypatch.setattr(p.hosts, "os_name", lambda: "macos")
    monkeypatch.setenv("ARCHER_ALLOW_LAB_PROVISION", "1")
    assert p.can_provision(False) == (False, "Provisioning needs an admin account.")


def test_can_provision_requires_optin(monkeypatch):
    monkeypatch.setattr(p.hosts, "os_name", lambda: "macos")
    monkeypatch.delenv("ARCHER_ALLOW_LAB_PROVISION", raising=False)
    ok, why = p.can_provision(True)
    assert not ok and "ARCHER_ALLOW_LAB_PROVISION" in why


def test_can_provision_allowed(monkeypatch):
    monkeypatch.setattr(p.hosts, "os_name", lambda: "macos")
    monkeypatch.setenv("ARCHER_ALLOW_LAB_PROVISION", "yes")
    assert p.can_provision(True) == (True, "")


def test_field_parses_config_block():
    out = 'caldera:\n  url: "http://10.0.0.5:8888"\n  api_key: "abc123"\n  verify_tls: false\n'
    assert p._field(out, "url") == "http://10.0.0.5:8888"
    assert p._field(out, "api_key") == "abc123"
    assert p._field(out, "missing") == ""


def test_initial_tasks_order():
    assert [t["id"] for t in p.initial_tasks()] == ["check", "homebrew", "orbstack", "server", "agents", "configure"]
    assert all(t["state"] == "pending" for t in p.initial_tasks())


def test_provision_happy_path(monkeypatch):
    """Everything already present: each task ends 'done' and the parsed URL/key is saved."""
    monkeypatch.setattr(p.hosts, "os_name", lambda: "macos")
    monkeypatch.setattr(p, "which", lambda tool: "/usr/local/bin/" + tool)  # brew + orb present
    monkeypatch.setattr(p, "_docker_ready", lambda: True)
    monkeypatch.setattr(p, "lab_up", lambda: True)  # server container up
    monkeypatch.setattr(p, "_stream", lambda argv, say, cwd=None, extra_env=None: 0)
    monkeypatch.setattr(p, "_script", lambda: "/tmp/caldera-lab.sh")

    def fake_run(argv, timeout=120, check=True, input_text=None):
        if argv[-1] == "config":
            return 'caldera:\n  url: "http://10.0.0.9:8888"\n  api_key: "redkey"\n  verify_tls: false\n'
        return ""

    monkeypatch.setattr(p, "run", fake_run)

    states, saved = {}, {}

    def task(tid, **ch):
        if "state" in ch:
            states[tid] = ch["state"]

    p.provision(lambda line: None, task,
                lambda url, key, verify: saved.update(url=url, key=key, verify=verify))

    assert states == {"check": "done", "homebrew": "done", "orbstack": "done",
                      "server": "done", "agents": "done", "configure": "done"}
    assert saved == {"url": "http://10.0.0.9:8888", "key": "redkey", "verify": False}


def test_provision_fails_without_config(monkeypatch):
    """If caldera-lab.sh config yields no key, configure fails and nothing is saved."""
    monkeypatch.setattr(p.hosts, "os_name", lambda: "macos")
    monkeypatch.setattr(p, "which", lambda tool: "/usr/local/bin/" + tool)
    monkeypatch.setattr(p, "_docker_ready", lambda: True)
    monkeypatch.setattr(p, "lab_up", lambda: True)
    monkeypatch.setattr(p, "_stream", lambda argv, say, cwd=None, extra_env=None: 0)
    monkeypatch.setattr(p, "_script", lambda: "/tmp/caldera-lab.sh")
    monkeypatch.setattr(p, "run", lambda argv, timeout=120, check=True, input_text=None: "nothing useful")

    saved = {}
    try:
        p.provision(lambda line: None, lambda tid, **ch: None, lambda *a: saved.update(hit=True))
        assert False, "expected LabError"
    except p.LabError:
        pass
    assert saved == {}
