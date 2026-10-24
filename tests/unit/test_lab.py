"""The lab: host detection, templates filtered to the host, output parsing, and lifecycle
dispatch — all with the one shell-out point (archer.lab.runner.run) patched, so nothing runs."""

import json

import pytest

from archer.lab import engines, hosts, machines, provision, templates
from archer.lab.runner import LabError, safe_name


def test_safe_name_rejects_anything_that_could_reach_a_shell():
    assert safe_name("win11-run1") == "win11-run1"
    assert safe_name("CVE_2024") == "CVE_2024"
    for bad in ("", "a b", "a;rm -rf", "$(x)", "a/b", "../x", "a`b`", "-flag", "x" * 65):
        with pytest.raises(LabError):
            safe_name(bad)


def test_arch_and_templates_follow_the_host(monkeypatch):
    # An Apple Silicon Mac with both engines: Linux containers, Linux and macOS VMs, no Windows
    monkeypatch.setattr(hosts.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(hosts.platform, "system", lambda: "Darwin")
    caps = {"os": "macos", "arch": "arm64", "ready": ["docker", "tart"],
            "engines": [{"key": "docker", "name": "Docker", "supported": True, "installed": True, "running": True},
                        {"key": "tart", "name": "Tart", "supported": True, "installed": True, "running": True}]}
    ids = {t["id"]: t for t in templates.offered(caps)}
    assert set(ids) == {"ubuntu-container", "ubuntu-vm", "macos-vm"}  # no windows-vm on arm64
    assert ids["macos-vm"]["image"].startswith("ghcr.io/cirruslabs/macos")
    assert all(t["ready"] for t in ids.values())


def test_windows_only_appears_on_an_x64_host():
    x64 = {"os": "linux", "arch": "amd64", "ready": ["docker"],
           "engines": [{"key": "docker", "name": "Docker", "supported": True, "installed": True, "running": True},
                       {"key": "tart", "name": "Tart", "supported": False, "installed": False, "running": False}]}
    ids = {t["id"] for t in templates.offered(x64)}
    # tart isn't supported off Apple Silicon, so only the docker container is offered; no VMs
    assert ids == {"ubuntu-container"}


def test_a_missing_engine_is_reported_with_its_install_command(monkeypatch):
    monkeypatch.setattr(hosts.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(hosts.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(hosts, "which", lambda t: "/opt/homebrew/bin/tart" if t == "tart" else None)
    monkeypatch.setattr(hosts, "run_ok", lambda argv, timeout=20: argv[0] == "tart")
    monkeypatch.setattr(hosts, "run", lambda argv, timeout=15, check=False: "2.41.1\n")
    caps = hosts.capabilities()
    docker = next(e for e in caps["engines"] if e["key"] == "docker")
    assert not docker["installed"] and docker["install"]  # the brew/get.docker command
    assert "orbstack" in docker["install"].lower() or "docker" in docker["install"].lower()


def test_parse_docker_ps_skips_snapshot_images():
    out = "\n".join([
        json.dumps({"Names": "win11", "Image": "ubuntu:24.04", "State": "running", "Status": "Up 2m"}),
        json.dumps({"Names": "old", "Image": "archer-snap/win11:clean", "State": "exited", "Status": "x"}),
        json.dumps({"Names": "box", "Image": "ubuntu:24.04", "State": "exited", "Status": "Exited (0)"}),
    ])
    rows = engines.parse_docker_ps(out)
    assert [(r["name"], r["state"]) for r in rows] == [("win11", "running"), ("box", "stopped")]
    assert all(r["os"] == "linux" and r["kind"] == "container" for r in rows)


def test_parse_tart_list_keeps_local_vms_and_hides_snapshots():
    out = json.dumps([
        {"Source": "local", "Name": "macos-run1", "State": "running", "Size": "30 GB"},
        {"Source": "local", "Name": "macos-run1.snap.clean", "State": "stopped", "Size": "30 GB"},
        {"Source": "oci", "Name": "ghcr.io/cirruslabs/ubuntu:latest", "State": "stopped"},
    ])
    rows = engines.parse_tart_list(out)
    assert [(r["name"], r["state"]) for r in rows] == [("macos-run1", "running")]


def test_create_records_the_template_and_pulls_the_right_image(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr("archer.lab.engines.run", lambda argv, **k: calls.append(list(argv)) or "")
    monkeypatch.setattr(hosts.platform, "machine", lambda: "arm64")
    monkeypatch.setattr("archer.lab.registry._PATH", str(tmp_path / "machines.json"))
    machines.create("ubuntu-container", "box1")
    assert ["docker", "pull", "ubuntu:24.04"] in calls
    assert any(c[:3] == ["docker", "run", "-d"] and "box1" in c for c in calls)
    import archer.lab.registry as reg
    assert reg.get("docker", "box1")["template"] == "ubuntu-container"


def test_create_refuses_a_windows_vm_on_arm(monkeypatch, tmp_path):
    monkeypatch.setattr(hosts.platform, "machine", lambda: "arm64")
    monkeypatch.setattr("archer.lab.registry._PATH", str(tmp_path / "machines.json"))
    with pytest.raises(LabError):
        machines.create("windows-vm", "win1")


def test_docker_snapshot_and_revert_use_the_committed_image(monkeypatch):
    calls = []
    monkeypatch.setattr("archer.lab.engines.run", lambda argv, **k: calls.append(list(argv)) or "")
    monkeypatch.setattr("archer.lab.engines.run_ok", lambda argv, **k: True)
    d = engines.Docker()
    d.snapshot("box", "clean")
    assert ["docker", "commit", "box", "archer-snap/box:clean"] in calls
    d.revert("box", "clean")
    assert ["docker", "rm", "-f", "box"] in calls
    assert any(c[:3] == ["docker", "run", "-d"] and "archer-snap/box:clean" in c for c in calls)


def test_tart_start_spawns_and_snapshot_clones(monkeypatch):
    spawned, ran = [], []
    monkeypatch.setattr("archer.lab.engines.spawn", lambda argv: spawned.append(list(argv)))
    monkeypatch.setattr("archer.lab.engines.run", lambda argv, **k: ran.append(list(argv)) or "")
    t = engines.Tart()
    t.start("mac1")
    assert spawned == [["tart", "run", "mac1", "--no-graphics"]]
    t.snapshot("mac1", "clean")
    assert ["tart", "clone", "mac1", "mac1.snap.clean"] in ran


def test_provision_runs_the_os_script_inside_the_machine_and_remembers_it(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr("archer.lab.registry._PATH", str(tmp_path / "machines.json"))

    class FakeEngine:
        def exec(self, name, argv, timeout):
            seen["name"], seen["argv"] = name, argv
            return "auditd rules loaded"

    monkeypatch.setattr(provision, "engine_for", lambda key: FakeEngine())
    out = provision.run_step("docker", "box1", "linux", "logging")
    assert "auditd" in out and seen["name"] == "box1"
    assert seen["argv"][0] == "bash" and "auditd" in seen["argv"][-1]
    import archer.lab.registry as reg
    reg.record("docker", "box1", "ubuntu-container", "linux", "ubuntu:24.04")
    reg.mark_provisioned("docker", "box1", "logging")
    assert "logging" in reg.get("docker", "box1")["provisioned"]


def test_windows_provisioning_uses_powershell_and_lists_three_steps():
    steps = [s["step"] for s in provision.steps_for("windows")]
    assert steps == ["logging", "powershell", "atomics"]
    assert provision.STEPS["windows"]["interp"][0] == "pwsh"
    assert provision.steps_for("plan9") == []
