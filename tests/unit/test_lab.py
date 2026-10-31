"""The lab: host detection, templates filtered to the host, output parsing, and lifecycle
dispatch — all with the one shell-out point (archer.lab.runner.run) patched, so nothing runs."""

import json

import pytest

from archer.lab import engines, hosts, machines, provision, templates
from archer.lab.runner import LabError, safe_name


@pytest.fixture(autouse=True)
def utm_already_quiet(monkeypatch):
    # Otherwise the first utmctl call reads UTM's real preferences
    monkeypatch.setattr("archer.lab.engines._utm_quiet", True)


def test_safe_name_rejects_anything_that_could_reach_a_shell():
    assert safe_name("win11-run1") == "win11-run1"
    assert safe_name("CVE_2024") == "CVE_2024"
    for bad in ("", "a b", "a;rm -rf", "$(x)", "a/b", "../x", "a`b`", "-flag", "x" * 65):
        with pytest.raises(LabError):
            safe_name(bad)


def test_arch_and_templates_follow_the_host(monkeypatch):
    # An Apple Silicon Mac with both engines: Linux containers (Ubuntu, Rocky), Linux and macOS VMs, no Windows
    monkeypatch.setattr(hosts.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(hosts.platform, "system", lambda: "Darwin")
    caps = {"os": "macos", "arch": "arm64", "ready": ["docker", "tart"],
            "engines": [{"key": "docker", "name": "Docker", "supported": True, "installed": True, "running": True},
                        {"key": "tart", "name": "Tart", "supported": True, "installed": True, "running": True}]}
    ids = {t["id"]: t for t in templates.offered(caps)}
    assert set(ids) == {"ubuntu-container", "ubuntu-vm", "rocky-container", "macos-vm"}  # no Windows: no engine can run it
    assert ids["macos-vm"]["image"].startswith("ghcr.io/cirruslabs/macos")
    assert all(t["ready"] for t in ids.values())


def test_only_docker_templates_on_an_x64_host():
    x64 = {"os": "linux", "arch": "amd64", "ready": ["docker"],
           "engines": [{"key": "docker", "name": "Docker", "supported": True, "installed": True, "running": True},
                       {"key": "tart", "name": "Tart", "supported": False, "installed": False, "running": False}]}
    ids = {t["id"] for t in templates.offered(x64)}
    # tart isn't supported off Apple Silicon, so only the docker containers are offered; no VMs
    assert ids == {"ubuntu-container", "rocky-container"}


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


def test_create_refuses_an_unknown_template(monkeypatch, tmp_path):
    # There is no Windows template (no engine here can run Windows), so asking for one is refused
    monkeypatch.setattr(hosts.platform, "machine", lambda: "arm64")
    monkeypatch.setattr("archer.lab.registry._PATH", str(tmp_path / "machines.json"))
    assert "windows-vm" not in templates.BY_ID
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


# --- Step 5: record (Atomic Red Team → Your lab). Nothing detonates: execute stays False. ---

def test_clean_techniques_validates_and_dedupes():
    from archer.lab import record as lab_run

    assert lab_run.clean_techniques("t1059.001, T1053.003 T1059.001") == ["T1059.001", "T1053.003"]
    assert lab_run.clean_techniques(["T1003"]) == ["T1003"]
    for bad in ("", "   ", "T105", "1059", "T1059.1", "notatech", "T1059;rm"):
        with pytest.raises(LabError):
            lab_run.clean_techniques(bad)


def test_plan_lists_the_steps_without_running_anything():
    from archer.lab import record as lab_run

    steps = lab_run.plan("docker", "box1", "linux", ["T1059.001"], "box1-run", revert_to="clean")
    joined = "\n".join(steps)
    assert "record-atomics.ps1" in joined and "box1-run" in joined
    assert any("Revert box1 to the snapshot clean" in s for s in steps)
    assert any("Rebuild Your lab" in s for s in steps)
    # Windows uses powershell and Windows paths
    win = lab_run.plan("tart", "win1", "windows", ["T1003"], "win1-run")
    assert any("powershell" in s and "Windows\\Temp" in s for s in win)


def test_record_dry_run_runs_nothing(monkeypatch):
    from archer.lab import record as lab_run

    # Any shell-out or engine use would be a bug in the dry run — make them explode if touched
    def boom(*a, **k):
        raise AssertionError("dry run must not touch the engine")

    monkeypatch.setattr(lab_run, "engine_for", boom)
    monkeypatch.setattr(lab_run, "_push", boom)
    monkeypatch.setattr(lab_run, "_pull", boom)
    lines = []
    out = lab_run.record("docker", "box1", "linux", "T1059.001", run_name="box1-run",
                         execute=False, say=lines.append)
    assert out == {"run": "box1-run", "executed": False, "plan_only": True}
    assert any(l.startswith("would: ") for l in lines)
    assert any("Dry run" in l for l in lines)


def test_listing_shows_only_machines_archer_made(monkeypatch, tmp_path):
    # Two VMs on the host; only one is in Archer's registry — the other is left out
    monkeypatch.setattr("archer.lab.registry._PATH", str(tmp_path / "machines.json"))
    monkeypatch.setattr(engines.Docker, "list", lambda self: [])
    monkeypatch.setattr(engines.Tart, "list", lambda self: [
        {"engine": "tart", "name": "mine", "kind": "vm", "image": "", "os": "", "state": "stopped", "detail": ""},
        {"engine": "tart", "name": "sequoia-vm", "kind": "vm", "image": "", "os": "", "state": "stopped", "detail": ""},
    ])
    import archer.lab.registry as reg
    reg.record("tart", "mine", "macos-vm", "macos", "ghcr.io/cirruslabs/macos", owner=1)
    names = [m["name"] for m in machines.listing(["tart"], user_id=1, is_admin=False)]
    assert names == ["mine"]  # sequoia-vm (not in the registry) is omitted
    assert machines.listing(["tart"], user_id=1, is_admin=False)[0]["os"] == "macos"


def test_all_host_names_includes_vms_outside_archer(monkeypatch):
    # For clash-free naming: every name on the host, Archer's and not
    monkeypatch.setattr(engines.Docker, "list", lambda self: [
        {"engine": "docker", "name": "archer-ubuntu-1", "kind": "container", "image": "", "os": "linux", "state": "running", "detail": ""}])
    monkeypatch.setattr("archer.lab.engines.run",
                        lambda argv, **k: json.dumps([{"Source": "local", "Name": "sequoia-vm"},
                                                      {"Source": "local", "Name": "archer-macos-1"}]))
    names = machines.all_host_names(["docker", "tart"])
    assert "archer-ubuntu-1" in names and "sequoia-vm" in names and "archer-macos-1" in names


# --- UTM engine (Windows/Linux VMs via QEMU; utmctl-driven, create is manual) ---

def test_parse_utm_list_reads_the_table_and_marks_running():
    out = ("UUID                                  Status   Name\n"
           "11111111-1111-1111-1111-111111111111  started  archer-win11\n"
           "22222222-2222-2222-2222-222222222222  stopped  archer-ubuntu\n")
    rows = engines.parse_utm_list(out)
    assert [(r["name"], r["state"]) for r in rows] == [("archer-win11", "running"), ("archer-ubuntu", "stopped")]
    assert all(r["engine"] == "utm" and r["kind"] == "vm" for r in rows)


def test_utm_snapshot_restore_and_start_use_utmctl(monkeypatch):
    calls = []
    monkeypatch.setattr("archer.lab.engines.run", lambda argv, **k: calls.append(list(argv)) or "")
    u = engines.UTM()
    u.snapshot("win", "clean")
    u.revert("win", "clean")
    u.start("win")
    assert ["utmctl", "snapshot", "create", "win", "--name", "clean"] in calls
    assert ["utmctl", "snapshot", "restore", "win", "--snapshot", "clean"] in calls
    assert any(c[:3] == ["utmctl", "start", "--hide"] for c in calls)


def test_utm_is_kept_out_of_the_dock_unless_you_chose_otherwise(monkeypatch):
    calls = []
    monkeypatch.setattr("archer.lab.engines.run", lambda argv, **k: calls.append(list(argv)) or "")
    write = ["defaults", "write", "com.utmapp.UTM", "HideDockIcon", "-bool", "true"]

    # Never set: Archer sets it, once, before its first utmctl call
    monkeypatch.setattr("archer.lab.engines._utm_quiet", False)
    monkeypatch.setattr("archer.lab.engines.run_ok", lambda argv, **k: False)
    engines.UTM().start("win")
    engines.UTM().stop("win")
    assert calls.count(write) == 1 and calls.index(write) < calls.index(["utmctl", "start", "--hide", "win"])

    # Set by you, either way: left alone
    calls.clear()
    monkeypatch.setattr("archer.lab.engines._utm_quiet", False)
    monkeypatch.setattr("archer.lab.engines.run_ok", lambda argv, **k: True)
    engines.UTM().start("win")
    assert write not in calls


def test_utm_create_is_refused_with_guidance():
    with pytest.raises(LabError):
        engines.UTM().create("win", "")


def test_utm_clone_uses_utmctl(monkeypatch):
    calls = []
    monkeypatch.setattr("archer.lab.engines.run", lambda argv, **k: calls.append(list(argv)) or "")
    engines.UTM().clone("archer-win11", "archer-win11-2")
    assert ["utmctl", "clone", "archer-win11", "--name", "archer-win11-2"] in calls


def test_machines_clone_carries_the_source_os(monkeypatch, tmp_path):
    monkeypatch.setattr("archer.lab.registry._PATH", str(tmp_path / "m.json"))
    cloned = []
    monkeypatch.setattr(engines.UTM, "clone", lambda self, name, new: cloned.append((name, new)))
    import archer.lab.registry as reg
    reg.record("utm", "archer-win11", "utm-vm", "windows", "")
    out = machines.clone("utm", "archer-win11", "archer-win11-2")
    assert cloned == [("archer-win11", "archer-win11-2")]
    assert out["os"] == "windows"
    assert reg.get("utm", "archer-win11-2")["os"] == "windows"  # clone registered with the OS


def test_machines_clone_refused_for_an_engine_without_clone(monkeypatch):
    monkeypatch.setattr(engines.Docker, "list", lambda self: [])
    with pytest.raises(LabError):
        machines.clone("docker", "box", "box-2")


def test_utm_exec_puts_cmd_last_and_forwards_stdin(monkeypatch):
    seen = {}

    def fake_run(argv, timeout=120, check=True, input_text=None):
        seen["argv"], seen["input"] = list(argv), input_text
        return "ok"

    monkeypatch.setattr("archer.lab.engines.run", fake_run)
    engines.UTM().exec("vm", ["bash", "-lc", "id"], timeout=30, input_text="data")
    a = seen["argv"]
    assert a[:4] == ["utmctl", "exec", "--hide", "vm"] and "--input" in a
    assert a[a.index("--cmd") + 1:] == ["bash", "-lc", "id"] and seen["input"] == "data"


def test_utm_vms_are_managed_and_adopt_sets_their_os(monkeypatch, tmp_path):
    monkeypatch.setattr("archer.lab.registry._PATH", str(tmp_path / "m.json"))
    monkeypatch.setattr(engines.Docker, "list", lambda self: [])
    monkeypatch.setattr(engines.Tart, "list", lambda self: [])
    monkeypatch.setattr(engines.UTM, "list", lambda self: [
        {"engine": "utm", "name": "archer-win11", "uuid": "u", "kind": "vm", "image": "",
         "os": "", "state": "stopped", "detail": "stopped"}])
    rows = machines.listing(["utm"])
    assert rows and rows[0]["archer"] is True and rows[0]["adopted"] is False and rows[0]["os"] == ""
    machines.adopt("utm", "archer-win11", "windows")
    rows = machines.listing(["utm"])
    assert rows[0]["adopted"] is True and rows[0]["os"] == "windows"


def test_utm_engine_is_detected_on_macos(monkeypatch):
    monkeypatch.setattr(hosts.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(hosts.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(hosts, "which", lambda t: "/opt/homebrew/bin/utmctl" if t == "utmctl" else None)
    monkeypatch.setattr(hosts, "_utm_version", lambda: "5.0.8")
    monkeypatch.setattr(hosts, "_utm_ready", lambda: True)
    e = {x["key"]: x for x in hosts.capabilities()["engines"]}["utm"]
    assert e["supported"] and e["installed"] and e["running"] and e["version"] == "5.0.8"
    assert e["blurb"] and "brew install --cask utm" not in e["install"]  # installed, so no install cmd
