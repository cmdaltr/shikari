#!/usr/bin/env python3
"""
End-to-end lifecycle of one Shikari lab engine on a real host: detect, create, start, wait until
the guest answers, exec, copy a file in and a folder out, snapshot, change something, revert,
confirm the change is gone, logs, stop, delete. One PASS/FAIL line per step; exit status is the
number of failures. Drives shikari.lab.machines and the engine exactly as the Lab page does.

Run from anywhere; it works out the repo root itself (Shikari's data/ is relative to it).

  KVM, Ubuntu cloud image:       lifecycle.py --engine libvirt --template ubuntu-kvm
  Hyper-V, Ubuntu cloud image:   lifecycle.py --engine hyperv  --template ubuntu-hyperv
  Hyper-V, your Windows disk:    lifecycle.py --engine hyperv  --image C:\\lab\\images\\ws2022-base.vhd
                                     --os windows --user Administrator --password-env SHIKARI_KIT_PASSWORD

--keep leaves the machine in place at the end (no stop, no delete), to look at it.
"""

import argparse
import os
import sys
import tempfile
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from shikari.lab import engines, hosts, machines  # noqa: E402
from shikari.lab.runner import LabError  # noqa: E402

results = []


def step(label, fn, needs=()):
    """Run one step. A step whose prerequisite failed is skipped, not run into a broken machine."""
    if any(r[1] != "PASS" for r in results if r[0] in needs):
        results.append((label, "SKIP", "an earlier step it needs failed"))
        print(f"SKIP  {label}", flush=True)
        return None
    t0 = time.time()
    try:
        detail = fn()
        verdict = "PASS"
    except AssertionError as e:
        detail, verdict = str(e), "FAIL"
    except LabError as e:
        detail, verdict = e.message + (f": {e.detail}" if e.detail else ""), "FAIL"
    except Exception as e:  # noqa: BLE001 - a kit reports everything, it never stops on a surprise
        detail, verdict = f"{type(e).__name__}: {e}", "FAIL"
    took = time.time() - t0
    line = str(detail or "").strip().splitlines()
    print(f"{verdict}  {label}  ({took:.0f}s){'  ' + line[0][:150] if line else ''}", flush=True)
    for extra in line[1:6] if verdict == "FAIL" else []:
        print(f"        {extra[:150]}")
    results.append((label, verdict, detail))
    return detail


def until(fn, timeout, every=10):
    """fn() until it returns without raising, or the time is up (then its last error is raised)."""
    deadline = time.time() + timeout
    while True:
        try:
            return fn()
        except Exception:  # noqa: BLE001
            if time.time() > deadline:
                raise
            time.sleep(every)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--engine", required=True, choices=["libvirt", "hyperv"])
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--template", help="a Lab template id (ubuntu-kvm, ubuntu-hyperv)")
    src.add_argument("--image", help="a disk image or ISO path on this host (create_from_image)")
    p.add_argument("--os", choices=["linux", "windows"], default="linux", help="the guest OS, with --image")
    p.add_argument("--name", help="machine name (default shi-kit-<engine>-<os>)")
    p.add_argument("--user", help="guest login (Hyper-V Windows: PowerShell Direct account)")
    p.add_argument("--password-env", help="environment variable holding the guest password")
    p.add_argument("--ready-timeout", type=int, default=1200,
                   help="seconds to wait for the guest to answer exec (first boot runs cloud-init)")
    p.add_argument("--keep", action="store_true", help="leave the machine at the end")
    args = p.parse_args()
    try:
        sys.stdout.reconfigure(errors="replace")
    except AttributeError:
        pass

    os_name = args.os if args.image else machines.BY_ID[args.template]["os"]
    windows = os_name == "windows"
    name = args.name or f"shi-kit-{'kvm' if args.engine == 'libvirt' else 'hv'}-{'win' if windows else 'lin'}"
    eng = engines.engine_for(args.engine)
    print(f"Shikari lab engine test: {args.engine}, {os_name} guest '{name}', repo {ROOT}\n")

    # Guest commands, per OS. The marker is what the snapshot must not contain after the revert.
    if windows:
        probe = ["cmd", "/c", "echo", "ok"]
        ident = ["cmd", "/c", "ver"]
        marker = r"C:\Windows\Temp\shikari-marker.txt"
        make = ["powershell", "-NoProfile", "-Command", f"Set-Content -Path '{marker}' -Value shikari"]
        check = ["powershell", "-NoProfile", "-Command",
                 f"if (Test-Path '{marker}') {{ 'present' }} else {{ 'absent' }}"]
        kit_dir = r"C:\Windows\Temp\shikari-kit"
        mkdir = ["powershell", "-NoProfile", "-Command", f"New-Item -ItemType Directory -Force -Path '{kit_dir}' | Out-Null"]
        pushed = kit_dir + r"\hello.txt"
    else:
        probe = ["true"]
        ident = ["sh", "-c", "uname -srm; . /etc/os-release; echo $PRETTY_NAME"]
        marker = "/var/tmp/shikari-marker"
        make = ["sh", "-c", f"echo shikari > {marker} && sync"]
        check = ["sh", "-c", f"test -f {marker} && echo present || echo absent"]
        kit_dir = "/tmp/shikari-kit"
        mkdir = ["mkdir", "-p", kit_dir]
        pushed = kit_dir + "/hello.txt"

    def detect():
        e = {x["key"]: x for x in hosts.capabilities()["engines"]}[args.engine]
        assert e["supported"], f"{e['name']} isn't supported on this host ({hosts.os_name()} {hosts.arch()})"
        assert e["installed"], f"{e['name']} isn't installed: {e['install']}"
        assert e["running"], f"{e['name']} is installed but not answering. {e['note']}"
        return f"{e['name']} {e['version']} ready"

    def create():
        assert name not in {m["name"] for m in eng.list()}, f"{name} already exists: delete it or pass --name"
        if args.template:
            machines.create(args.template, name)
        else:
            access = {"user": args.user or "", "password": os.environ.get(args.password_env or "", "")}
            machines.create_from_image(args.engine, name, args.image, os_name, access=access)
        return f"created from {args.template or args.image}"

    def start():
        machines.start(args.engine, name)
        st = until(lambda: _running(), 180, every=5)
        return st

    def _running():
        st = eng.status(name)
        assert st["state"] == "running", f"state is {st['state']}"
        return st["detail"]

    def ready():
        until(lambda: eng.exec(name, probe, timeout=30), args.ready_timeout, every=15)
        if not windows:  # first boot: let cloud-init finish installing what Shikari needs
            out = eng.exec(name, ["sh", "-c", "cloud-init status --wait >/dev/null 2>&1; cloud-init status"],
                           timeout=900)
            assert "done" in out, f"cloud-init: {out.strip()}"
            return "guest answers; " + out.strip()
        return "guest answers"

    def exec_():
        out = eng.exec(name, ident, timeout=60).strip()
        assert out, "no output"
        return out.replace("\n", " | ")

    def push_pull():
        eng.exec(name, mkdir, timeout=60)
        text = f"shikari kit {time.time()}\n"
        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "hello.txt")
            with open(local, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            eng.push_file(name, local, pushed, windows=windows)
            back = os.path.join(tmp, "back")
            eng.pull_dir(name, kit_dir, back, windows=windows)
            with open(os.path.join(back, "shikari-kit", "hello.txt"), encoding="utf-8") as fh:
                got = fh.read()
        assert got.replace("\r\n", "\n") == text, f"came back as {got!r}"
        return "file pushed in and its folder pulled back intact"

    def snapshot():
        out = eng.exec(name, check, timeout=60).strip()
        assert out == "absent", f"marker already {out} before the snapshot"
        return "snapshot " + machines.snapshot(args.engine, name, "kit-clean")["snapshot"]

    def change():
        eng.exec(name, make, timeout=60)
        out = eng.exec(name, check, timeout=60).strip()
        assert out == "present", f"marker is {out} after writing it"
        return "marker written: " + marker

    def revert():
        machines.revert(args.engine, name, "kit-clean")
        until(lambda: _running(), 300, every=5)
        until(lambda: eng.exec(name, probe, timeout=30), 300, every=10)
        return "reverted to kit-clean and the guest answers"

    def gone():
        out = eng.exec(name, check, timeout=60).strip()
        assert out == "absent", f"marker is still {out}: the revert didn't take"
        return "marker gone"

    def logs():
        out = machines.logs(args.engine, name)
        assert out.strip(), "no logs text"
        return out.strip().splitlines()[0]

    def stop():
        machines.stop(args.engine, name)

        def stopped():
            st = eng.status(name)
            assert st["state"] != "running", "still running"
            return st["detail"]

        return until(stopped, 240, every=5)

    def delete():
        machines.delete(args.engine, name)
        left = {m["name"] for m in eng.list()}
        assert name not in left, f"{name} still listed after delete"
        return "deleted, and no longer listed"

    step("detect engine", detect)
    step("create", create, needs=["detect engine"])
    step("start", start, needs=["create"])
    step("guest ready (exec answers)", ready, needs=["start"])
    step("exec a command", exec_, needs=["guest ready (exec answers)"])
    step("push a file, pull a folder", push_pull, needs=["guest ready (exec answers)"])
    step("snapshot (clean)", snapshot, needs=["guest ready (exec answers)"])
    step("change something", change, needs=["snapshot (clean)"])
    step("revert", revert, needs=["change something"])
    step("change is gone", gone, needs=["revert"])
    step("logs", logs, needs=["create"])
    if args.keep:
        print(f"\n--keep: {name} left in place.")
    else:
        step("stop", stop, needs=["start"])
        # Always try to clean up a machine that was created, whatever failed in between
        step("delete", delete, needs=["create"])

    fails = [r for r in results if r[1] == "FAIL"]
    print(f"\n{len([r for r in results if r[1] == 'PASS'])} passed, {len(fails)} failed, "
          f"{len([r for r in results if r[1] == 'SKIP'])} skipped")
    return len(fails)


if __name__ == "__main__":
    sys.exit(main())
