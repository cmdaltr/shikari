"""
The two engines Archer drives on the machine it runs on, behind one interface
(create/start/stop/snapshot/revert/delete/status/logs/exec):

  docker   Linux containers. A snapshot is a committed image; revert recreates the
           container from it. Works wherever the docker command does.
  tart     macOS and Linux VMs on Apple Silicon. A snapshot is a clone; revert deletes the
           VM and clones the snapshot back. `tart run` holds the VM open, so start spawns it.

The command parsing (parse_docker_ps, parse_tart_list) is pure, so it's tested without either
installed. Names are validated by the caller (archer.lab.machines) before they reach here.
"""

import json
from typing import Dict, List

from archer.lab.runner import LabError, run, run_ok, spawn

LABEL = "archer.lab=1"       # marks the containers Archer made
SNAP_TAG = "archer-snap"     # docker: snapshot images are archer-snap/<name>:<snap>
SNAP_SEP = ".snap."          # tart: a snapshot VM is <name>.snap.<snap>


def parse_docker_ps(out: str) -> List[Dict]:
    """`docker ps -a --format {{json .}}`: one JSON object per line."""
    machines = []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        name = row.get("Names", "")
        if not name or SNAP_TAG in row.get("Image", ""):
            continue
        state = (row.get("State") or "").lower()
        machines.append({"engine": "docker", "name": name, "kind": "container",
                        "image": row.get("Image", ""), "os": "linux",
                        "state": "running" if state == "running" else "stopped",
                        "detail": row.get("Status", "")})
    return machines


def parse_tart_list(out: str) -> List[Dict]:
    """`tart list --format json`: the local VMs, snapshots (name.snap.*) left out."""
    try:
        rows = json.loads(out or "[]")
    except ValueError:
        return []
    machines = []
    for row in rows if isinstance(rows, list) else []:
        if row.get("Source") != "local":
            continue
        name = row.get("Name", "")
        if not name or SNAP_SEP in name:
            continue
        running = (row.get("State") or row.get("Running") or "").lower()
        machines.append({"engine": "tart", "name": name, "kind": "vm", "image": "", "os": "",
                        "state": "running" if running in ("running", "true") else "stopped",
                        "detail": f"{row.get('Size', '')} on disk"})
    return machines


class Docker:
    key = "docker"

    def list(self) -> List[Dict]:
        return parse_docker_ps(run(["docker", "ps", "-a", "--filter", f"label={LABEL}",
                                    "--format", "{{json .}}"]))

    def create(self, name: str, image: str):
        run(["docker", "pull", image], timeout=600)
        # sleep infinity keeps the container up so we can exec into it; label marks it ours
        run(["docker", "run", "-d", "--name", name, "--label", LABEL, "--hostname", name,
             image, "sleep", "infinity"], timeout=120)

    def start(self, name: str):
        run(["docker", "start", name])

    def stop(self, name: str):
        run(["docker", "stop", name], timeout=60)

    def snapshot(self, name: str, snap: str):
        run(["docker", "commit", name, f"{SNAP_TAG}/{name}:{snap}"], timeout=120)

    def revert(self, name: str, snap: str):
        image = f"{SNAP_TAG}/{name}:{snap}"
        if not run_ok(["docker", "image", "inspect", image]):
            raise LabError("No such snapshot", f"{name} has no snapshot {snap}")
        run(["docker", "rm", "-f", name], timeout=60)
        run(["docker", "run", "-d", "--name", name, "--label", LABEL, "--hostname", name,
             image, "sleep", "infinity"], timeout=120)

    def delete(self, name: str):
        run(["docker", "rm", "-f", name], timeout=60, check=False)
        # Drop the machine's snapshot images too
        images = run(["docker", "images", f"{SNAP_TAG}/{name}", "--format", "{{.Repository}}:{{.Tag}}"],
                     check=False)
        for image in images.splitlines():
            if image.strip():
                run(["docker", "rmi", "-f", image.strip()], check=False)

    def status(self, name: str) -> Dict:
        found = [m for m in self.list() if m["name"] == name]
        if not found:
            raise LabError("No such machine", name)
        return found[0]

    def logs(self, name: str, tail: int) -> str:
        return run(["docker", "logs", "--tail", str(tail), name], check=False)

    def exec(self, name: str, argv: List[str], timeout: int) -> str:
        return run(["docker", "exec", name, *argv], timeout=timeout)


class Tart:
    key = "tart"

    def list(self) -> List[Dict]:
        return parse_tart_list(run(["tart", "list", "--format", "json"]))

    def create(self, name: str, image: str):
        run(["tart", "clone", image, name], timeout=1800)  # pulls the image if it's remote

    def start(self, name: str):
        spawn(["tart", "run", name, "--no-graphics"])  # holds the VM open; returns at once

    def stop(self, name: str):
        run(["tart", "stop", name], timeout=90, check=False)

    def snapshot(self, name: str, snap: str):
        run(["tart", "clone", name, f"{name}{SNAP_SEP}{snap}"], timeout=600)

    def revert(self, name: str, snap: str):
        clone = f"{name}{SNAP_SEP}{snap}"
        if not run_ok(["tart", "get", clone]):
            raise LabError("No such snapshot", f"{name} has no snapshot {snap}")
        run(["tart", "stop", name], timeout=90, check=False)
        run(["tart", "delete", name], check=False)
        run(["tart", "clone", clone, name], timeout=600)

    def delete(self, name: str):
        run(["tart", "stop", name], timeout=90, check=False)
        run(["tart", "delete", name], check=False)
        for row in parse_tart_list_raw():
            if row.startswith(f"{name}{SNAP_SEP}"):
                run(["tart", "delete", row], check=False)

    def status(self, name: str) -> Dict:
        found = [m for m in self.list() if m["name"] == name]
        if not found:
            raise LabError("No such machine", name)
        return found[0]

    def logs(self, name: str, tail: int) -> str:
        ip = run(["tart", "ip", name], check=False).strip()
        return (f"Tart doesn't keep a console log. The VM's address is {ip}.\n" if ip
                else "Tart doesn't keep a console log, and the VM has no address yet "
                     "(it may still be booting).\n")

    def exec(self, name: str, argv: List[str], timeout: int) -> str:
        return run(["tart", "exec", name, *argv], timeout=timeout)


def parse_tart_list_raw() -> List[str]:
    """Every local Tart VM name, snapshots included (delete sweeps a machine's snapshots)."""
    try:
        rows = json.loads(run(["tart", "list", "--format", "json"]))
    except (ValueError, LabError):
        return []
    return [r.get("Name", "") for r in rows if isinstance(r, dict) and r.get("Source") == "local"]


ENGINES = {"docker": Docker(), "tart": Tart()}


def engine_for(key: str):
    engine = ENGINES.get(key)
    if engine is None:
        raise LabError("Unknown engine", key)
    return engine
