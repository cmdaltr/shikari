"""
What this machine is, and which engines it can drive.

OS and CPU architecture decide which templates are offered and which image a template uses
(archer.lab.templates). An engine that isn't installed is reported with the command to
install it — Archer detects and guides, it doesn't install hypervisors itself.
"""

import platform
from typing import Dict, List

from archer.lab.runner import first_line, run, run_ok, which

# CPU architecture, normalised: Apple Silicon and x86-64 are the two that matter here
ARCH = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64", "x64": "amd64"}


def arch() -> str:
    return ARCH.get(platform.machine().lower(), platform.machine().lower())


def os_name() -> str:
    return {"darwin": "macos", "linux": "linux", "windows": "windows"}.get(platform.system().lower(),
                                                                            platform.system().lower())


# Each engine: how to detect it, what it runs, and how to install it per host OS
ENGINES = {
    "docker": {
        "name": "Docker",
        "runs": "Linux containers",
        "probe": ["docker", "version", "--format", "{{.Server.Version}}"],
        "install": {"macos": "brew install --cask orbstack   # or Docker Desktop",
                    "linux": "curl -fsSL https://get.docker.com | sh",
                    "windows": "winget install Docker.DockerDesktop"},
        "note": "OrbStack satisfies this too — it provides the docker command.",
    },
    "tart": {
        "name": "Tart",
        "runs": "macOS and Linux VMs on Apple Silicon",
        "probe": ["tart", "--version"],
        "install": {"macos": "brew install cirruslabs/cli/tart"},
        "requires": {"os": "macos", "arch": "arm64"},
    },
}


def _engine_status(key: str, spec: Dict) -> Dict:
    host_os, host_arch = os_name(), arch()
    requires = spec.get("requires") or {}
    supported = (requires.get("os", host_os) == host_os and requires.get("arch", host_arch) == host_arch)
    present = which(spec["probe"][0]) is not None
    version = ""
    if present:
        try:
            version = first_line(run(spec["probe"], timeout=15, check=False))
        except Exception:
            version = ""
    # OrbStack provides docker but reports its own daemon; "running" means the daemon answers
    running = present and run_ok(["docker", "info", "--format", "{{.ServerVersion}}"] if key == "docker"
                                 else spec["probe"])
    return {
        "key": key, "name": spec["name"], "runs": spec["runs"],
        "supported": supported, "installed": present, "running": running,
        "version": version, "note": spec.get("note", ""),
        "install": spec.get("install", {}).get(host_os, "") if supported and not present else "",
    }


def capabilities() -> Dict:
    """The host and its engines, for the Lab card. Cheap enough to call on each page load."""
    engines = [_engine_status(k, spec) for k, spec in ENGINES.items()]
    return {
        "os": os_name(), "arch": arch(),
        "label": f"{platform.system()} {platform.machine()}",
        "engines": engines,
        "ready": [e["key"] for e in engines if e["running"]],
    }


def engine_ready(key: str) -> bool:
    spec = ENGINES.get(key)
    return bool(spec) and _engine_status(key, spec)["running"]
