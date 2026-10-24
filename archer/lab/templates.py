"""
The machines you can create here. Each template names the engine that runs it, the OS it
records, and the image per architecture. offered() keeps only the ones this host can run,
and picks the image for the host's CPU — so the same list gives Linux containers and a macOS
VM on an Apple Silicon Mac, and (where Archer runs on an x64 host) a Windows VM.

A template says what Emulate can record on it, so the page can tie a machine back to the
telemetry it produces.
"""

from typing import Dict, List, Optional

from archer.lab import hosts

# image: {arch: reference}. records: the telemetry sources this OS feeds (archer.telemetry).
TEMPLATES = [
    {
        "id": "ubuntu-container", "engine": "docker", "kind": "container", "os": "linux",
        "name": "Ubuntu 24.04 container", "image": {"arm64": "ubuntu:24.04", "amd64": "ubuntu:24.04"},
        "records": "auditd, syslog, journald",
        "about": "A throwaway Linux container. Fast to create and reset; no kernel of its own, "
                 "so auditd records through the host — enough for process and file telemetry.",
    },
    {
        "id": "ubuntu-vm", "engine": "tart", "kind": "vm", "os": "linux",
        "name": "Ubuntu 24.04 VM", "image": {"arm64": "ghcr.io/cirruslabs/ubuntu:latest"},
        "records": "auditd, syslog, journald, Sysmon for Linux",
        "about": "A full Linux VM with its own kernel, so auditd and Sysmon for Linux record "
                 "exactly as on a real host. Heavier than the container.",
    },
    {
        "id": "macos-vm", "engine": "tart", "kind": "vm", "os": "macos",
        "name": "macOS VM", "image": {"arm64": "ghcr.io/cirruslabs/macos-sequoia-base:latest"},
        "records": "Endpoint Security (eslogger), the unified log, launch items",
        "about": "A macOS VM on Apple Silicon. Records the unified log and Endpoint Security, "
                 "which no public dataset has — the main reason to record your own.",
    },
    {
        "id": "windows-vm", "engine": "tart", "kind": "vm", "os": "windows",
        "name": "Windows 11 VM", "image": {"amd64": "ghcr.io/cirruslabs/windows-2022:latest"},
        "records": "Security, PowerShell, Sysmon, Defender, Task Scheduler, WMI, BITS",
        "about": "A Windows VM. Needs an x64 host — run Archer on an x64 machine (the Mac Mini) "
                 "to create it; it won't appear on an Apple Silicon Mac.",
    },
]
BY_ID = {t["id"]: t for t in TEMPLATES}


def _image_for(template: Dict, arch: str) -> Optional[str]:
    return (template.get("image") or {}).get(arch)


def offered(caps: Optional[Dict] = None) -> List[Dict]:
    """
    The templates this host can run: the engine is installed and running, and the image
    exists for the host's CPU. Each carries whether its engine is ready and the reason when not.
    """
    caps = caps or hosts.capabilities()
    ready = set(caps["ready"])
    by_key = {e["key"]: e for e in caps["engines"]}
    out = []
    for t in TEMPLATES:
        image = _image_for(t, caps["arch"])
        if not image:
            continue  # not built for this architecture (a Windows amd64 image on an arm64 host)
        engine = by_key.get(t["engine"], {})
        if not engine.get("supported"):
            continue
        reason = ""
        if not engine.get("installed"):
            reason = f"{engine['name']} isn't installed"
        elif not engine.get("running"):
            reason = f"{engine['name']} isn't running"
        out.append({**{k: t[k] for k in ("id", "engine", "kind", "os", "name", "records", "about")},
                    "image": image, "ready": t["engine"] in ready, "reason": reason})
    return out
