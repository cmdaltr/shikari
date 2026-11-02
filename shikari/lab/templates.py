"""
The machines you can create here. Each template names the engine that runs it, the OS it
records, the Linux distro (where that matters for the name), the short name tag, and the image
per architecture. offered() keeps only the ones this host can run, and picks the image for the
host's CPU — so on an Apple Silicon Mac the list gives an Ubuntu container, an Ubuntu VM, a Rocky
container and a macOS VM. There is no Windows template: Docker and Tart can't run Windows, and UTM
(which does, via QEMU) has no create-from-image. A Windows VM is built in the UTM app once and then
managed from Your machines (shikari.lab.engines.UTM).

A template says what Emulate can record on it, so the page can tie a machine back to the
telemetry it produces. The name tag is the lab naming convention's OS+version suffix (ubu24,
rky10, mac15), carried on the template so one machine of each distro reads unambiguously.
"""

from typing import Dict, List, Optional

from shikari.lab import hosts

# image: {arch: reference}. records: the telemetry sources this OS feeds (shikari.telemetry).
# distro: the Linux distribution (groups the create grid and picks the name tag); absent for macOS.
# tag: the name-convention OS+version suffix (shikari.lab.caldera.suggested_name).
TEMPLATES = [
    {
        "id": "ubuntu-vm", "engine": "tart", "kind": "vm", "os": "linux",
        "distro": "ubuntu", "tag": "ubu24",
        "name": "Ubuntu 24.04 VM", "image": {"arm64": "ghcr.io/cirruslabs/ubuntu:latest"},
        "records": "auditd, syslog, journald, Sysmon for Linux",
        "about": "A full Linux VM with its own kernel, so auditd and Sysmon for Linux record "
                 "exactly as on a real host. Heavier than the container.",
    },
    {
        "id": "ubuntu-container", "engine": "docker", "kind": "container", "os": "linux",
        "distro": "ubuntu", "tag": "ubu24",
        "name": "Ubuntu 24.04 container", "image": {"arm64": "ubuntu:24.04", "amd64": "ubuntu:24.04"},
        "records": "auditd, syslog, journald",
        "about": "A throwaway Linux container. Fast to create and reset; no kernel of its own, "
                 "so auditd records through the host — enough for process and file telemetry.",
    },
    {
        "id": "rocky-container", "engine": "docker", "kind": "container", "os": "linux",
        "distro": "rocky", "tag": "rky10",
        # Rocky is Docker-only: cirruslabs ships no Rocky Tart base, so Tart can't carry it (no guest
        # agent — the same blocker as macOS on a non-cirruslabs base). The container needs none.
        "name": "Rocky Linux 10 container", "image": {"arm64": "rockylinux/rockylinux:10", "amd64": "rockylinux/rockylinux:10"},
        "records": "auditd, syslog, journald",
        "about": "A throwaway RHEL-compatible container (Rocky 10). Like the Ubuntu container it has "
                 "no kernel of its own, so auditd records through the host.",
    },
    {
        "id": "macos-vm", "engine": "tart", "kind": "vm", "os": "macos",
        "tag": "mac15",
        "name": "macOS VM", "image": {"arm64": "ghcr.io/cirruslabs/macos-sequoia-base:latest"},
        "records": "Endpoint Security (eslogger), the unified log, launch items",
        "about": "A macOS VM on Apple Silicon. Records the unified log and Endpoint Security, "
                 "which no public dataset has — the main reason to record your own.",
    },
    # No Windows template: Tart can't run Windows (Apple's Virtualization.framework takes only
    # Linux and macOS guests), and UTM — which runs Windows 11 on ARM via QEMU — has no
    # create-from-image. Build the Windows VM in the UTM app once; Shikari then manages and records
    # it from Your machines (shikari.lab.engines.UTM). record-atomics.ps1 still works by hand too.
]
BY_ID = {t["id"]: t for t in TEMPLATES}
# template id -> name tag, the single source suggested_name and the UIs read so a name reads back
# to the right distro and version (ubuntu-vm -> ubu24, rocky-container -> rky10, macos-vm -> mac15).
TEMPLATE_TAG = {t["id"]: t["tag"] for t in TEMPLATES if t.get("tag")}

# One card per distro (Linux) or OS: the group-level blurb and the telemetry it feeds. The weight of
# a machine is the platform's (a container is light, a VM heavy) — that lives on the engine cards.
GROUP_INFO = {
    "ubuntu": {
        "name": "Ubuntu 24.04",
        "about": "A Linux box for recording Linux attack telemetry.",
        "records": "auditd, syslog, journald (Sysmon for Linux on a VM)",
    },
    "rocky": {
        "name": "Rocky Linux 10",
        "about": "An RHEL-compatible Linux box for recording Linux attack telemetry (Docker).",
        "records": "auditd, syslog, journald",
    },
    "macos": {
        "name": "macOS",
        "about": "macOS on Apple Silicon. Records the unified log and Endpoint Security, which "
                 "no public dataset has — the main reason to record your own.",
        "records": "Endpoint Security (eslogger), the unified log, launch items",
    },
    # "windows" intentionally absent — no engine here can create a Windows VM (see TEMPLATES).
}


def _group(template: Dict) -> str:
    """How the create grid groups a template, and which GROUP_INFO blurb it takes: the distro for
    Linux (Ubuntu and Rocky are separate cards), the OS otherwise."""
    return template.get("distro") or template["os"]


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
        group = _group(t)
        info = GROUP_INFO.get(group, {})
        out.append({**{k: t[k] for k in ("id", "engine", "kind", "os", "name", "records", "about")},
                    "group": group, "tag": t.get("tag"),
                    "os_name": info.get("name", t["name"]), "os_about": info.get("about", t["about"]),
                    "os_records": info.get("records", t["records"]),
                    "image": image, "ready": t["engine"] in ready, "reason": reason})
    return out
