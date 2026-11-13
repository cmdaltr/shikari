"""
What this machine is, and which engines it can drive.

OS and CPU architecture decide which templates are offered and which image a template uses
(shikari.lab.templates). An engine that isn't installed is reported with the command to
install it — Shikari detects and guides, it doesn't install hypervisors itself. The one
exception is CALDERA provisioning (shikari.lab.caldera_provision), which does install OrbStack,
but only on an opt-in local macOS host, never on a shared server.
"""

import platform
from typing import Dict, List

from shikari.lab.runner import LabError, first_line, run, run_ok, which

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
        "blurb": "A throwaway container. Fast to create and reset; no kernel of its own. "
                 "Enough for process and file telemetry.",
        "probe": ["docker", "version", "--format", "{{.Server.Version}}"],
        "install": {"macos": "brew install --cask orbstack   # or Docker Desktop",
                    "linux": "curl -fsSL https://get.docker.com | sh",
                    "windows": "winget install Docker.DockerDesktop"},
        "note": "OrbStack satisfies this too — it provides the docker command.",
    },
    "tart": {
        "name": "Tart",
        "runs": "macOS and Linux VMs on Apple Silicon",
        "blurb": "A full VM with its own kernel — records exactly as on a real host, Sysmon "
                 "included. Heavier than a container.",
        "probe": ["tart", "--version"],
        "install": {"macos": "brew install cirruslabs/cli/tart"},
        "requires": {"os": "macos", "arch": "arm64"},
    },
    "utm": {
        "name": "UTM",
        "runs": "Windows, Linux and more via QEMU",
        "blurb": "QEMU VMs on macOS, including Windows 11 on ARM. You build the VM in UTM once; "
                 "Shikari then starts, snapshots, provisions and records it.",
        "probe": ["utmctl", "version"],
        "install": {"macos": "brew install --cask utm"},
        "requires": {"os": "macos"},
        "note": "The first time Shikari drives utmctl, macOS asks you to allow Automation access "
                "to UTM — grant it (System Settings → Privacy & Security → Automation), and open "
                "the UTM app once.",
    },
    "hyperv": {
        "name": "Hyper-V",
        "runs": "Windows and Linux VMs on Windows",
        "blurb": "Hyper-V VMs on a Windows host. Shikari creates a Linux VM from a cloud image, or a "
                 "VM from your VHDX or ISO, and starts, checkpoints, provisions and records it.",
        "probe": ["powershell", "-NoProfile", "-Command", "Get-VMHost"],
        "install": {"windows": "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All   "
                               "# elevated PowerShell, then reboot (Windows Pro, Enterprise or Education)"},
        "requires": {"os": "windows"},
        "note": "Shikari needs to run elevated, or as a member of the Hyper-V Administrators group "
                "(sign out and in after adding it). A Linux cloud image also needs qemu-img "
                "(winget install SoftwareFreedomConservancy.QEMU).",
    },
    "libvirt": {
        "name": "KVM (libvirt)",
        "runs": "Linux and Windows VMs on Linux",
        "blurb": "KVM/QEMU VMs through libvirt. Shikari creates a Linux VM from a cloud image, or one "
                 "from your ISO, and starts, snapshots, provisions and records it.",
        "probe": ["virsh", "--version"],
        "install": {"linux": "sudo apt install -y qemu-system-x86 libvirt-daemon-system virtinst qemu-utils "
                             "&& sudo usermod -aG libvirt,kvm $USER   # then sign out and in"},
        "requires": {"os": "linux"},
        "note": "virsh answers only for a member of the libvirt group (qemu:///system), and VMs need "
                "/dev/kvm: on a VM host, nested virtualisation must be on. Creating a VM also needs "
                "virt-install (the virtinst package).",
    },
}


_UTM_READY = {"t": 0.0, "ok": False}


def _utm_version() -> str:
    """UTM's version from its bundle — not utmctl, which would try to drive the app and can hang."""
    import plistlib

    try:
        with open("/Applications/UTM.app/Contents/Info.plist", "rb") as fh:
            return plistlib.load(fh).get("CFBundleShortVersionString", "")
    except Exception:
        return ""


def _utm_ready() -> bool:
    """Whether utmctl answers — true only once the UTM app is open and Automation is allowed.
    Cached briefly, and short-timed, because before the grant utmctl blocks on the macOS prompt."""
    import time

    now = time.time()
    if now - _UTM_READY["t"] < 20:
        return _UTM_READY["ok"]
    from shikari.lab.engines import utmctl

    try:
        utmctl("list", "--hide", timeout=8)
        ok = True
    except LabError:
        ok = False
    _UTM_READY.update(t=now, ok=ok)
    return ok


_HYPERV = {"t": 0.0, "probe": None}

# One PowerShell launch answers all three questions (a launch costs about a second)
HYPERV_PROBE = ("$m = [bool](Get-Command Get-VM -ErrorAction SilentlyContinue); $h = $false; $v = ''; "
                "if ($m) { try { Get-VMHost -ErrorAction Stop | Out-Null; $h = $true } catch {} }; "
                "try { $v = (Get-Item \"$env:windir\\System32\\vmms.exe\" -ErrorAction Stop).VersionInfo.ProductVersion } catch {}; "
                "ConvertTo-Json -InputObject @{ module = $m; host = $h; version = $v } -Compress")


def parse_hyperv_probe(out: str) -> Dict:
    """HYPERV_PROBE's answer: installed (the Hyper-V module is there), running (Get-VMHost works for
    this account, which needs elevation or Hyper-V Administrators) and the VMMS version."""
    import json

    try:
        row = json.loads((out or "").strip() or "{}")
    except ValueError:
        row = {}
    row = row if isinstance(row, dict) else {}
    return {"installed": bool(row.get("module")), "running": bool(row.get("host")),
            "version": str(row.get("version") or "")}


def _hyperv_probe() -> Dict:
    """Cached briefly: the Lab page asks on every load, and PowerShell is slow to start."""
    import time

    now = time.time()
    if _HYPERV["probe"] is not None and now - _HYPERV["t"] < 20:
        return _HYPERV["probe"]
    from shikari.lab.engines import ps_argv

    try:
        probe = parse_hyperv_probe(run(ps_argv(HYPERV_PROBE), timeout=20, check=False))
    except LabError:
        probe = {"installed": False, "running": False, "version": ""}
    _HYPERV.update(t=now, probe=probe)
    return probe


def _engine_status(key: str, spec: Dict) -> Dict:
    host_os, host_arch = os_name(), arch()
    requires = spec.get("requires") or {}
    supported = (requires.get("os", host_os) == host_os and requires.get("arch", host_arch) == host_arch)
    present = which(spec["probe"][0]) is not None
    version = ""
    # hyperv: powershell is on every Windows, so "installed" is the Hyper-V module, not the command
    hv = _hyperv_probe() if key == "hyperv" and present and supported else None
    if hv is not None:
        present, version = hv["installed"], hv["version"]
    elif present:
        if key == "utm":
            version = _utm_version()
        else:
            try:
                version = first_line(run(spec["probe"], timeout=15, check=False))
            except Exception:
                version = ""
    # docker: OrbStack reports its own daemon, so "running" means the daemon answers.
    # utm: "running" means utmctl answers (app open + Automation granted), checked with a timeout.
    if key == "docker":
        running = present and run_ok(["docker", "info", "--format", "{{.ServerVersion}}"])
    elif key == "utm":
        running = present and _utm_ready()
    elif key == "hyperv":
        running = bool(hv and hv["running"])
    elif key == "libvirt":
        # virsh itself always runs; the daemon answering this account is what matters
        from shikari.lab.engines import virsh_argv

        running = supported and present and run_ok(virsh_argv("list", "--all", "--name"))
    else:
        running = present and run_ok(spec["probe"])
    return {
        "key": key, "name": spec["name"], "runs": spec["runs"], "blurb": spec.get("blurb", ""),
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


def engine_supported(key: str) -> bool:
    """Whether this host's OS and CPU can run the engine at all — no probe, so it's free to ask."""
    spec = ENGINES.get(key)
    if not spec:
        return False
    requires = spec.get("requires") or {}
    return requires.get("os", os_name()) == os_name() and requires.get("arch", arch()) == arch()


def engine_ready(key: str) -> bool:
    spec = ENGINES.get(key)
    return bool(spec) and _engine_status(key, spec)["running"]
