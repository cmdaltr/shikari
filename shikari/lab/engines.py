"""
The engines Shikari drives on the machine it runs on, behind one interface
(create/start/stop/snapshot/revert/delete/status/logs/exec):

  docker   Linux containers. A snapshot is a committed image; revert recreates the
           container from it. Works wherever the docker command does.
  tart     macOS and Linux VMs on Apple Silicon. A snapshot is a clone; revert deletes the
           VM and clones the snapshot back. `tart run` holds the VM open, so start spawns it.
  utm      QEMU VMs on macOS through utmctl; you build the VM in UTM, Shikari drives it.
  hyperv   Hyper-V VMs on a Windows host, through PowerShell. Snapshots are Standard checkpoints;
           exec is PowerShell Direct for a Windows guest, SSH over the Default Switch for Linux.
  libvirt  KVM/QEMU VMs on a Linux host, through virsh and virt-install. Snapshots are internal
           qcow2 snapshots; exec is the QEMU guest agent.

The command parsing and building (parse_docker_ps, parse_tart_list, parse_hyperv_vms,
parse_virsh_list, hyperv_create_script, virt_install_argv…) is pure, so it's tested without any
of them installed. Names are validated by the caller (shikari.lab.machines) before they reach here.
"""

import json
import os
import re
import time
from typing import Dict, List

from shikari.lab.runner import LabError, run, run_ok, spawn

LABEL = "shikari.lab=1"       # marks the containers Shikari made
SNAP_TAG = "shikari-snap"     # docker: snapshot images are shikari-snap/<name>:<snap>
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

    def push_file(self, name: str, local_path: str, remote_path: str):
        run(["docker", "cp", local_path, f"{name}:{remote_path}"], timeout=120)

    def pull_dir(self, name: str, remote_dir: str, local_parent: str):
        run(["docker", "cp", f"{name}:{remote_dir}", local_parent], timeout=600)


class Tart:
    key = "tart"

    def list(self) -> List[Dict]:
        return parse_tart_list(run(["tart", "list", "--format", "json"]))

    def create(self, name: str, image: str):
        # Pulls the image if it's remote; a macOS base is ~30 GB, so allow a slow link (2h), not 30m.
        run(["tart", "clone", image, name], timeout=7200)

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

    def push_file(self, name: str, local_path: str, remote_path: str, windows: bool = False):
        # Tart has no cp; stream the file in over the guest agent (the script is text)
        with open(local_path, encoding="utf-8") as fh:
            text = fh.read()
        if windows:
            run(["tart", "exec", name, "powershell", "-NoProfile", "-Command",
                 f"[IO.File]::WriteAllText('{remote_path}', [Console]::In.ReadToEnd())"],
                timeout=120, input_text=text)
        else:
            run(["tart", "exec", name, "bash", "-lc", f"cat > {remote_path}"], timeout=120, input_text=text)

    def pull_dir(self, name: str, remote_dir: str, local_parent: str, windows: bool = False):
        import base64
        import os
        import tarfile

        parent, base = remote_dir.rsplit("/", 1) if "/" in remote_dir else (".", remote_dir)
        if windows:
            parent, base = remote_dir.replace("/", "\\").rsplit("\\", 1)
            b64 = run(["tart", "exec", name, "powershell", "-NoProfile", "-Command",
                       f"$t=[IO.Path]::GetTempFileName(); tar -czf $t -C '{parent}' '{base}'; "
                       "[Convert]::ToBase64String([IO.File]::ReadAllBytes($t))"], timeout=600)
        else:
            b64 = run(["tart", "exec", name, "bash", "-lc",
                       f"tar czf - -C {parent} {base} | base64"], timeout=600)
        data = base64.b64decode("".join(b64.split()))
        tmp = os.path.join(local_parent, f".{base}.tgz")
        os.makedirs(local_parent, exist_ok=True)
        with open(tmp, "wb") as fh:
            fh.write(data)
        with tarfile.open(tmp) as tf:
            tf.extractall(local_parent, filter="data")
        os.remove(tmp)


class _ExecFiles:
    """File transfer for an engine whose only way in is exec: base64 over stdin in, a base64'd
    tarball over stdout out. UTM, Hyper-V and libvirt use it; Docker and Tart have their own."""

    def push_file(self, name: str, local_path: str, remote_path: str, windows: bool = False):
        import base64

        with open(local_path, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode()
        if windows:
            ps = ("$b=[Console]::In.ReadToEnd(); "
                  f"[IO.File]::WriteAllBytes('{remote_path}', [Convert]::FromBase64String($b))")
            self.exec(name, ["powershell", "-NoProfile", "-Command", ps], timeout=300, input_text=b64)
        else:
            self.exec(name, ["bash", "-lc", f"base64 -d > '{remote_path}'"], timeout=300, input_text=b64)

    def pull_dir(self, name: str, remote_dir: str, local_parent: str, windows: bool = False):
        import base64
        import os
        import tarfile

        if windows:
            parent, base = remote_dir.replace("/", "\\").rsplit("\\", 1)
            ps = (f"$t=[IO.Path]::GetTempFileName(); tar -czf $t -C '{parent}' '{base}'; "
                  "[Convert]::ToBase64String([IO.File]::ReadAllBytes($t))")
            b64 = self.exec(name, ["powershell", "-NoProfile", "-Command", ps], timeout=600)
        else:
            parent, base = remote_dir.rsplit("/", 1) if "/" in remote_dir else (".", remote_dir)
            b64 = self.exec(name, ["bash", "-lc", f"tar czf - -C {parent} {base} | base64"], timeout=600)
        data = base64.b64decode("".join(b64.split()))
        os.makedirs(local_parent, exist_ok=True)
        tmp = os.path.join(local_parent, f".{base}.tgz")
        with open(tmp, "wb") as fh:
            fh.write(data)
        with tarfile.open(tmp) as tf:
            tf.extractall(local_parent, filter="data")
        os.remove(tmp)


_utm_quiet = False


def utmctl(*args: str, timeout: int = 120, check: bool = True, input_text=None) -> str:
    """utmctl, with UTM kept out of the Dock. utmctl launches the UTM app to do anything, which puts it
    in the Dock beside Shikari; UTM's own Hide dock icon setting moves it to the menu bar. Shikari turns
    it on once, and only when it was never set, so unticking it in UTM sticks."""
    global _utm_quiet
    if not _utm_quiet:
        _utm_quiet = True
        if not run_ok(["defaults", "read", "com.utmapp.UTM", "HideDockIcon"]):
            run(["defaults", "write", "com.utmapp.UTM", "HideDockIcon", "-bool", "true"], check=False)
    return run(["utmctl", *args], timeout=timeout, check=check, input_text=input_text)


_UTM_UUID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")


def parse_utm_list(out: str) -> List[Dict]:
    """`utmctl list`: a table of UUID, status and name. The header and blank lines are skipped;
    a UTM VM is 'started' when running. The name (space-free, by our convention) is the id we use."""
    machines = []
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0].lower() == "uuid":
            continue
        uuid, status = parts[0], parts[1].lower()
        name = " ".join(parts[2:]) if len(parts) > 2 else uuid
        machines.append({"engine": "utm", "name": name, "uuid": uuid, "kind": "vm", "image": "", "os": "",
                        "state": "running" if status in ("started", "running") else "stopped",
                        "detail": status})
    return machines


class UTM(_ExecFiles):
    """UTM/QEMU VMs on macOS, driven through utmctl. Shikari can't create a VM (utmctl has no
    create-from-image) — you build it in the UTM app once — but it starts, snapshots, restores,
    provisions and records whatever UTM holds. Snapshots are QEMU saved states (fast); exec and
    base64 move files, so no dependence on utmctl's undocumented file push/pull."""

    key = "utm"

    def list(self) -> List[Dict]:
        return parse_utm_list(utmctl("list", "--hide", timeout=30))

    def create(self, name: str, image: str):
        raise LabError("Build this VM in UTM first",
                       "utmctl can't create a VM from an image. Make it in the UTM app "
                       "(New → Virtualize or Emulate), name it without spaces, and it appears "
                       "here for Shikari to manage.")

    def start(self, name: str):
        utmctl("start", "--hide", name, timeout=180)

    def stop(self, name: str):
        utmctl("stop", "--hide", name, timeout=120, check=False)

    def snapshot(self, name: str, snap: str):
        utmctl("snapshot", "create", name, "--name", snap, timeout=600)

    def revert(self, name: str, snap: str):
        utmctl("snapshot", "restore", name, "--snapshot", snap, timeout=600)

    def clone(self, name: str, new_name: str):
        # Copies the disk, so it's slow for a Windows VM — run it as a job. UTM registers the
        # clone itself; it inherits the source's drives, snapshots and guest tools.
        utmctl("clone", name, "--name", new_name, timeout=1800)

    def delete(self, name: str):
        utmctl("delete", "--hide", name, timeout=60, check=False)

    def status(self, name: str) -> Dict:
        found = [m for m in self.list() if m["name"] == name]
        if not found:
            raise LabError("No such machine", name)
        return found[0]

    def logs(self, name: str, tail: int) -> str:
        ip = utmctl("ip-address", "--hide", name, check=False).strip()
        return (f"UTM keeps no console log. The VM's address is {ip}.\n" if ip
                else "UTM keeps no console log, and the VM has no address yet "
                     "(it may be booting, or missing the guest agent / SPICE tools).\n")

    def exec(self, name: str, argv: List[str], timeout: int, input_text=None) -> str:
        args = ["exec", "--hide", name]
        if input_text is not None:
            args.append("--input")
        args += ["--cmd", *argv]          # --cmd is variadic, so it has to come last
        return utmctl(*args, timeout=timeout, input_text=input_text)


# --- Shared by the Hyper-V and libvirt engines -------------------------------------------

def _lab_path(*parts: str) -> str:
    """An absolute path under Shikari's lab folder. Absolute because Hyper-V's VMMS and libvirt
    resolve paths in their own process, not Shikari's working directory."""
    from shikari.lab.registry import LAB_DIR

    return os.path.abspath(os.path.join(LAB_DIR, *parts))


def _fetch(url: str, dest: str) -> str:
    """Download a cloud image once into the lab's image cache. Not a shell-out, so not run()."""
    import urllib.request

    if os.path.isfile(dest):
        return dest
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    part = dest + ".part"
    try:
        with urllib.request.urlopen(url, timeout=60) as resp, open(part, "wb") as fh:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                fh.write(chunk)
    except OSError as e:
        raise LabError("Couldn't download the image", f"{url}: {e}")
    os.replace(part, dest)
    return dest


def _local_image(image: str) -> str:
    """A local path for `image`: a URL is downloaded into the cache, a path is expanded."""
    if re.match(r"^https?://", image or ""):
        return _fetch(image, _lab_path("images", os.path.basename(image.split("?", 1)[0])))
    path = os.path.abspath(os.path.expanduser(image or ""))
    if not os.path.isfile(path):
        raise LabError("No such image", path)
    return path


def ssh_key() -> str:
    """Shikari's own lab SSH key (created on first use); returns the public key. A Linux guest
    on Hyper-V is reached over SSH with it, and libvirt guests get it too, as a way in."""
    key = _lab_path("ssh", "id_ed25519")
    if not os.path.isfile(key):
        os.makedirs(os.path.dirname(key), exist_ok=True)
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "shikari-lab", "-f", key], timeout=30)
        if os.name == "nt":
            # Windows OpenSSH refuses a key other accounts can read, and C:\ grants Authenticated Users
            run(["icacls", key, "/inheritance:r", "/grant:r", f"{os.environ.get('USERNAME', '')}:F"],
                check=False)
    with open(key + ".pub", encoding="utf-8") as fh:
        return fh.read().strip()


def ssh_argv(user: str, host: str, key: str, argv: List[str]) -> List[str]:
    """ssh running argv in the guest. The remote side gets one shell string, so each element is
    quoted. Host keys aren't kept: these are disposable VMs on a host-only NAT whose addresses
    are recycled, so a remembered key would only ever be wrong."""
    import shlex

    return ["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", f"UserKnownHostsFile={os.devnull}", "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
            f"{user}@{host}", "--", shlex.join(argv)]


def _first_ipv4(addresses) -> str:
    for a in addresses or []:
        a = str(a).split("/", 1)[0]
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", a) and not a.startswith("169.254."):
            return a
    return ""


# --- Hyper-V (Windows hosts) -------------------------------------------------------------

HYPERV_SWITCH = os.environ.get("SHIKARI_HYPERV_SWITCH", "Default Switch")
HYPERV_NOTE = "shikari.lab=1"      # Set-VM -Notes on the VMs Shikari made
NO_SNAPSHOT = "SHIKARI_NO_SNAPSHOT"  # what the revert script prints when the checkpoint is missing

# Get-VM's State when ConvertTo-Json writes the enum as a number (Windows PowerShell 5.1 does)
_HYPERV_STATES = {2: "Running", 3: "Off", 4: "Stopping", 6: "Saved", 9: "Paused", 10: "Starting",
                  11: "Reset", 32773: "Saving", 32776: "Pausing", 32777: "Resuming"}


def psq(value: str) -> str:
    """A PowerShell single-quoted string literal: the only escape is a doubled quote."""
    return "'" + str(value).replace("'", "''") + "'"


def ps_argv(script: str) -> List[str]:
    """Windows PowerShell running `script`. -EncodedCommand (UTF-16LE base64) means nothing in
    the script is re-parsed by the Windows command line, whose quoting PowerShell reads its own way."""
    import base64

    body = ("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script)
    return ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-EncodedCommand", base64.b64encode(body.encode("utf-16-le")).decode()]


def _json_rows(out: str) -> List[Dict]:
    """ConvertTo-Json output as a list: one object comes back bare, none comes back empty."""
    try:
        data = json.loads(out or "[]")
    except ValueError:
        return []
    if isinstance(data, dict):
        data = [data]
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def parse_hyperv_vms(out: str) -> List[Dict]:
    """The Get-VM listing (HyperV.list's script): Name, State, Uptime, Notes per VM."""
    machines = []
    for row in _json_rows(out):
        name = row.get("Name") or ""
        if not name:
            continue
        state = row.get("State")
        state = _HYPERV_STATES.get(state, str(state)) if isinstance(state, int) else str(state or "")
        uptime = str(row.get("Uptime") or "")
        machines.append({"engine": "hyperv", "name": name, "kind": "vm", "image": "", "os": "",
                        "state": "running" if state.lower() == "running" else "stopped",
                        "shikari_made": HYPERV_NOTE in str(row.get("Notes") or ""),
                        "detail": state.lower() + (f", up {uptime.split('.')[0]}" if state.lower() == "running" and uptime else "")})
    return machines


def parse_hyperv_address(out: str) -> str:
    """The guest's IPv4 from HyperV.address's script: what the guest's KVP daemon reported, else
    the host's neighbour entry for the VM's MAC (the Default Switch NAT has seen it talk)."""
    rows = _json_rows(out)
    if not rows:
        return ""
    row = rows[0]
    return _first_ipv4(row.get("ips")) or _first_ipv4(row.get("neighbours"))


def hyperv_create_script(name: str, vm_dir: str, base: str = "", iso: str = "", seed: str = "",
                         linux: bool = True, memory_mb: int = 2048, cpus: int = 2,
                         disk_gb: int = 64, switch: str = HYPERV_SWITCH) -> str:
    """New-VM for a lab machine, everything in vm_dir. From `base`, a differencing disk over a
    read-only parent (instant, and the parent serves every machine made from it); from `iso`, a
    blank disk and the ISO as first boot device. Generation 2 (UEFI), except over a .vhd parent:
    Generation 2 boots only VHDX, and a .vhd (Microsoft's evaluation VHDs) is an MBR disk for
    Generation 1's BIOS. Checkpoints are Standard (memory included), so a revert lands on the
    running moment the snapshot was taken, as UTM's do."""
    gen = 1 if base.lower().endswith(".vhd") else 2
    disk = f"{vm_dir}\\{name}.{'vhd' if gen == 1 else 'vhdx'}"  # a differencing disk takes its parent's format
    lines = [f"New-Item -ItemType Directory -Force -Path {psq(vm_dir)} | Out-Null"]
    if base:
        lines.append(f"New-VHD -Path {psq(disk)} -ParentPath {psq(base)} -Differencing | Out-Null")
    else:
        lines.append(f"New-VHD -Path {psq(disk)} -SizeBytes {int(disk_gb)}GB -Dynamic | Out-Null")
    lines += [
        f"New-VM -Name {psq(name)} -Generation {gen} -MemoryStartupBytes {int(memory_mb)}MB "
        f"-Path {psq(vm_dir)} -VHDPath {psq(disk)} -SwitchName {psq(switch)} | Out-Null",
        f"Set-VMProcessor -VMName {psq(name)} -Count {int(cpus)}",
        f"Set-VM -Name {psq(name)} -Notes {psq(HYPERV_NOTE)} -CheckpointType Standard "
        "-AutomaticCheckpointsEnabled $false -AutomaticStopAction TurnOff",
        f"Enable-VMIntegrationService -VMName {psq(name)} -Name 'Guest Service Interface'",
    ]
    if gen == 2:
        # Linux boots under the third-party UEFI CA; Windows keeps the default Microsoft template
        lines.append(f"Set-VMFirmware -VMName {psq(name)} -SecureBootTemplate MicrosoftUEFICertificateAuthority"
                     if linux else f"Set-VMFirmware -VMName {psq(name)} -EnableSecureBoot On")
    if seed:
        lines.append(f"Add-VMDvdDrive -VMName {psq(name)} -Path {psq(seed)}")
    if iso:
        lines.append(f"$dvd = Add-VMDvdDrive -VMName {psq(name)} -Path {psq(iso)} -Passthru; "
                     f"Set-VMFirmware -VMName {psq(name)} -FirstBootDevice $dvd")
        if not linux:  # Windows 11 setup wants a TPM
            lines.append(f"Set-VMKeyProtector -VMName {psq(name)} -NewLocalKeyProtector; "
                         f"Enable-VMTPM -VMName {psq(name)}")
    return "; ".join(lines)


def hyperv_direct_script(name: str, user: str, argv: List[str], has_input: bool) -> str:
    """PowerShell Direct: run argv in a Windows guest over the VM bus, no network needed. The
    password and any stdin come in on stdin (password first line), never on a command line, and
    argv travels as base64, so nothing in it is parsed as PowerShell. The guest's exit code
    comes back as this script's. One limit is the guest's: Windows PowerShell 5.1 drops double
    quotes inside an argument it hands a native program, so guest commands quote with single ones
    (Shikari's provisioning, recorder and CALDERA scripts all do)."""
    import base64

    # One base64 literal per element, decoded into an @() array: unlike ConvertFrom-Json, that gives
    # the same array in Windows PowerShell 5.1 and 7 whatever the count (one element included)
    elements = ",".join(psq(base64.b64encode(str(a).encode("utf-8")).decode()) for a in argv)
    return (
        "$all = [Console]::In.ReadToEnd(); $nl = $all.IndexOf([char]10); "
        "if ($nl -lt 0) { $pw = $all; $in = '' } else { $pw = $all.Substring(0, $nl).TrimEnd([char]13); "
        "$in = $all.Substring($nl + 1) }; "
        f"$cred = New-Object System.Management.Automation.PSCredential({psq(user)}, "
        "(ConvertTo-SecureString $pw -AsPlainText -Force)); "
        f"$argv = @(@({elements}) | ForEach-Object {{ [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_)) }}); "
        f"$r = Invoke-Command -VMName {psq(name)} -Credential $cred "
        f"-ArgumentList $argv, $in, ${'true' if has_input else 'false'} -ScriptBlock {{ "
        "param($argv, $stdin, $hasInput) $exe = $argv[0]; $rest = @($argv | Select-Object -Skip 1); "
        "$global:LASTEXITCODE = 0; "
        "if ($hasInput) { $lines = @($stdin | & $exe @rest 2>&1 | ForEach-Object { \"$_\" }) } "
        "else { $lines = @(& $exe @rest 2>&1 | ForEach-Object { \"$_\" }) }; "
        "[pscustomobject]@{ out = ($lines -join \"`n\"); code = [int]$LASTEXITCODE } }; "
        "[Console]::Out.Write($r.out); exit $r.code")


class HyperV(_ExecFiles):
    """Hyper-V on a Windows host (Pro, Enterprise or Education), driven through PowerShell's
    Hyper-V module. Shikari needs to run elevated or as a member of Hyper-V Administrators.

    Running commands in the guest: PowerShell Direct (Invoke-Command -VMName) for Windows guests,
    which needs the guest's local administrator login (set with Set OS) but no network; SSH over
    the Default Switch for Linux guests, with Shikari's key (put in by the cloud-init seed on a
    machine Shikari made, or your own key and user for one you built)."""

    key = "hyperv"
    from_image = True  # create takes a disk or ISO path, not only a template

    def _ps(self, script: str, timeout: int = 120, check: bool = True, input_text=None) -> str:
        return run(ps_argv(script), timeout=timeout, check=check, input_text=input_text)

    def _dir(self, name: str) -> str:
        root = os.environ.get("SHIKARI_HYPERV_DIR")
        return os.path.join(os.path.abspath(root), name) if root else _lab_path("hyperv", name)

    def list(self) -> List[Dict]:
        return parse_hyperv_vms(self._ps(
            "$v = @(Get-VM | ForEach-Object { [pscustomobject]@{ Name = $_.Name; State = [string]$_.State; "
            "Uptime = [string]$_.Uptime; Notes = $_.Notes } }); ConvertTo-Json -InputObject $v -Compress",
            timeout=60))

    def create(self, name: str, image: str, os_name: str = "linux", memory_mb: int = 2048, cpus: int = 2, **_):
        """From a .vhdx/.vhd base disk, a .qcow2/.img cloud image (converted once with qemu-img),
        or an .iso to install from. A Linux machine from a disk gets the cloud-init seed."""
        path = _local_image(image)
        linux = os_name != "windows"
        low = path.lower()
        vm_dir = self._dir(name)
        base = iso = seed = ""
        if low.endswith(".iso"):
            iso = path
        elif low.endswith((".vhdx", ".vhd")):
            base = path
        elif low.endswith((".img", ".qcow2")):
            base = _lab_path("images", os.path.splitext(os.path.basename(path))[0] + ".vhdx")
            os.makedirs(os.path.dirname(base), exist_ok=True)
            if not os.path.isfile(base):
                run(["qemu-img", "convert", "-O", "vhdx", "-o", "subformat=dynamic", path, base], timeout=1800)
        else:
            raise LabError("Hyper-V can't use this image", f"{path}: give a .vhdx, .vhd, .qcow2/.img or .iso")
        if base and linux:
            from shikari.lab.seed import nocloud_iso

            os.makedirs(vm_dir, exist_ok=True)
            seed = os.path.join(vm_dir, "seed.iso")
            with open(seed, "wb") as fh:
                fh.write(nocloud_iso(name, ssh_key(), engine="hyperv"))
        self._ps(hyperv_create_script(name, vm_dir, base=base, iso=iso, seed=seed, linux=linux,
                                      memory_mb=memory_mb, cpus=cpus), timeout=600)

    def start(self, name: str):
        self._ps(f"Start-VM -Name {psq(name)}", timeout=180)

    def stop(self, name: str):
        # A clean shutdown through the guest's integration services, else pull the plug
        self._ps(f"try {{ Stop-VM -Name {psq(name)} -Force -ErrorAction Stop }} "
                 f"catch {{ Stop-VM -Name {psq(name)} -TurnOff -Force }}", timeout=180, check=False)

    def snapshot(self, name: str, snap: str):
        # Hyper-V allows two checkpoints of one name; re-taking one replaces it, as docker commit does
        self._ps(f"Get-VMCheckpoint -VMName {psq(name)} -Name {psq(snap)} -ErrorAction SilentlyContinue "
                 f"| Remove-VMCheckpoint; Checkpoint-VM -Name {psq(name)} -SnapshotName {psq(snap)}", timeout=600)

    def revert(self, name: str, snap: str):
        try:
            self._ps(f"$c = Get-VMCheckpoint -VMName {psq(name)} -Name {psq(snap)} -ErrorAction SilentlyContinue; "
                     f"if (-not $c) {{ [Console]::Error.Write('{NO_SNAPSHOT}'); exit 3 }}; "
                     "Restore-VMCheckpoint -VMSnapshot $c -Confirm:$false; "
                     # a checkpoint of a running VM restores to Saved; resume it, so revert lands running
                     f"if ((Get-VM -Name {psq(name)}).State -eq 'Saved') {{ Start-VM -Name {psq(name)} }}",
                     timeout=600)
        except LabError as e:
            if NO_SNAPSHOT in (e.detail or ""):
                raise LabError("No such snapshot", f"{name} has no snapshot {snap}")
            raise

    def delete(self, name: str):
        # Shikari's own machines live in one folder each (config, disk, checkpoints, seed), so the
        # folder goes too. A VM you built elsewhere loses only its Hyper-V registration: its disks stay.
        self._ps(f"$vm = Get-VM -Name {psq(name)} -ErrorAction SilentlyContinue; "
                 "if ($vm) { Stop-VM -VM $vm -TurnOff -Force -ErrorAction SilentlyContinue; Remove-VM -VM $vm -Force }; "
                 f"if (Test-Path {psq(self._dir(name))}) {{ Remove-Item -Recurse -Force {psq(self._dir(name))} }}",
                 timeout=300, check=False)

    def status(self, name: str) -> Dict:
        found = [m for m in self.list() if m["name"] == name]
        if not found:
            raise LabError("No such machine", name)
        return found[0]

    def address(self, name: str) -> str:
        return parse_hyperv_address(self._ps(
            f"$a = Get-VMNetworkAdapter -VMName {psq(name)} | Select-Object -First 1; "
            "$mac = ($a.MacAddress -replace '[^0-9A-Fa-f]', '').ToUpper(); "
            "$nb = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { "
            "($_.LinkLayerAddress -replace '[^0-9A-Fa-f]', '').ToUpper() -eq $mac -and $_.State -ne 'Unreachable' } "
            "| ForEach-Object { $_.IPAddress }); "
            "ConvertTo-Json -InputObject @{ ips = @($a.IPAddresses); neighbours = $nb; mac = $mac } -Compress",
            timeout=60, check=False))

    def logs(self, name: str, tail: int) -> str:
        ip = self.address(name)
        return (f"Hyper-V keeps no console log; open the VM in Hyper-V Manager (vmconnect) to see its screen. "
                f"Its address is {ip}.\n" if ip
                else "Hyper-V keeps no console log, and the VM has reported no address yet (it may be booting; "
                     "a Linux guest reports it through hv_kvp_daemon, from linux-cloud-tools).\n")

    def exec(self, name: str, argv: List[str], timeout: int, input_text=None) -> str:
        from shikari.lab.registry import get as known, get_access

        access = get_access("hyperv", name) or {}
        if ((known("hyperv", name) or {}).get("os")) == "windows":
            if not access.get("password"):
                raise LabError("Set the guest login first",
                               f"PowerShell Direct runs commands in {name} as one of its accounts. Give its "
                               "local administrator user and password under Set OS.")
            return self._ps(hyperv_direct_script(name, access.get("user") or "Administrator", argv,
                                                 input_text is not None),
                            timeout=timeout, input_text=access["password"] + "\n" + (input_text or ""))
        host = access.get("host") or self.address(name)
        if not host:
            raise LabError("The VM has no address yet",
                           f"{name} hasn't reported an IPv4 address on {HYPERV_SWITCH}. Give it a minute to "
                           "boot, or set its address under Set OS.")
        key = access.get("key") or _lab_path("ssh", "id_ed25519")
        if not access.get("key"):
            ssh_key()
        return run(ssh_argv(access.get("user") or "shikari", host, key, argv), timeout=timeout,
                   input_text=input_text)


# --- libvirt (Linux hosts, KVM/QEMU) -----------------------------------------------------

LIBVIRT_URI = os.environ.get("SHIKARI_LIBVIRT_URI", "qemu:///system")
LIBVIRT_POOL = os.environ.get("SHIKARI_LIBVIRT_POOL", "default")
LIBVIRT_NETWORK = os.environ.get("SHIKARI_LIBVIRT_NETWORK", "default")
AGENT_CHUNK = 48 * 1024  # a guest-file-write's payload; its base64 stays under Linux's 128 KB argument limit


def virsh_argv(*args: str) -> List[str]:
    return ["virsh", "-c", LIBVIRT_URI, *args]


def parse_virsh_list(out: str) -> List[Dict]:
    """`virsh list --all`: a table of Id, Name and State under a dashed rule."""
    machines, seen_rule = [], False
    for line in (out or "").splitlines():
        if not seen_rule:
            seen_rule = line.strip().startswith("---")
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        state = parts[2].strip().lower()
        machines.append({"engine": "libvirt", "name": parts[1], "kind": "vm", "image": "", "os": "",
                        "state": "running" if state == "running" else "stopped", "detail": state})
    return machines


def parse_domifaddr(out: str) -> List[str]:
    """`virsh domifaddr`: the IPv4 addresses, without their prefix length."""
    ips = []
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "ipv4":
            ip = _first_ipv4([parts[3]])
            if ip and not ip.startswith("127."):
                ips.append(ip)
    return ips


def parse_domdisplay(out: str):
    """`virsh domdisplay`: vnc://127.0.0.1:0 or spice://127.0.0.1:5901, as (host, port, kind). A VNC
    display number is an offset from 5900; SPICE gives the port itself."""
    m = re.match(r"^\s*(vnc|spice)://([^:/\s]+):(\d+)", out or "")
    if not m:
        return None
    kind, host, n = m.group(1), m.group(2), int(m.group(3))
    port = 5900 + n if kind == "vnc" and n < 5900 else n
    return ("127.0.0.1" if host == "localhost" else host), port, kind


def parse_domblklist(out: str) -> List[Dict]:
    """`virsh domblklist --details`: Type, Device, Target, Source per disk."""
    disks, seen_rule = [], False
    for line in (out or "").splitlines():
        if not seen_rule:
            seen_rule = line.strip().startswith("---")
            continue
        parts = line.split(None, 3)
        if len(parts) >= 3:
            disks.append({"type": parts[0], "device": parts[1], "target": parts[2],
                          "source": parts[3].strip() if len(parts) > 3 else "-"})
    return disks


def agent_command(execute: str, **arguments) -> str:
    """One QEMU guest agent command, as the JSON virsh qemu-agent-command takes. Keyword names
    use _ for the protocol's - (capture_output -> capture-output)."""
    cmd: Dict = {"execute": execute}
    if arguments:
        cmd["arguments"] = {k.replace("_", "-"): v for k, v in arguments.items()}
    return json.dumps(cmd, separators=(",", ":"))


def guest_exec_command(argv: List[str], input_text=None) -> str:
    import base64

    args: Dict = {"path": argv[0], "arg": list(argv[1:]), "capture_output": True}
    if input_text is not None:
        args["input_data"] = base64.b64encode(input_text.encode("utf-8")).decode()
    return agent_command("guest-exec", **args)


def parse_agent_return(out: str):
    """The `return` member of a guest agent reply."""
    try:
        reply = json.loads(out or "{}")
    except ValueError:
        raise LabError("The guest agent gave an unreadable reply", (out or "")[:500])
    if not isinstance(reply, dict) or "return" not in reply:
        raise LabError("The guest agent refused the command", (out or "")[:500])
    return reply["return"]


def parse_exec_status(out: str) -> Dict:
    """guest-exec-status: whether it has exited, its exit code, and its decoded output."""
    import base64

    ret = parse_agent_return(out) or {}

    def text(key):
        raw = ret.get(key) or ""
        return base64.b64decode(raw).decode("utf-8", "replace") if raw else ""

    return {"exited": bool(ret.get("exited")), "code": ret.get("exitcode", 0 if ret.get("exited") else None),
            "out": text("out-data"), "err": text("err-data"),
            "truncated": bool(ret.get("out-truncated") or ret.get("err-truncated"))}


def virt_install_argv(name: str, disk: str = "", iso: str = "", seed: str = "", osinfo: str = "",
                      windows: bool = False, memory_mb: int = 2048, cpus: int = 2, disk_gb: int = 40,
                      pool: str = LIBVIRT_POOL, network: str = LIBVIRT_NETWORK) -> List[str]:
    """virt-install for a lab machine: imports `disk` (a pool volume, the cloud-image overlay) or
    installs from `iso` onto a new disk. BIOS firmware, so internal snapshots (qcow2, memory
    included) work on any libvirt. VNC on loopback for the Desktop panel, a serial console for the
    Console, and the guest agent's channel, which is how Shikari runs commands in it."""
    bus = "sata" if windows else "virtio"
    argv = ["virt-install", "--connect", LIBVIRT_URI, "--name", name, "--memory", str(int(memory_mb)),
            "--vcpus", str(int(cpus)), "--osinfo", osinfo or "detect=on,require=off",
            "--network", f"network={network},model={'e1000e' if windows else 'virtio'}",
            "--graphics", "vnc,listen=127.0.0.1", "--serial", "pty", "--console", "pty,target_type=serial",
            "--channel", "unix,target_type=virtio,name=org.qemu.guest_agent.0", "--noautoconsole"]
    if iso:
        argv += ["--cdrom", iso, "--disk", f"pool={pool},size={int(disk_gb)},format=qcow2,bus={bus}"]
    else:
        argv += ["--import", "--disk", f"vol={pool}/{disk},bus={bus}"]
    if seed:
        argv += ["--disk", f"vol={pool}/{seed},device=cdrom"]
    return argv


def _vol_name(path: str) -> str:
    return "shikari-base-" + re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(path))


class Libvirt(_ExecFiles):
    """KVM/QEMU VMs on a Linux host, through libvirt (virsh and virt-install). The Shikari account
    needs the libvirt group (qemu:///system); SHIKARI_LIBVIRT_URI picks another connection.

    Running commands in the guest: the QEMU guest agent (guest-exec), as UTM's utmctl exec and
    tart exec do — no network, no SSH keys or addresses, and it works on a guest whose network is
    cut off, which a lab VM detonating atomics often should be. A machine Shikari made gets the
    agent from its cloud-init seed; one you built needs qemu-guest-agent installed (virtio-win's
    guest tools on Windows)."""

    key = "libvirt"
    from_image = True

    def _virsh(self, *args: str, timeout: int = 120, check: bool = True) -> str:
        return run(virsh_argv(*args), timeout=timeout, check=check)

    def list(self) -> List[Dict]:
        return parse_virsh_list(self._virsh("list", "--all", timeout=30))

    def _upload(self, local: str, vol: str):
        """Put a file into the storage pool, where qemu can read it whatever the file's own
        permissions (a home directory is usually closed to the libvirt-qemu user)."""
        if run_ok(virsh_argv("vol-info", "--pool", LIBVIRT_POOL, vol)):
            return
        self._virsh("vol-create-as", LIBVIRT_POOL, vol, str(os.path.getsize(local)), "--format", "raw")
        self._virsh("vol-upload", "--pool", LIBVIRT_POOL, vol, local, timeout=3600)
        self._virsh("pool-refresh", LIBVIRT_POOL, check=False)

    def create(self, name: str, image: str, os_name: str = "linux", osinfo: str = "",
               memory_mb: int = 2048, cpus: int = 2, disk_gb: int = 20, **_):
        """From a qcow2 cloud image (URL or path): an overlay volume on a shared base, plus the
        cloud-init seed. From an .iso: a blank disk to install onto, over the Desktop panel."""
        path = _local_image(image)
        windows = os_name == "windows"
        if path.lower().endswith(".iso"):
            vol = os.path.basename(path)
            self._upload(path, vol)
            pool_dir = self._pool_path()
            run(virt_install_argv(name, iso=os.path.join(pool_dir, vol) if pool_dir else path, osinfo=osinfo,
                                  windows=windows, memory_mb=memory_mb, cpus=cpus), timeout=600)
            return
        import tempfile

        from shikari.lab.seed import nocloud_iso

        base = _vol_name(path)
        self._upload(path, base)
        self._virsh("vol-create-as", LIBVIRT_POOL, f"{name}.qcow2", f"{int(disk_gb)}G", "--format", "qcow2",
                    "--backing-vol", base, "--backing-vol-format", "qcow2")
        seed = f"{name}-seed.iso"
        with tempfile.NamedTemporaryFile(suffix=".iso", delete=False) as fh:
            fh.write(nocloud_iso(name, ssh_key(), engine="libvirt"))
        try:
            self._virsh("vol-delete", "--pool", LIBVIRT_POOL, seed, check=False)  # a leftover from a failed create
            self._upload(fh.name, seed)
        finally:
            os.unlink(fh.name)
        run(virt_install_argv(name, disk=f"{name}.qcow2", seed=seed, osinfo=osinfo, windows=windows,
                              memory_mb=memory_mb, cpus=cpus), timeout=600)

    def _pool_path(self) -> str:
        out = self._virsh("pool-dumpxml", LIBVIRT_POOL, check=False)
        m = re.search(r"<path>([^<]+)</path>", out or "")
        return m.group(1) if m else ""

    def start(self, name: str):
        self._virsh("start", name, timeout=120)

    def stop(self, name: str):
        # ACPI shutdown first; a guest that ignores it (or has no ACPI daemon) is powered off after a minute
        self._virsh("shutdown", name, check=False)
        for _ in range(30):
            if self._virsh("domstate", name, check=False).strip() != "running":
                return
            time.sleep(2)
        self._virsh("destroy", name, check=False)

    def snapshot(self, name: str, snap: str):
        # Re-taking a snapshot replaces it, as docker commit does with a tag
        self._virsh("snapshot-delete", "--domain", name, "--snapshotname", snap, check=False)
        self._virsh("snapshot-create-as", "--domain", name, "--name", snap, "--atomic", timeout=600)

    def revert(self, name: str, snap: str):
        if not run_ok(virsh_argv("snapshot-info", "--domain", name, "--snapshotname", snap)):
            raise LabError("No such snapshot", f"{name} has no snapshot {snap}")
        self._virsh("snapshot-revert", "--domain", name, "--snapshotname", snap, timeout=600)

    def delete(self, name: str):
        self._virsh("destroy", name, check=False)
        # Eject the CD-ROMs first: --remove-all-storage would otherwise delete an install ISO that
        # sits in the pool, which other machines may still use. The seed is this machine's own.
        for disk in parse_domblklist(self._virsh("domblklist", name, "--details", check=False)):
            if disk["device"] == "cdrom" and disk["source"] not in ("", "-"):
                self._virsh("change-media", name, disk["target"], "--eject", "--config", check=False)
        self._virsh("undefine", name, "--remove-all-storage", "--snapshots-metadata", "--nvram",
                    timeout=300, check=False)
        self._virsh("vol-delete", "--pool", LIBVIRT_POOL, f"{name}-seed.iso", check=False)

    def status(self, name: str) -> Dict:
        found = [m for m in self.list() if m["name"] == name]
        if not found:
            raise LabError("No such machine", name)
        return found[0]

    def addresses(self, name: str) -> List[str]:
        # The agent knows the guest's own view; the DHCP lease answers before the agent is up
        for source in ("agent", "lease"):
            ips = parse_domifaddr(self._virsh("domifaddr", name, "--source", source, timeout=30, check=False))
            if ips:
                return ips
        return []

    def desktop(self, name: str):
        """The VM's live VNC endpoint. The port is allocated at each start, so it's asked of libvirt
        rather than stored; it comes from virsh, never from the client."""
        return parse_domdisplay(self._virsh("domdisplay", name, timeout=30, check=False))

    def logs(self, name: str, tail: int) -> str:
        ips = self.addresses(name)
        display = self._virsh("domdisplay", name, timeout=30, check=False).strip()
        return ((f"Address: {', '.join(ips)}\n" if ips else "No address yet (the VM may still be booting).\n")
                + (f"Display: {display}\n" if display else "")
                + "QEMU's own log is /var/log/libvirt/qemu/" + name + ".log on the host (root only).\n")

    def _agent(self, name: str, command: str, timeout: int = 30):
        return parse_agent_return(self._virsh("qemu-agent-command", name, "--timeout", str(timeout), command,
                                              timeout=timeout + 15))

    def exec(self, name: str, argv: List[str], timeout: int, input_text=None) -> str:
        try:
            pid = (self._agent(name, guest_exec_command(argv, input_text)) or {}).get("pid")
        except LabError as e:
            raise LabError("Couldn't run it in the VM",
                           "libvirt runs commands through the QEMU guest agent (qemu-guest-agent in the "
                           "guest). " + (e.detail or ""))
        deadline, wait = time.time() + timeout, 0.2
        while True:
            status = parse_exec_status(self._virsh(
                "qemu-agent-command", name, agent_command("guest-exec-status", pid=pid), timeout=45))
            if status["exited"]:
                break
            if time.time() > deadline:
                raise LabError(f"{argv[0]} timed out in the VM", f"did not finish within {timeout}s")
            time.sleep(wait)
            wait = min(wait * 2, 2.0)
        if status["code"]:
            raise LabError(f"{argv[0]} failed", (status["err"] or status["out"]).strip()[:2000])
        return status["out"]

    def push_file(self, name: str, local_path: str, remote_path: str, windows: bool = False):
        # guest-file-* writes straight to the path in chunks, so a file of any size fits the argument limit
        import base64

        handle = self._agent(name, agent_command("guest-file-open", path=remote_path, mode="wb"))
        try:
            with open(local_path, "rb") as fh:
                while True:
                    chunk = fh.read(AGENT_CHUNK)
                    if not chunk:
                        break
                    self._agent(name, agent_command("guest-file-write", handle=handle,
                                                    buf_b64=base64.b64encode(chunk).decode()), timeout=60)
        finally:
            self._agent(name, agent_command("guest-file-close", handle=handle))


def parse_tart_list_raw() -> List[str]:
    """Every local Tart VM name, snapshots included (delete sweeps a machine's snapshots)."""
    try:
        rows = json.loads(run(["tart", "list", "--format", "json"]))
    except (ValueError, LabError):
        return []
    return [r.get("Name", "") for r in rows if isinstance(r, dict) and r.get("Source") == "local"]


ENGINES = {"docker": Docker(), "tart": Tart(), "utm": UTM(), "hyperv": HyperV(), "libvirt": Libvirt()}


def engine_for(key: str):
    engine = ENGINES.get(key)
    if engine is None:
        raise LabError("Unknown engine", key)
    return engine
