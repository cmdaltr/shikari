"""
archer-cli caldera — provision and enrol CALDERA agents from the command line (the CLI half of the
#30 provisioning the web 'Add CALDERA agent' flow also exposes).

  archer-cli caldera provision linux [name] [--engine tart|docker] [--group G]
  archer-cli caldera provision macos [name]            # needs a cirruslabs base (Tart guest agent)
  archer-cli caldera enrol <tart|docker|utm> <name>    # enrol a machine Archer already manages
  archer-cli caldera list                              # managed machines, and which are agents

The disposable-lab bring-up (the server plus a couple of Linux agents) still lives in
scripts/telemetry/caldera-lab.sh; this is for adding individual, Archer-managed agents.
"""
import argparse
import subprocess
import sys

from archer.lab import caldera, registry
from archer.lab.runner import LabError


def _lan_ip() -> str:
    """The host's LAN IP on its default route — the address a VM reaches the server on."""
    try:
        route = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True).stdout
        dev = next((l.split(":", 1)[1].strip() for l in route.splitlines() if "interface:" in l), "")
        if dev:
            return subprocess.run(["ipconfig", "getifaddr", dev], capture_output=True, text=True).stdout.strip()
    except OSError:
        pass
    return ""


def _server(arg: str) -> str:
    """The CALDERA server URL: --server, then the configured settings, then the host's LAN IP."""
    url = arg or caldera.settings().get("url") or (f"http://{_lan_ip()}:8888" if _lan_ip() else "")
    if not url:
        raise SystemExit("No CALDERA server — pass --server http://host:8888 "
                         "(or set it in Profile → Emulation Tools, or the caldera block in bespoke/config.yaml)")
    return url.rstrip("/")


def _autoname(os_name: str) -> str:
    """A free machine name in the lab convention (cal-Ubuntu2404, cal-macOSSeq, …)."""
    from archer.lab.machines import all_host_names

    return caldera.suggested_name(os_name, all_host_names(), for_caldera=True)


def _provision(args) -> int:
    if args.os == "linux":
        template = "ubuntu-container" if args.engine == "docker" else "ubuntu-vm"
    else:
        template = "macos-vm"
    name = args.name or _autoname(args.os)
    group = args.group or caldera.GROUP_FOR[args.os]
    r = caldera.provision_for_caldera(template, name, group, _server(args.server))
    print(f"provisioned {r['name']} ({r['os']}/{r['engine']}) in group {group}")
    return 0


def _enrol(args) -> int:
    os_name = args.os or (registry.get(args.engine, args.name) or {}).get("os")
    if not os_name:
        raise SystemExit(f"Don't know the OS of {args.engine}/{args.name} — pass --os linux|macos|windows")
    group = args.group or caldera.GROUP_FOR.get(os_name, "disposable")
    caldera.enrol_agent(args.engine, args.name, os_name, group, _server(args.server))
    return 0


def _list(args) -> int:
    from archer.lab import machines

    # Rivendell's own VMs are excluded — this is Archer's lab.
    rows = [m for m in machines.listing(is_admin=True) if not m["name"].lower().startswith("rivendell-")]
    if not rows:
        print("No Archer-managed machines. Create one with: archer-cli caldera provision linux")
        return 0
    rank = {"windows": 0, "macos": 1, "linux": 2}
    rows.sort(key=lambda m: (rank.get(m.get("os"), 3), m["name"]))
    hosts = caldera.agent_hosts()  # which are live CALDERA agents (empty if the server isn't configured here)
    for m in rows:
        mark = "agent" if (m.get("name") or "").lower() in hosts else "-"
        print(f"  {m['engine']:7} {m['name']:22} {m.get('os') or '?':7} {m.get('state') or '?':8} {mark}")
    if not hosts:
        print("  (enrolment unknown — set CALDERA_URL/CALDERA_API_KEY, or the caldera block in bespoke/config.yaml)")
    return 0


def main():
    p = argparse.ArgumentParser(prog="archer-cli caldera", description="Provision and enrol CALDERA agents.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("provision", help="create a managed VM/container for an OS and enrol it")
    pr.add_argument("os", choices=["linux", "macos"],
                    help="linux or macos (Windows: build the UTM VM, then `caldera enrol utm <name>`)")
    pr.add_argument("name", nargs="?", help="machine name (default: linux1, macos1, …)")
    pr.add_argument("--engine", choices=["tart", "docker"], default="tart",
                    help="linux only: tart VM (full kernel, default) or docker container (light)")
    pr.add_argument("--group", help="CALDERA group (default: per OS)")
    pr.add_argument("--server", help="CALDERA server URL (default: configured, else the host LAN IP)")

    en = sub.add_parser("enrol", help="enrol a machine Archer already manages")
    en.add_argument("engine", choices=["tart", "docker", "utm"])
    en.add_argument("name")
    en.add_argument("--os", choices=["linux", "macos", "windows"], help="override the machine's recorded OS")
    en.add_argument("--group", help="CALDERA group (default: per OS)")
    en.add_argument("--server", help="CALDERA server URL")

    sub.add_parser("list", help="list Archer-managed machines")

    args = p.parse_args()
    try:
        return {"provision": _provision, "enrol": _enrol, "list": _list}[args.cmd](args)
    except LabError as e:
        print(f"error: {e.message}" + (f" — {e.detail}" if e.detail else ""), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
