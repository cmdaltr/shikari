"""
CALDERA operations client (#30): plan an operation from ATT&CK techniques, a threat group or a
CVE, run it on an agent group, pull back what each link actually ran, and check saved detections
and correlations against that evidence.

Archer drives a CALDERA server you run in your own lab; it ships no agent and no C2 of its own.
The results land in

    data/telemetry/caldera/<operation>/manifest.json

which archer.telemetry.caldera (a separate, byte-different module — do not confuse the two) then
reads as a local recording source. This module is the client and the checker; that one is the
telemetry source. The manifests carry your hosts' names and the steps' output, so they stay on
this machine: data/telemetry/ is gitignored.

The CALDERA API key goes only in the KEY header. It is never logged, returned by Archer's API or
written to a manifest. The check is static: no AI, no SIEM.
"""

import base64
import io
import json
import os
import shutil
import tarfile
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional

import httpx

from archer import paths
from archer.lab.runner import LabError, safe_name  # noqa: F401  (safe_name is re-exported by contract)

# CALDERA's shipped names. The planner chains facts between steps; the fact source seeds them.
PLANNER = "atomic"
SOURCE = "basic"
OBFUSCATOR = "plain-text"
# Archer leaves out CALDERA's own import of Atomic Red Team when another ability runs the
# technique, so the operation exercises CALDERA's implant rather than a packaged atomic.
ATOMIC_PLUGIN = "atomic"
_OUTPUT_CAP = 20000  # characters of each step's output kept; a manifest is evidence, not an archive


# --------------------------------------------------------------------------- settings

def settings(overrides: Optional[Dict] = None) -> Dict:
    """
    Where the CALDERA server and key come from, in order: the environment (a throwaway run needn't
    touch anyone's config), then `overrides` — the signed-in user's own settings (Profile → Emulation
    Tools), passed in by the web layer — then the caldera: block in bespoke/config.yaml. Returns url,
    api_key and verify_tls.
    """
    from archer.build import bespoke

    block = (bespoke.get_config() or {}).get("caldera") or {}
    ov = overrides or {}
    url = os.environ.get("CALDERA_URL") or ov.get("url") or block.get("url") or ""
    api_key = os.environ.get("CALDERA_API_KEY") or ov.get("api_key") or block.get("api_key") or ""
    verify = ov.get("verify_tls")
    if verify is None:
        verify = block.get("verify_tls")
    return {"url": url.rstrip("/"), "api_key": api_key,
            "verify_tls": True if verify is None else bool(verify)}


def configured(overrides: Optional[Dict] = None) -> bool:
    """True once there is both a server to talk to and a key to talk with."""
    s = settings(overrides)
    return bool(s["url"] and s["api_key"])


# --------------------------------------------------------------------------- client

class Client:
    """
    A thin httpx client for CALDERA's v2 REST API. The key lives only in the KEY header; the
    instance never stores it anywhere it could be logged or serialised by mistake.
    """

    def __init__(self, url: str, api_key: str, verify_tls: bool = True, timeout: float = 120.0,
                 transport: Optional[httpx.BaseTransport] = None):
        if not url or not api_key:
            raise LabError("CALDERA is not configured",
                           "Set the server and key in Profile → Emulation Tools (or caldera.url and "
                           "caldera.api_key in bespoke/config.yaml)")
        self.url = url.rstrip("/")  # the base url only — echoed by the status route, never the key
        kw = {"base_url": f"{self.url}/api/v2",
              "headers": {"KEY": api_key, "Content-Type": "application/json"},
              "verify": verify_tls, "timeout": timeout}
        # A caller (the tests) can inject a transport; then skip reading the environment's proxies.
        if transport is not None:
            kw["transport"] = transport
            kw["trust_env"] = False
        try:
            self._http = httpx.Client(**kw)
        except httpx.InvalidURL:
            # A malformed proxy setting in the environment (e.g. a NO_PROXY entry like "[::1]")
            # makes httpx fail while building its proxy mounts. A lab CALDERA is a direct
            # connection, so fall back to ignoring the environment's proxy configuration rather
            # than refusing to start.
            kw["trust_env"] = False
            self._http = httpx.Client(**kw)

    @classmethod
    def from_settings(cls, overrides: Optional[Dict] = None) -> "Client":
        s = settings(overrides)
        return cls(s["url"], s["api_key"], s["verify_tls"])

    # The key is in a header, so it can't surface here; raise a clean LabError on any transport
    # or status error rather than leak an httpx repr that might quote the request.
    def _get(self, path: str):
        return self._request("GET", path)

    def _post(self, path: str, body: Dict):
        return self._request("POST", path, json=body)

    def _delete(self, path: str):
        return self._request("DELETE", path)

    def _request(self, method: str, path: str, **kw):
        try:
            r = self._http.request(method, path, **kw)
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise LabError("CALDERA rejected the request",
                           f"{method} {path} → HTTP {e.response.status_code}")
        except httpx.HTTPError as e:
            # str(e) is httpx's own message about the connection, never the KEY header.
            raise LabError("Could not reach CALDERA", f"{self.url}: {e}")
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError:
            return r.text

    def agents(self) -> List[Dict]:
        return self._get("/agents") or []

    def delete_agent(self, paw: str) -> None:
        """Forget an agent — remove its registration from CALDERA. The sandcat on the host, if it is
        still running, simply re-registers on its next beacon; this clears dead or stale records."""
        self._delete(f"/agents/{paw}")

    def abilities(self) -> List[Dict]:
        return self._get("/abilities") or []


def groups(agents: List[Dict]) -> List[Dict]:
    """Agent groups for the status card: how many agents each has, and the platforms they span."""
    by_group: Dict[str, Dict] = {}
    for a in agents or []:
        g = a.get("group") or ""
        row = by_group.setdefault(g, {"group": g, "agents": 0, "_platforms": set()})
        row["agents"] += 1
        if a.get("platform"):
            row["_platforms"].add(a["platform"])
    out = []
    for row in by_group.values():
        out.append({"group": row["group"], "agents": row["agents"],
                    "platforms": sorted(row.pop("_platforms"))})
    return sorted(out, key=lambda r: r["group"])


# --------------------------------------------------------------------------- planning

def resolve_techniques(kind: str, value: str, generate_dir: str) -> List[str]:
    """
    The ATT&CK technique IDs a target names. Techniques are taken as given; a group or CVE is
    resolved exactly as Emulate's planner resolves them, so the two agree on what a target covers.
    """
    from archer.lab import record

    kind = (kind or "technique").lower()
    if kind == "technique":
        tids = record.clean_techniques(value)  # raises LabError on anything that isn't an ID
    else:
        from archer.telemetry.planner import _resolve

        seen: List[str] = []
        for t in _resolve(kind, value, generate_dir):
            tid = t.get("technique_id")
            if tid and tid not in seen:
                seen.append(tid)
        tids = seen
    if not tids:
        raise LabError("No techniques", f"{value!r} resolved to no ATT&CK techniques")
    return tids


def _related(a: str, b: str) -> bool:
    """A technique matches itself, its parent and its sub-techniques (T1059 ~ T1059.001)."""
    a, b = a.upper(), b.upper()
    return a == b or a.startswith(b + ".") or b.startswith(a + ".")


def _match_rank(ability_tid: str, want: str) -> Optional[int]:
    """0 exact, 1 a sub/parent, or None when the ability doesn't run the technique at all."""
    ability_tid = (ability_tid or "").upper()
    if ability_tid == want.upper():
        return 0
    if _related(ability_tid, want):
        return 1
    return None


def _runnable_executors(abilities_executor: List[Dict], platforms, executors) -> List[Dict]:
    """An ability's executors an agent in the group could run: right platform, known executor."""
    out = []
    for ex in abilities_executor or []:
        platform, name = ex.get("platform"), ex.get("name")
        if platform and platform not in platforms:
            continue
        # Some agents don't advertise their executors; then platform alone decides.
        if executors and name and name not in executors:
            continue
        out.append(ex)
    return out


def plan(abilities: List[Dict], agents: List[Dict], techniques: List[str], group: str) -> Dict:
    """
    Choose one ability per technique the group can run, preferring an exact ATT&CK match over a
    sub/parent one and CALDERA's own plugins over its Atomic import. Reads only; it is the dry run.
    """
    in_group = [a for a in agents or [] if (a.get("group") or "") == group]
    platforms = {a.get("platform") for a in in_group if a.get("platform")}
    executors = {e for a in in_group for e in (a.get("executors") or []) if e}
    paws = [a.get("paw") for a in in_group if a.get("paw")]

    steps, gaps, warnings = [], [], []
    if not in_group:
        warnings.append(f"No agents in group {group!r}")
    for want in techniques:
        best, best_key = None, None
        for ab in abilities or []:
            rank = _match_rank(ab.get("technique_id", ""), want)
            if rank is None:
                continue
            runnable = _runnable_executors(ab.get("executors") or [], platforms, executors)
            if not runnable:
                continue
            ex = runnable[0]
            plugin_rank = 1 if (ab.get("plugin") or "").lower() == ATOMIC_PLUGIN else 0
            key = (rank, plugin_rank)  # lower is better: exact first, then non-atomic plugins
            if best_key is None or key < best_key:
                best_key, best = key, {
                    "technique_id": want, "ability": ab.get("name") or ab.get("ability_id"),
                    "ability_id": ab.get("ability_id"), "executor": ex.get("name"),
                    "platform": ex.get("platform"), "command": ex.get("command") or ""}
        if best:
            steps.append(best)
        else:
            gaps.append(want)
    return {"steps": steps, "gaps": gaps, "agents": paws, "warnings": warnings}


# Archer's own machine engines, and the environments the lab script (scripts/telemetry/caldera-lab.sh)
# builds each CALDERA group in — so an agent the machine registry doesn't know (a lab-script VM, say)
# is still placed by the group it enrolled under.
_ENGINE_LABEL = {"docker": "Docker", "tart": "Tart", "utm": "UTM"}
_GROUP_ENV = {"disposable": "OrbStack", "winlab": "UTM", "maclab": "Tart"}


def _agent_env(a: Dict, by_name: Dict[str, Dict], host_name: str) -> Dict:
    """Where a node runs, as {env, engine, machine}: an Archer-managed machine's engine when its
    name matches (so the diagram can drive it), 'this host' when the agent is this machine itself,
    else the lab script's group convention. engine/machine are set only for a managed match."""
    paw, host = (a.get("paw") or "").lower(), (a.get("host") or "").lower()
    if host_name and host == host_name.lower():
        return {"env": "this host", "engine": "", "machine": ""}  # a sandcat on the machine, not a VM
    for key in (paw, host):
        m = by_name.get(key)
        if m:
            eng = m.get("engine") or ""
            return {"env": _ENGINE_LABEL.get(eng, eng), "engine": eng, "machine": m.get("name") or ""}
    return {"env": _GROUP_ENV.get((a.get("group") or "").lower(), ""), "engine": "", "machine": ""}


def agent_nodes(agents: List[Dict], machines: Optional[List[Dict]] = None,
                host_name: str = "") -> List[Dict]:
    """A trimmed agent list for the topology diagram: one node per host with its paw, platform,
    group, the environment it runs in and — when it maps to an Archer-managed machine — that
    machine's engine and name, so the node can be acted on. CALDERA keeps every agent that ever
    enrolled, so a VM re-enrolled under a fresh paw (an `up` before the lab fixed its paws, say)
    leaves stale records on the same host; keep only the most recently seen agent per host, so the
    diagram shows live VMs and not their ghosts. The key is never here — these come from /agents."""
    by_name = {m["name"].lower(): m for m in (machines or []) if m.get("name")}
    by_host: Dict[str, Dict] = {}
    for a in agents or []:
        host = (a.get("host") or a.get("paw") or "?").lower()
        prev = by_host.get(host)
        if prev is None or (a.get("last_seen") or "") > (prev.get("last_seen") or ""):
            by_host[host] = a
    return [{"host": a.get("host") or a.get("paw") or "?", "paw": a.get("paw") or "",
             "platform": a.get("platform") or "", "group": a.get("group") or "",
             **_agent_env(a, by_name, host_name), "last_seen": a.get("last_seen") or ""}
            for a in by_host.values()]


def _technique_platforms(abilities: List[Dict], want: str) -> set:
    """The OSes some ability could run this technique on — for the Detonate dialog's OS badges."""
    out = set()
    for ab in abilities or []:
        if _match_rank(ab.get("technique_id", ""), want) is None:
            continue
        for ex in ab.get("executors") or []:
            if ex.get("platform"):
                out.add(ex["platform"])
    return out


def coverage(abilities: List[Dict], agents: List[Dict], techniques: List[str]) -> Dict:
    """For the Detonate dialog: the resolved techniques (with the OSes they can run on), and for
    each agent group its VMs and which of those techniques it can and can't run. Reads only.

    Targeting is by group because a sandcat agent re-asserts its enrolment group on every beacon,
    so a group — not an ad-hoc selection — is what an operation can reliably hit. Within a group,
    CALDERA runs each ability only on the agents whose OS matches, so OS-specific techniques land on
    the right VMs on their own; the gaps below are the techniques no VM in that group can run."""
    techs = [{"id": t, "platforms": sorted(_technique_platforms(abilities, t))} for t in techniques]
    grps = []
    for g in groups(agents):
        p = plan(abilities, agents, techniques, g["group"])
        grps.append({
            "group": g["group"], "platforms": g["platforms"],
            "vms": [{"host": a.get("host") or a.get("paw") or "?", "paw": a.get("paw") or "",
                     "platform": a.get("platform") or "?"}
                    for a in agents if (a.get("group") or "") == g["group"]],
            "runnable": [s["technique_id"] for s in p["steps"]],
            "gaps": p["gaps"],
        })
    return {"techniques": techs, "groups": grps}


def plan_lines(plan: Dict, label: str) -> List[str]:
    """The dry-run lines the guide's Planning table describes, in order."""
    steps, gaps = plan.get("steps") or [], plan.get("gaps") or []
    lines = [f"Create adversary {label!r} with {len(steps)} abilit{'y' if len(steps) == 1 else 'ies'}"]
    if steps:
        lines.append(f"Start operation on group with planner {PLANNER}, obfuscator {OBFUSCATOR}, "
                     f"closing when done ({len(plan.get('agents') or [])} agent(s))")
    for s in steps:
        lines.append(f"{s['technique_id']} {s['ability']} on {s.get('platform')}/{s.get('executor')}: "
                     f"{s.get('command', '')}")
    for g in gaps:
        lines.append(f"No runnable ability for {g}")
    return lines


# ------------------------------------------------------- provisioning agents (web + CLI, #30)

# OS name (Archer's templates) -> sandcat's GOOS.
_PLATFORM = {"windows": "windows", "macos": "darwin", "linux": "linux"}
# A default group per OS, matching the lab script's convention so the topology colours agree.
GROUP_FOR = {"linux": "disposable", "macos": "maclab", "windows": "winlab"}
# The templates Archer can provision a CALDERA agent from, by OS. "Offer both" for Linux.
TEMPLATES_FOR = {"linux": ["ubuntu-vm", "ubuntu-container"], "macos": ["macos-vm"]}


def _agent_arch(os_name: str) -> str:
    """The sandcat architecture to compile. Linux/macOS VMs are the host's architecture (Tart/UTM
    virtualise the host CPU); Windows on Apple Silicon is ARM64 Windows but runs x64 under emulation,
    and CALDERA builds windows/amd64 reliably, so ask for amd64 there."""
    import platform as _p

    if os_name == "windows":
        return "amd64"
    return "arm64" if _p.machine().lower() in ("arm64", "aarch64") else "amd64"


def enrol_agent(engine_key: str, name: str, os_name: str, group: str, server_url: str,
                say: Callable[[str], None] = print) -> None:
    """
    Enrol an Archer-managed, running machine as a CALDERA agent in `group`, with the machine name as
    its paw. The machine fetches the architecture-correct sandcat itself and runs it detached, so
    nothing large streams over the guest agent (which chokes on it):
      - Tart Linux : curl in the VM, hostname set to `name`, run under systemd (systemd-run)
      - Docker     : push the binary with `docker cp`, run with `docker exec -d`
      - Tart macOS : curl in the VM, run under launchd — needs the Tart guest agent (a cirruslabs base)
      - UTM Windows: download in the VM with PowerShell, run hidden with Start-Process
    The arch header matters: the amd64 default fails on an arm64 Tart VM (Exec format error).
    """
    from archer.lab.engines import engine_for
    from archer.lab.runner import run as _run

    platform = _PLATFORM.get(os_name)
    if not platform:
        raise LabError("Unknown OS", os_name)
    # Which OS each engine can carry: a container is Linux, Tart does Linux/macOS, UTM does Windows.
    valid = {"docker": {"linux"}, "tart": {"linux", "macos"}, "utm": {"windows"}}
    if os_name not in valid.get(engine_key, set()):
        raise LabError("Can't enrol this machine", f"no enrol path for {os_name} on {engine_key}")
    url = server_url.rstrip("/")
    arch = _agent_arch(os_name)
    eng = engine_for(engine_key)
    dl = f"-XPOST -Hfile:sandcat.go -Hplatform:{platform} -Harchitecture:{arch} {url}/file/download"
    say(f"Enrolling {name} ({os_name}/{engine_key}) in group {group}…")

    if engine_key == "docker":
        # A bare container may lack curl; fetch the arch-correct binary on the host and copy it in.
        # The container's hostname is already `name` (set at create), and -d detaches the agent.
        import os as _os
        import tempfile

        import httpx

        with httpx.Client(timeout=120) as c:
            r = c.post(f"{url}/file/download",
                       headers={"file": "sandcat.go", "platform": platform, "architecture": arch})
            r.raise_for_status()
            binary = r.content
        if not binary:
            raise LabError("Agent download failed", "the server returned no sandcat binary")
        tmp = tempfile.NamedTemporaryFile(prefix="sc-", delete=False)
        try:
            tmp.write(binary)
            tmp.close()
            eng.push_file(name, tmp.name, "/tmp/sc")
            eng.exec(name, ["chmod", "+x", "/tmp/sc"], timeout=30)
            _run(["docker", "exec", "-d", name, "/tmp/sc", "-paw", name,
                  "-server", url, "-group", group, "-v"], timeout=30)
        finally:
            _os.unlink(tmp.name)

    elif engine_key == "tart" and os_name == "linux":
        # systemd-run returns at once and hands the agent to systemd, so it survives the exec session;
        # the cirruslabs base's hostname is "ubuntu", so set it to `name` or the diagram collapses nodes.
        script = (f"curl -s {dl} -o /tmp/sc && chmod +x /tmp/sc && "
                  f"sudo hostnamectl set-hostname {name} 2>/dev/null; "
                  f"sudo systemctl stop caldera-sc 2>/dev/null; sudo systemctl reset-failed caldera-sc 2>/dev/null; "
                  f"sudo systemd-run --unit=caldera-sc --property=Restart=always /tmp/sc "
                  f"-paw {name} -server {url} -group {group} -v")
        eng.exec(name, ["bash", "-lc", script], timeout=180)

    elif engine_key == "tart" and os_name == "macos":
        # Needs the Tart guest agent (a cirruslabs base). launchd keeps it running past the session.
        label = "io.archer.caldera-sc"
        plist = (f'<?xml version="1.0" encoding="UTF-8"?>'
                 f'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
                 f'<plist version="1.0"><dict><key>Label</key><string>{label}</string>'
                 f'<key>ProgramArguments</key><array><string>/tmp/sc</string>'
                 f'<string>-paw</string><string>{name}</string><string>-server</string><string>{url}</string>'
                 f'<string>-group</string><string>{group}</string><string>-v</string></array>'
                 f'<key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>')
        script = (f"curl -s {dl} -o /tmp/sc && chmod +x /tmp/sc && "
                  f"sudo scutil --set HostName {name} 2>/dev/null; "
                  f"printf '%s' '{plist}' | sudo tee /Library/LaunchDaemons/{label}.plist >/dev/null && "
                  f"sudo launchctl bootout system/{label} 2>/dev/null; "
                  f"sudo launchctl bootstrap system /Library/LaunchDaemons/{label}.plist")
        eng.exec(name, ["bash", "-lc", script], timeout=180)

    elif engine_key == "utm" and os_name == "windows":
        ps = (f"$ErrorActionPreference='Stop'; "
              f"$h=@{{'file'='sandcat.go';'platform'='windows';'architecture'='{arch}'}}; "
              f"Invoke-WebRequest -Uri '{url}/file/download' -Method Post -Headers $h -OutFile 'C:\\Windows\\Temp\\sc.exe'; "
              f"Start-Process -WindowStyle Hidden 'C:\\Windows\\Temp\\sc.exe' "
              f"-ArgumentList '-server','{url}','-group','{group}','-paw','{name}','-v'")
        eng.exec(name, ["powershell", "-NoProfile", "-Command", ps], timeout=180)

    else:
        raise LabError("Can't enrol this machine", f"no enrol path for {os_name} on {engine_key}")
    say(f"{name} enrolled — it will appear in the topology on its next beacon")


def agent_hosts(overrides: Optional[Dict] = None) -> set:
    """Lower-cased paws and hosts of the CALDERA agents currently checked in — for marking which
    Archer machines are enrolled. Best-effort: an empty set when CALDERA isn't configured or is down,
    so a caller can always treat 'not in the set' as 'not enrolled'."""
    if not configured(overrides):
        return set()
    try:
        client = Client.from_settings(overrides)
        names = set()
        for a in client.agents():
            for k in (a.get("paw"), a.get("host")):
                if k:
                    names.add(str(k).lower())
        return names
    except LabError:
        return set()


def _wait_ready(engine_key: str, name: str, say: Callable[[str], None] = print,
                tries: int = 60, interval: int = 5) -> None:
    """Wait until a just-started machine will accept exec — a VM needs to boot its guest agent."""
    from archer.lab.engines import engine_for

    if engine_key == "docker":
        return  # a container is ready the moment it is running
    eng = engine_for(engine_key)
    for _ in range(tries):
        try:
            eng.exec(name, ["true"] if engine_key == "tart" else ["cmd", "/c", "echo", "ok"], timeout=15)
            return
        except LabError:
            time.sleep(interval)
    raise LabError("Machine never became ready",
                   f"{name} did not accept exec in {tries * interval}s — is its guest agent installed?")


def provision_for_caldera(template_id: str, name: str, group: str, server_url: str, owner=None,
                          say: Callable[[str], None] = print) -> Dict:
    """Create an Archer-managed machine from a template, start it, wait for it, and enrol it as a
    CALDERA agent — the one-call 'provision a host for CALDERA' used by the web and the CLI."""
    from archer.lab import machines
    from archer.lab.templates import BY_ID

    tpl = BY_ID.get(template_id)
    if not tpl:
        raise LabError("Unknown template", template_id)
    name = safe_name(name)
    say(f"Creating {tpl['name']} '{name}'…")
    machines.create(template_id, name, owner=owner)
    say("Starting the machine…")
    machines.start(tpl["engine"], name)
    _wait_ready(tpl["engine"], name, say)
    enrol_agent(tpl["engine"], name, tpl["os"], group or GROUP_FOR.get(tpl["os"], "disposable"),
                server_url, say)
    return {"name": name, "engine": tpl["engine"], "os": tpl["os"], "template": template_id}


# --------------------------------------------------------------------------- running

def operate(client: Client, techniques: List[str], group: str, name: str = "",
            target: str = "", execute: bool = False, say: Callable[[str], None] = print) -> Dict:
    """
    Build the adversary from the planned abilities and start the operation. With execute=False it
    POSTs nothing — planning already happened — and just returns the chosen label.
    """
    label = safe_name(name) if name else "archer-operation"
    plan_now = plan(client.abilities(), client.agents(), techniques, group)
    ability_ids = [s["ability_id"] for s in plan_now["steps"] if s.get("ability_id")]
    if not execute:
        return {"operation_id": "", "name": label, "executed": False}
    if not ability_ids:
        raise LabError("Nothing to run", "No ability the group can run matched these techniques")

    say(f"Creating adversary {label} with {len(ability_ids)} abilities…")
    adversary = client._post("/adversaries", {
        "name": label, "description": f"Archer: {target}" if target else "Archer operation",
        "atomic_ordering": ability_ids}) or {}
    adversary_id = adversary.get("adversary_id") or adversary.get("id")

    say(f"Starting operation on group {group}…")
    op = client._post("/operations", {
        "name": label, "group": group, "state": "running", "auto_close": True,
        "obfuscator": OBFUSCATOR, "visibility": 51,
        "adversary": {"adversary_id": adversary_id},
        "planner": {"id": PLANNER}, "source": {"id": SOURCE}}) or {}
    op_id = op.get("id") or op.get("operation_id")
    if not op_id:
        raise LabError("CALDERA did not return an operation id", "The operation may not have started")
    return {"operation_id": op_id, "name": label, "adversary_id": adversary_id, "group": group}


def wait(client: Client, op_id: str, say: Callable[[str], None] = print,
         timeout: int = 1800, interval: int = 10) -> str:
    """Poll the operation until it has finished or closed, and return its final state."""
    done = {"finished", "closed", "out_of_time", "cleanup"}
    deadline = time.time() + timeout
    state = ""
    while time.time() < deadline:
        op = client._get(f"/operations/{op_id}") or {}
        state = op.get("state") or ""
        if state in done:
            return state
        time.sleep(interval)
    say(f"Gave up waiting after {timeout}s; last state {state or 'unknown'}")
    return state or "unknown"


# --------------------------------------------------------------------------- collecting

def _decode(s) -> str:
    """
    A link's base64 command or result as text. CALDERA base64-encodes these; a result is often a
    base64 of {"stdout","stderr"} JSON. Plain input (already decoded, or never encoded) is returned
    unchanged rather than mangled.
    """
    if s is None:
        return ""
    if isinstance(s, dict):  # already-parsed {stdout, stderr}
        return "\n".join(str(s.get(k, "")) for k in ("stdout", "stderr") if s.get(k)).strip()
    text = str(s)
    try:
        raw = base64.b64decode(text, validate=True).decode("utf-8", "replace")
    except (ValueError, UnicodeDecodeError):
        return text  # not base64: it was plain all along
    stripped = raw.strip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict) and ("stdout" in obj or "stderr" in obj):
                return "\n".join(str(obj.get(k, "")) for k in ("stdout", "stderr") if obj.get(k)).strip()
        except ValueError:
            pass
    return raw


def _link_result(client: Client, op_id: str, link_id: str) -> str:
    """One link's decoded output, or empty if it produced none."""
    try:
        res = client._get(f"/operations/{op_id}/links/{link_id}/result")
    except LabError:
        return ""  # a link with no result yet 404s; that is not a failure of the collect
    if isinstance(res, dict):
        # CALDERA 5.2 returns {"link": {...}, "result": "<base64>"}; older builds used "output".
        res = res.get("result") or res.get("output") or ""
    return _decode(res)


def _caldera_dir() -> str:
    # Resolved at call time, not import, so ARCHER_HOME set for a throwaway run (or a test) is honoured.
    return str(paths.DATA / "telemetry" / "caldera")


def collect(client: Client, op_id: str, say: Callable[[str], None] = print,
            rebuild: bool = False) -> Dict:
    """
    Pull an operation and its links into a manifest: for every link the technique, ability, the
    command as it ran, host and paw, platform and executor, status, the decide/collect/finish
    times and the decoded output (capped). Rebuilds the CALDERA recording source unless a capture
    run will do that afterwards.
    """
    op = client._get(f"/operations/{op_id}") or {}
    links = client._get(f"/operations/{op_id}/links") or op.get("chain") or []
    name = safe_name(op.get("name") or f"operation-{op_id}")
    say(f"Collecting {len(links)} link(s) from operation {name}…")

    steps = []
    for ln in links:
        ability = ln.get("ability") or {}
        executor = ln.get("executor") or {}
        steps.append({
            "technique_id": ability.get("technique_id") or ln.get("technique_id") or "",
            "ability": ability.get("name") or ln.get("ability_name") or "",
            "command": _decode(ln.get("command")),
            "host": ln.get("host") or "", "paw": ln.get("paw") or "",
            "platform": executor.get("platform") or ln.get("platform") or "",
            "executor": executor.get("name") or ln.get("executor") or "",
            "status": ln.get("status"),
            "decide": ln.get("decide") or "", "collect": ln.get("collect") or "",
            "finish": ln.get("finish") or "",
            "output": _link_result(client, op_id, ln.get("id") or ln.get("unique") or "")[:_OUTPUT_CAP]})

    manifest = {"name": name, "operation_id": op_id, "state": op.get("state") or "",
                "group": op.get("group") or "", "collected": _now_iso(),
                "start": op.get("start") or "", "captured": False, "steps": steps}

    folder = os.path.join(_caldera_dir(), name)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    say(f"Saved {len(steps)} step(s) to data/telemetry/caldera/{name}")

    if rebuild:
        say("Rebuilding the CALDERA recording source…")
        from archer.telemetry.__main__ import build

        build(["caldera"], log=say)
    return manifest


def collected() -> List[Dict]:
    """Every collected manifest, newest first. The caller strips step output before returning it."""
    base = _caldera_dir()
    out = []
    for name in os.listdir(base) if os.path.isdir(base) else []:
        m = load(name)
        if m:
            out.append(m)
    return sorted(out, key=lambda m: m.get("collected") or "", reverse=True)


def load(name: str) -> Optional[Dict]:
    """One collected manifest by name, or None."""
    try:
        path = os.path.join(_caldera_dir(), safe_name(name), "manifest.json")
    except LabError:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------- capture

def windows(manifest: Dict) -> List[Dict]:
    """
    The per-step time windows for capture-window.ps1: each step's own window, widened by 5s before
    the decision and 20s after the finish for clock skew and late events.
    """
    out = []
    for i, s in enumerate(manifest.get("steps") or [], 1):
        start, end = _parse_time(s.get("decide")), _parse_time(s.get("finish"))
        if not (start and end):
            continue
        tid = s.get("technique_id") or "T0000"
        out.append({"technique": tid, "folder": f"{tid}-{i}", "name": s.get("ability") or tid,
                    "start": _iso(start - timedelta(seconds=5)),
                    "end": _iso(end + timedelta(seconds=20))})
    return out


def capture(engine: str, name: str, os_name: str, manifest: Dict, host: str = "",
            say: Callable[[str], None] = print) -> Dict:
    """
    Read the agent host's logs back over each step's window and import them as a lab run named
    caldera-<operation>. Reuses the lab recorder's push/run/pull so it reads nothing but the logs.
    """
    from archer.lab.engines import engine_for
    from archer.lab.record import _pull, _push, _pwsh, _paths  # the lab recorder's machine plumbing
    from archer.telemetry.lab import LAB_DIR

    wins = windows(manifest)
    if not wins:
        say("No step had both a decide and a finish time; nothing to capture")
        return manifest
    run_name = safe_name(f"caldera-{manifest['name']}")
    script = os.path.join(paths.ROOT, "scripts", "telemetry", "capture-window.ps1")
    if not os.path.isfile(script):
        raise LabError("capture-window.ps1 is missing", script)

    eng = engine_for(engine)
    is_windows = os_name == "windows"
    script_remote, out_remote, run_remote = _paths(os_name, run_name)
    script_remote = script_remote.replace("record-atomics.ps1", "capture-window.ps1")
    windows_remote = script_remote.replace("capture-window.ps1", "archer-windows.json")

    # Hand the windows to the machine as JSON, then let the script read its own logs over them.
    local_windows = os.path.join(paths.DATA, "telemetry", f".{run_name}.windows.json")
    os.makedirs(os.path.dirname(local_windows), exist_ok=True)
    with open(local_windows, "w", encoding="utf-8") as fh:
        json.dump(wins, fh)

    say(f"Capturing {len(wins)} window(s) on {name}…")
    _push(eng, name, script, script_remote, is_windows)
    _push(eng, name, local_windows, windows_remote, is_windows)
    argv = [_pwsh(os_name), "-NoProfile", "-File", script_remote, "-Windows", windows_remote,
            "-Run", run_name, "-Out", out_remote, "-Tool", "CALDERA"]
    out = eng.exec(name, argv, timeout=1800)
    for line in (out or "").strip().splitlines()[-15:]:
        say(line)

    os.makedirs(LAB_DIR, exist_ok=True)
    _pull(eng, name, run_remote, LAB_DIR, is_windows)
    try:
        os.remove(local_windows)
    except OSError:
        pass

    say("Rebuilding Your lab…")
    from archer.telemetry.__main__ import build

    build(["lab"], log=say)

    manifest["captured"] = True
    for s in manifest.get("steps") or []:
        s["recorded"] = f"lab:{run_name}/{s.get('technique_id')}"
    folder = os.path.join(_caldera_dir(), manifest["name"])
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    say(f"Captured endpoint logs for {manifest['name']} as {run_name}")
    return manifest


# ------------------------------------------------- capture over the agent's own C2 (no host access)

_C2_OPEN, _C2_CLOSE = "ARCHERB64:", ":ENDB64"
_MAC_LOG_CAP = 2_000_000  # bytes per window of `log show` output — the unified log is huge; this is
#                           ample for indicator matching and keeps the link result small.


def _capture_command(script_b64: str, win_b64: str, run_name: str) -> str:
    """
    The PowerShell the agent runs for a C2 capture: write capture-window.ps1 and the windows out,
    run them (every stream to a log, so only our marker reaches stdout), tar the run folder and print
    it base64 between markers. The whole run then comes back in the link result — no exfil dir, no
    host access. Valid under both Windows PowerShell 5.1 and pwsh 7, so one body serves every OS.
    """
    # Joined with ';', not newlines: CALDERA runs a psh command as a single line, collapsing newlines,
    # so statements must be semicolon-separated. Paths go in variables first because PowerShell can
    # only redirect (*>) to a variable or literal, never to a parenthesised expression.
    return ";".join([
        "$ErrorActionPreference='Stop'",
        "$d=Join-Path ([IO.Path]::GetTempPath()) 'archer-cap'",
        "if(Test-Path $d){Remove-Item -Recurse -Force $d}",
        "New-Item -ItemType Directory -Force $d|Out-Null",
        "$cap=Join-Path $d 'cap.ps1'",
        "$wj=Join-Path $d 'w.json'",
        "$o=Join-Path $d 'out'",
        "$log=Join-Path $d 'log.txt'",
        "$tgz=Join-Path $d 'r.tgz'",
        f"[IO.File]::WriteAllText($cap,[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{script_b64}')))",
        f"[IO.File]::WriteAllText($wj,[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{win_b64}')))",
        f"& $cap -Windows $wj -Run '{run_name}' -Out $o -Tool CALDERA *> $log",
        f"& tar -c -z -f $tgz -C $o '{run_name}'",
        f"'{_C2_OPEN}'+[Convert]::ToBase64String([IO.File]::ReadAllBytes($tgz))+'{_C2_CLOSE}'",
    ])


def _capture_command_sh(wins: List[Dict], run_name: str, os_name: str) -> str:
    """
    The native shell a Linux or macOS agent runs for a C2 capture — the no-dependency analogue of
    capture-window.ps1, so no PowerShell is needed on the host. It reads only logs (auditd and the
    journal on Linux, the unified log on macOS) into the lab-recorder layout, tars the run and prints
    it base64 between markers, so the run returns in the link result. Statements are ';'-joined because
    CALDERA runs a command as one line; each log read is best-effort so a missing source can't fail it.
    """
    platform = "macos" if os_name == "darwin" else "linux"
    rd = f"$d/out/{run_name}"

    def epoch(iso) -> int:
        dt = _parse_time(iso)
        if not dt:
            return 0
        return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp())

    tests, parts = [], [
        "set -u",
        'd="${TMPDIR:-/tmp}/archer-cap"',
        'rm -rf "$d" 2>/dev/null',
        f'mkdir -p "{rd}"',
        "host=$(hostname 2>/dev/null | tr 'A-Z' 'a-z')",
        "started=$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    ]
    for i, w in enumerate(wins, 1):
        folder, fp = w["folder"], f"{rd}/{w['folder']}"
        frm, to = epoch(w["start"]), epoch(w["end"])
        parts.append(f'mkdir -p "{fp}"')
        if platform == "macos":
            # The unified log is huge and unfiltered; cap each window so the tarball fits in the link
            # result (plenty for indicator matching, which keeps few values per field).
            parts.append(
                f"log show --start \"$(date -r {frm} '+%Y-%m-%d %H:%M:%S')\" "
                f"--end \"$(date -r {to} '+%Y-%m-%d %H:%M:%S')\" --style ndjson 2>/dev/null "
                f"| head -c {_MAC_LOG_CAP} > \"{fp}/unified.ndjson\" || true")
        else:
            parts.append(
                f"awk -v a={frm} -v b={to} '{{p=index($0,\"audit(\");if(p){{n=substr($0,p+6)+0;"
                f"if(n>=a&&n<=b)print}}}}' /var/log/audit/audit.log 2>/dev/null > \"{fp}/audit.log\" || true")
            parts.append(
                f"journalctl --since @{frm} --until @{to} -o short --no-pager > \"{fp}/journal.log\" 2>/dev/null || true")
        tests.append({"technique": w["technique"], "test": i, "name": w.get("name") or w["technique"],
                      "folder": folder, "start": w["start"], "end": w["end"]})

    # Build the manifest in Python (names escaped by json), fill host/started on the agent via sed.
    manifest = json.dumps({"run": run_name, "host": "__HOST__", "platform": platform,
                           "tool": "CALDERA", "started": "__STARTED__", "tests": tests})
    safe = manifest.replace("'", "'\\''")  # survive the single-quoted shell literal
    parts += [
        f"printf '%s' '{safe}' > \"{rd}/manifest.json.tmpl\"",
        f'sed "s/__HOST__/$host/;s/__STARTED__/$started/" "{rd}/manifest.json.tmpl" > "{rd}/manifest.json"',
        f'rm -f "{rd}/manifest.json.tmpl"',
        f'tar -czf "$d/r.tgz" -C "$d/out" "{run_name}"',
        f"printf '{_C2_OPEN}'; base64 < \"$d/r.tgz\" | tr -d '\\n'; printf '{_C2_CLOSE}\\n'",
    ]
    return ";".join(parts)


def _safe_extract(tar: tarfile.TarFile, path: str) -> None:
    """extractall, but refuse any member that would land outside `path` (defence in depth; the tar
    is our own capture, but it arrived over the network)."""
    base = os.path.realpath(path)
    for m in tar.getmembers():
        target = os.path.realpath(os.path.join(path, m.name))
        if target != base and not target.startswith(base + os.sep):
            raise LabError("Unsafe path in the capture archive", m.name)
    tar.extractall(path)


def capture_via_agent(client: "Client", manifest: Dict, say: Callable[[str], None] = print) -> Dict:
    """
    Zero-touch endpoint-log capture: task the operation's own agents, over CALDERA's C2, to read each
    step's logs back as a lab run. Needs only a running sandcat agent — nothing installed on the host:
    Windows reads its logs with the built-in PowerShell (capture-window.ps1), Linux and macOS with the
    native shell. The agent returns the run folder as a base64 tarball in its link result, so only the
    REST API is used. The result imports exactly as capture() does, and the check is the same.
    """
    from archer.telemetry.lab import LAB_DIR

    wins = windows(manifest)
    if not wins:
        say("No step had both a decide and a finish time; nothing to capture")
        return manifest
    script = os.path.join(paths.ROOT, "scripts", "telemetry", "capture-window.ps1")
    if not os.path.isfile(script):
        raise LabError("capture-window.ps1 is missing", script)

    base_run = safe_name(f"caldera-{manifest['name']}")
    hosts = sorted({(s.get("host") or s.get("paw") or "") for s in manifest.get("steps") or []})
    multi = len([h for h in hosts if h]) > 1

    def run_for(host: str) -> str:  # a per-host run name only when the operation spanned >1 host
        return safe_name(f"{base_run}-{host}") if multi and host else base_run

    with open(script, "rb") as fh:
        script_b64 = base64.b64encode(fh.read()).decode()
    win_b64 = base64.b64encode(json.dumps(wins).encode()).decode()
    # Windows runs capture-window.ps1 under its built-in PowerShell; Linux and macOS read the logs
    # with the native shell — so every OS is captured with nothing installed on the host.
    win_cmd = _capture_command(script_b64, win_b64, base_run)
    linux_cmd = _capture_command_sh(wins, base_run, "linux")
    macos_cmd = _capture_command_sh(wins, base_run, "darwin")

    say("Creating the capture ability…")
    ability = client._post("/abilities", {
        "name": "Archer: capture endpoint logs", "tactic": "collection",
        "technique_id": "T1005", "technique_name": "Data from Local System",
        "executors": [
            {"platform": "windows", "name": "psh", "command": win_cmd, "timeout": 900, "cleanup": []},
            {"platform": "linux", "name": "sh", "command": linux_cmd, "timeout": 900, "cleanup": []},
            {"platform": "darwin", "name": "sh", "command": macos_cmd, "timeout": 900, "cleanup": []}]}) or {}
    ability_id = ability.get("ability_id") or ability.get("id")
    if not ability_id:
        raise LabError("CALDERA did not create the capture ability", "no ability id returned")

    group = manifest.get("group") or ""
    adversary = client._post("/adversaries", {
        "name": f"Archer capture {base_run}", "description": "Archer: read endpoint logs back",
        "atomic_ordering": [ability_id]}) or {}
    adversary_id = adversary.get("adversary_id") or adversary.get("id")

    got = set()
    try:
        say(f"Running the capture on group {group} over C2…")
        op = client._post("/operations", {
            "name": f"capture-{base_run}", "group": group, "state": "running", "auto_close": True,
            "obfuscator": OBFUSCATOR, "visibility": 51, "adversary": {"adversary_id": adversary_id},
            "planner": {"id": PLANNER}, "source": {"id": SOURCE}}) or {}
        op_id = op.get("id") or op.get("operation_id")
        if not op_id:
            raise LabError("CALDERA did not start the capture operation", "no operation id returned")
        wait(client, op_id, say=say)

        os.makedirs(LAB_DIR, exist_ok=True)
        for ln in client._get(f"/operations/{op_id}/links") or []:
            res = _link_result(client, op_id, ln.get("id") or ln.get("unique") or "")
            if not res or _C2_OPEN not in res:
                continue
            blob = res.split(_C2_OPEN, 1)[1].split(_C2_CLOSE, 1)[0].strip()
            try:
                data = base64.b64decode(blob)
            except ValueError:  # binascii.Error subclasses ValueError
                continue
            host = ln.get("host") or ln.get("paw") or ""
            run_name = run_for(host)
            tmp = os.path.join(LAB_DIR, f".{run_name}.incoming")
            shutil.rmtree(tmp, ignore_errors=True)
            os.makedirs(tmp, exist_ok=True)
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                _safe_extract(t, tmp)
            dest = os.path.join(LAB_DIR, run_name)
            shutil.rmtree(dest, ignore_errors=True)
            os.replace(os.path.join(tmp, base_run), dest)
            shutil.rmtree(tmp, ignore_errors=True)
            got.add(host)
            say(f"Captured {host or 'agent'} → {run_name}")
        if not got:
            raise LabError("No agent returned captured logs",
                           "the capture ability ran but no link carried a result")
    finally:
        for path in (f"/abilities/{ability_id}", f"/adversaries/{adversary_id}" if adversary_id else ""):
            if path:
                try:
                    client._delete(path)
                except LabError:
                    pass  # best-effort tidy-up; leftover definitions don't affect anything

    say("Rebuilding Your lab…")
    from archer.telemetry.__main__ import build

    build(["lab"], log=say)

    manifest["captured"] = True
    for s in manifest.get("steps") or []:
        host = s.get("host") or s.get("paw") or ""
        s["recorded"] = f"lab:{run_for(host)}/{s.get('technique_id')}"
    folder = os.path.join(_caldera_dir(), manifest["name"])
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    say(f"Captured endpoint logs for {manifest['name']} over C2 ({len(got)} host(s))")
    return manifest


# --------------------------------------------------------------------------- the check

def _detection_index(generate_dir: str) -> List[Dict]:
    """Every saved detection with a technique, as {technique_id, name, file, doc}. Cached per dir."""
    import yaml

    cache = _detection_index._cache
    if cache.get("dir") == generate_dir:
        return cache["rows"]
    rows = []
    for fn in sorted(os.listdir(generate_dir)) if os.path.isdir(generate_dir) else []:
        if not fn.endswith((".yaml", ".yml")):
            continue
        try:
            with open(os.path.join(generate_dir, fn), encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
        except (OSError, ValueError, yaml.YAMLError):
            continue
        if doc.get("technique_id"):
            rows.append({"technique_id": str(doc["technique_id"]).upper(),
                         "name": doc.get("name") or fn, "file": fn, "doc": doc})
    cache.update({"dir": generate_dir, "rows": rows})
    return rows


_detection_index._cache = {}


def _detections_for(tid: str, generate_dir: str) -> List[Dict]:
    """Saved detections for a technique, its parent or its sub-techniques."""
    return [d for d in _detection_index(generate_dir) if _related(d["technique_id"], tid)]


def _evidence(step: Dict, captured: bool) -> str:
    """
    Lower-cased text a detection's indicators are sought in: the captured logs when there are any,
    always alongside the command the step ran. check._found expects a lower-cased haystack.
    """
    parts = [step.get("command") or ""]
    if captured:
        from archer.telemetry import datasets as ds

        values = ds.values() or {}
        did = step.get("recorded")
        for by_type in ([values[did]] if did in values else []):
            for fields in by_type.values():
                for vs in fields.values():
                    parts.extend(vs)
    return "\n".join(parts).lower()


def check_operation(manifest: Dict, generate_dir: str) -> Dict:
    """
    Per technique: do any saved detection's indicators appear in what its steps left — the captured
    logs if any, else the commands? Static; the query's other conditions are not evaluated.
    """
    from archer.telemetry.check import _found, indicators_of

    captured = bool(manifest.get("captured"))
    by_tid: Dict[str, List[Dict]] = defaultdict(list)
    for s in manifest.get("steps") or []:
        if s.get("technique_id"):
            by_tid[s["technique_id"].upper()].append(s)

    names = _name_lookup(sorted(by_tid), generate_dir)
    techniques, matched, missed, no_detections = [], 0, 0, 0
    for tid in sorted(by_tid):
        steps = by_tid[tid]
        haystacks = [(s, _evidence(s, captured)) for s in steps]
        detections, unmatched = [], []
        dets = _detections_for(tid, generate_dir)
        for d in dets:
            hits, matched_any = [], False
            for _, hay in haystacks:
                for _, value in indicators_of(d["doc"]):
                    if _found(value, hay):
                        hits.append({"value": value})
                        matched_any = True
            # de-duplicate hit values while keeping them in order
            seen, uniq = set(), []
            for h in hits:
                if h["value"] not in seen:
                    seen.add(h["value"])
                    uniq.append(h)
            detections.append({"name": d["name"], "file": d["file"], "matched": matched_any, "hits": uniq})

        for s, hay in haystacks:
            if not any(_found(v, hay) for d in dets for _, v in indicators_of(d["doc"])):
                unmatched.append({"host": s.get("host") or s.get("paw") or "", "command": s.get("command") or ""})

        if not dets:
            status = "no_detections"
            no_detections += 1
        elif any(d["matched"] for d in detections):
            status = "matched"
            matched += 1
        else:
            status = "missed"
            missed += 1
        techniques.append({"technique_id": tid, "technique_name": names.get(tid, tid), "status": status,
                           "detections": detections, "unmatched_commands": unmatched})

    return {"operation": manifest.get("name") or "", "evidence": "captured logs" if captured else "commands",
            "summary": {"techniques": len(techniques), "matched": matched, "missed": missed,
                        "no_detections": no_detections},
            "techniques": techniques}


def _name_lookup(tids: List[str], generate_dir: str) -> Dict[str, str]:
    """technique_id -> ATT&CK name, falling back to the id when the matrix isn't loaded."""
    from archer.telemetry.planner import _resolve

    out = {}
    for t in _resolve("technique", " ".join(tids), generate_dir):
        out[t["technique_id"].upper()] = t.get("technique_name") or t["technique_id"]
    return out


# --------------------------------------------------------------------------- correlations

def _window_seconds(query: str) -> int:
    """Seconds from a 'within Nh'/'within Nm'/'within Ns' in a correlation's query; default 1h."""
    import re

    m = re.search(r"within\s+(\d+)\s*([hms])", query or "", re.IGNORECASE)
    if not m:
        return 3600
    n, unit = int(m.group(1)), m.group(2).lower()
    return n * {"h": 3600, "m": 60, "s": 1}[unit]


def _correlations(generate_dir: str):
    """Every saved correlation across data/correlate/*.json, vendor and cross-vendor alike."""
    base = str(paths.DATA / "correlate")
    for fn in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        if not fn.endswith(".json") or fn.startswith("."):
            continue
        try:
            with open(os.path.join(base, fn), encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        for corr in (data.get("vendor_correlations") or []) + (data.get("cross_vendor_correlations") or []):
            yield fn, corr


def _part_detections(corr: Dict, generate_dir: str) -> List[Dict]:
    """A correlation's parts (a, then each of b) as detection rows, keeping their order."""
    b = corr.get("b")
    files = [corr.get("a")] + (b if isinstance(b, list) else [b])
    index = {d["file"]: d for d in _detection_index(generate_dir)}
    parts = []
    for p in files:
        if not p:
            continue
        row = index.get(os.path.basename(p))
        if row:
            parts.append(row)
    return parts


def check_correlations(manifest: Dict, generate_dir: str) -> Dict:
    """
    Each saved correlation whose parts' techniques all ran: did every part's detection match a
    step, on one host, within the correlation's window? Order is reported, not required.
    """
    from archer.telemetry.check import _found, indicators_of

    captured = bool(manifest.get("captured"))
    steps = [dict(s, _hay=_evidence(s, captured)) for s in (manifest.get("steps") or []) if s.get("technique_id")]

    results = []
    fired = half = missed = 0
    for fn, corr in _correlations(generate_dir):
        parts = _part_detections(corr, generate_dir)
        if len(parts) < 2:
            continue  # a correlation is a join of at least two detections
        # Testable only when every part's technique actually ran in this operation.
        if not all(any(_related(s["technique_id"], d["technique_id"]) for s in steps) for d in parts):
            continue

        window = _window_seconds(corr.get("combined_query") or "")
        # For each part, the steps (per host) whose evidence its indicators appear in.
        per_host_matches: Dict[str, List[Dict]] = defaultdict(list)
        part_hosts: List[set] = []
        part_techs = []
        for d in parts:
            part_techs.append(d["technique_id"])
            hosts = set()
            for s in steps:
                if not _related(s["technique_id"], d["technique_id"]):
                    continue
                if any(_found(v, s["_hay"]) for _, v in indicators_of(d["doc"])):
                    host = s.get("host") or s.get("paw") or ""
                    per_host_matches[host].append({"tid": d["technique_id"], "step": s})
                    hosts.add(host)
            part_hosts.append(hosts)

        # The best host is the one where the most parts matched; ties broken by the tightest span.
        best = _best_host(parts, part_hosts, per_host_matches, steps)
        matched_count = best["matched"]
        missing = [parts[i]["technique_id"] for i, hs in enumerate(best["per_part"]) if not hs]

        if matched_count == len(parts) and best["host"] and best["span"] is not None and best["span"] <= window:
            status = "fired"
            fired += 1
        elif matched_count > 0:
            status = "half_fired"
            half += 1
        else:
            status = "missed"
            missed += 1

        results.append({"file": corr.get("file") or fn, "target": corr.get("group") or _stem(fn),
                        "vendor": corr.get("vendor") or "", "status": status,
                        "techniques": part_techs, "order": best["order"], "host": best["host"] or "",
                        "span_seconds": best["span"] if best["span"] is not None else 0,
                        "window_seconds": window, "missing": missing})

    return {"summary": {"testable": len(results), "fired": fired, "half_fired": half, "missed": missed},
            "correlations": results}


def _best_host(parts, part_hosts, per_host_matches, steps) -> Dict:
    """
    The host that satisfies the most of the correlation's parts, with the tightest time span when
    there's a tie. Returns which parts matched there, the order they ran in and the span.
    """
    candidate_hosts = set().union(*part_hosts) if part_hosts else set()
    best = {"host": "", "matched": 0, "span": None, "order": [], "per_part": [set()] * len(parts)}
    for host in candidate_hosts or {""}:
        per_part = [host in hs for hs in part_hosts]
        matched = sum(per_part)
        if matched == 0:
            continue
        times = [_parse_time(m["step"].get("decide")) or _parse_time(m["step"].get("finish"))
                 for m in per_host_matches.get(host, [])]
        times = [t for t in times if t]
        span = int((max(times) - min(times)).total_seconds()) if len(times) >= 2 else 0
        order = _order_on_host(per_host_matches.get(host, []))
        better = matched > best["matched"] or (matched == best["matched"] and best["span"] is not None and span < best["span"])
        if best["span"] is None or better:
            best = {"host": host, "matched": matched, "span": span, "order": order,
                    "per_part": [{host} if ok else set() for ok in per_part]}
    return best


def _order_on_host(matches: List[Dict]) -> List[str]:
    """The techniques that matched on a host, earliest decision first (reported, not required)."""
    ranked = sorted(matches, key=lambda m: _parse_time(m["step"].get("decide")) or datetime.min.replace(tzinfo=timezone.utc))
    out = []
    for m in ranked:
        if m["tid"] not in out:
            out.append(m["tid"])
    return out


# --------------------------------------------------------------------------- time helpers

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value) -> Optional[datetime]:
    """A CALDERA timestamp (ISO 8601, with or without timezone) as an aware datetime, or None."""
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(str(value).strip(), fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _stem(filename: str) -> str:
    return filename[:-5] if filename.endswith(".json") else filename
