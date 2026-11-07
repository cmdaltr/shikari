#!/usr/bin/env python3
"""
shikari: Shikari's one command. start | stop | restart | status | logs run Shikari (and
Ollama) in the background under a supervisor that restarts them when they crash; console,
preview, mcp and offline hand over to the tools in shikari/cli and shikari/mcp_server.py.

Standard library only, and the shikari package loads nothing until it's used, so stop and
status work even when the app is broken: as a file (./bin/shikari runs python shikari/service.py)
or as shikari.service (the pip-installed shikari).

    shikari start [--port 32453] [--no-reload] [--no-ollama] [--ollama-models DIR] [--skip-index]
    shikari stop
    shikari restart [same options as start]
    shikari status
    shikari logs [shikari|ollama|supervisor] [-f] [-n 100]
    shikari run [options]          supervise in the foreground (Ctrl+C stops everything)
    shikari serve [--port N]       the server in the foreground, no supervisor
    shikari clear-cache            clear server-side caches and reset browser preferences
    shikari console                the interactive console (modules, options, run)
    shikari preview <group> [...]  a group's queries on stdout, no files written
    shikari mcp                    Shikari's tools for an MCP client, over stdio
    shikari offline <command>      generate | correlate | hunt | emulate without the server
    shikari install [--system]     put `shikari` on your PATH (~/.local/bin; --system: /usr/local/bin)
    shikari app install [--dock]   Shikari as a desktop app (Dock, Start menu, app menu); see shikari/desktop.py
    shikari docker <args>          docker compose with the project's docker-compose.yml

Options given to start or restart are remembered in settings.json in the state directory:
~/Library/Application Support/Shikari (macOS) or $XDG_STATE_HOME/shikari (Linux), or
$SHIKARI_STATE_DIR. Logs go to ~/Library/Logs/Shikari (macOS) or <state dir>/logs. Neither is
in the repository: the repository can sit in a synced folder (OneDrive), which replaces
files open for writing and kills the processes writing them.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent


def _state_dirs():
    base = os.environ.get("SHIKARI_STATE_DIR")
    if base:
        return Path(base).expanduser() / "run", Path(base).expanduser() / "logs"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Shikari", Path.home() / "Library" / "Logs" / "Shikari"
    state = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "shikari"
    return state / "run", state / "logs"


RUN_DIR, LOG_DIR = _state_dirs()
LEGACY_RUN_DIR = ROOT / "data" / "run"  # before 2026-10-12: inside the repository
PID_FILE = RUN_DIR / "supervisor.pid"
STATE_FILE = RUN_DIR / "service.json"
SETTINGS_FILE = RUN_DIR / "settings.json"
LOG_ROTATE_BYTES = 20 * 1024 * 1024

DEFAULTS = {"host": "0.0.0.0", "port": 32453, "reload": True, "ollama": True, "ollama_models": ""}
OLLAMA_URL = "http://127.0.0.1:11434"
# Ollama's default 4k context silently truncates agent conversations (a single tool result can be
# 5k tokens); 16k costs ~2 GB more memory per loaded 8B model
OLLAMA_CONTEXT = "16384"
OLLAMA_CANDIDATES = ["/opt/homebrew/bin/ollama", "/usr/local/bin/ollama", "/Applications/Ollama.app/Contents/Resources/ollama"]

# A child that dies within QUICK_EXIT seconds of starting counts as a failed start; after
# MAX_QUICK_EXITS in a row the supervisor gives up (a port clash or broken install won't fix itself).
QUICK_EXIT = 60
MAX_QUICK_EXITS = 6
BACKOFF_MAX = 60


def python():
    venv = ROOT / ".venv" / "bin" / "python"
    return str(venv) if venv.exists() else sys.executable


def read_json(path, default=None):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(path)


def pid_alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def supervisor_pid():
    try:
        pid = int(PID_FILE.read_text().strip())
    except (OSError, ValueError):
        return None
    return pid if pid_alive(pid) else None


def http_ok(url, timeout=3):
    try:
        with urlopen(url, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def port_free(port, host="0.0.0.0"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
        except OSError:
            return False
    return True


def listeners(port):
    """PIDs listening on the port (lsof), with their command lines."""
    try:
        out = subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
                             capture_output=True, text=True).stdout
    except FileNotFoundError:
        return []
    result = []
    for pid in {int(p) for p in out.split() if p.isdigit()}:
        cmd = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True).stdout.strip()
        result.append((pid, cmd))
    return result


def ollama_binary():
    found = shutil.which("ollama")
    if found:
        return found
    return next((c for c in OLLAMA_CANDIDATES if os.access(c, os.X_OK)), None)


def ollama_models_dir(setting):
    """
    The models folder to give Ollama, or None for its default (~/.ollama/models).
    A folder on an external volume that isn't mounted would otherwise be created on the
    boot disk under /Volumes, and Ollama would start with no models.
    """
    path = setting or os.environ.get("OLLAMA_MODELS", "")
    if not path:
        return None, ""
    p = Path(path).expanduser()
    if p.is_dir():
        return str(p), ""
    parts = p.parts
    if len(parts) > 2 and parts[1] == "Volumes" and not Path("/", "Volumes", parts[2]).is_dir():
        return None, f"volume {parts[2]!r} isn't mounted; using Ollama's default models folder"
    return None, f"{p} doesn't exist; using Ollama's default models folder"


def ago(seconds):
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s" if m else f"{s}s"


def open_log(name):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    path = LOG_DIR / f"{name}.log"
    if path.exists() and path.stat().st_size > LOG_ROTATE_BYTES:
        path.replace(path.with_suffix(".log.1"))
    return open(path, "a", buffering=1)


def log(msg):
    """The supervisor's log line. A failed write must never stop the supervisor: reopen and carry on."""
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}"
    for _ in range(2):
        try:
            print(line, flush=True)
            return
        except (OSError, ValueError):
            try:
                sys.stdout = open_log("supervisor")
            except OSError:
                return


# --- supervisor -------------------------------------------------------------------------------

class Child:
    def __init__(self, name, cmd, env=None, note=""):
        self.name, self.cmd, self.env, self.note = name, cmd, env, note
        self.proc = None
        self.started = 0.0
        self.restarts = 0
        self.quick_exits = 0
        self.next_start = 0.0
        self.last_exit = None
        self.failed = False

    def start(self):
        out = open_log(self.name)
        out.write(f"\n--- {datetime.now():%Y-%m-%d %H:%M:%S} starting: {' '.join(self.cmd)}\n")
        # Own process group, so stopping it also stops uvicorn's reloader worker
        self.proc = subprocess.Popen(self.cmd, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT,
                                     env=self.env, start_new_session=True)
        out.close()
        self.started = time.time()
        log(f"{self.name}: started (pid {self.proc.pid})")

    def check(self):
        """Restart the child if it has exited. Returns False once it has failed for good."""
        if self.failed:
            return False
        if self.proc is None:
            if time.time() >= self.next_start:
                self.start()
            return True
        code = self.proc.poll()
        if code is None:
            if self.quick_exits and time.time() - self.started > QUICK_EXIT:
                self.quick_exits = 0
            return True
        ran = time.time() - self.started
        self.last_exit = {"code": code, "at": time.time(), "ran": round(ran)}
        self.proc = None
        self.quick_exits = self.quick_exits + 1 if ran < QUICK_EXIT else 0
        if self.quick_exits >= MAX_QUICK_EXITS:
            self.failed = True
            log(f"{self.name}: exited {code} after {ago(ran)}; {MAX_QUICK_EXITS} failed starts in a row, giving up")
            return False
        delay = min(BACKOFF_MAX, 2 ** self.quick_exits) if self.quick_exits else 1
        self.restarts += 1
        self.next_start = time.time() + delay
        log(f"{self.name}: exited {code} after {ago(ran)}; restarting in {delay}s (restart {self.restarts})")
        return True

    def stop(self):
        if not self.proc or self.proc.poll() is not None:
            return
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait()
        log(f"{self.name}: stopped")

    def state(self):
        return {"pid": self.proc.pid if self.proc and self.proc.poll() is None else None,
                "started": self.started, "restarts": self.restarts, "last_exit": self.last_exit,
                "failed": self.failed, "note": self.note, "cmd": self.cmd}


def build_osint_index(py):
    """Refresh the OSINT technique index if it's missing or a day old (non-fatal; see DEPLOY.md)."""
    index = ROOT / "data" / "cache" / "osint_technique_index.json"
    script = ROOT / "scripts" / "data" / "build_osint_index.py"
    if not script.exists():
        return
    try:
        generated = datetime.fromisoformat(read_json(index, {})["generated_at"].rstrip("Z"))
        if (datetime.utcnow() - generated).total_seconds() < 24 * 3600:
            return
    except (KeyError, TypeError, ValueError):
        pass
    log("building the OSINT technique index (missing or stale)")
    try:
        r = subprocess.run([py, str(script), "--skip-clone"], cwd=ROOT, capture_output=True, text=True, timeout=120)
        log("OSINT technique index ready" if r.returncode == 0 else f"OSINT index build failed: {r.stderr[-300:]}")
    except Exception as e:
        log(f"OSINT index build failed: {e}")


def supervise(settings, skip_index=False):
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))
    stopping = []
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda *_: stopping.append(True))

    py = python()
    children = []

    if settings["ollama"]:
        binary = ollama_binary()
        if http_ok(f"{OLLAMA_URL}/api/tags"):
            log("ollama: already running, not managed by shikari")
        elif not binary:
            log("ollama: not installed, skipping")
        else:
            models, warning = ollama_models_dir(settings.get("ollama_models"))
            if warning:
                log(f"ollama: {warning}")
            env = dict(os.environ)
            if models:
                env["OLLAMA_MODELS"] = models
            else:
                env.pop("OLLAMA_MODELS", None)
            env.setdefault("OLLAMA_CONTEXT_LENGTH", OLLAMA_CONTEXT)
            children.append(Child("ollama", [binary, "serve"], env, note=models or "~/.ollama/models (default)"))

    if not skip_index:
        build_osint_index(py)

    # Keep-alive longer than any poll interval (see shikari.app's __main__)
    cmd = [py, "-m", "uvicorn", "shikari.app:app", "--host", settings["host"], "--port", str(settings["port"]),
           "--timeout-keep-alive", "75"]
    if settings["reload"]:
        cmd.append("--reload")
    children.append(Child("shikari", cmd))

    def save(status):
        write_json(STATE_FILE, {"status": status, "supervisor": os.getpid(), "since": since,
                                "settings": settings, "children": {c.name: c.state() for c in children}})

    since = time.time()
    log(f"supervisor: started (pid {os.getpid()})")
    last = None
    try:
        while not stopping:
            try:
                ok = all(c.check() for c in children if c.name == "shikari")
                for c in children:
                    if c.name != "shikari":
                        c.check()
                snapshot = json.dumps([c.state() for c in children], default=str)
                if snapshot != last:
                    save("running")
                    last = snapshot
            except Exception as e:
                # Whatever went wrong (a state file it couldn't write), keep supervising
                log(f"supervisor: {e.__class__.__name__}: {e}")
                ok = True
            if not ok:
                break
            time.sleep(1)
    finally:
        failed = any(c.failed for c in children if c.name == "shikari")
        for c in reversed(children):
            c.stop()
        save("failed" if failed else "stopped")
        try:
            if PID_FILE.read_text().strip() == str(os.getpid()):
                PID_FILE.unlink()
        except OSError:
            pass
        log("supervisor: stopped")
    return 1 if failed else 0


# --- commands ---------------------------------------------------------------------------------

def load_settings(args=None):
    if not SETTINGS_FILE.exists() and (LEGACY_RUN_DIR / "settings.json").exists():
        write_json(SETTINGS_FILE, read_json(LEGACY_RUN_DIR / "settings.json", {}))
    settings = {**DEFAULTS, **read_json(SETTINGS_FILE, {})}
    if args is not None:
        if args.port:
            settings["port"] = args.port
        if args.host:
            settings["host"] = args.host
        if args.reload is not None:
            settings["reload"] = args.reload
        if args.ollama is not None:
            settings["ollama"] = args.ollama
        if args.ollama_models is not None:
            settings["ollama_models"] = args.ollama_models
        write_json(SETTINGS_FILE, settings)
    return settings


def cmd_start(args):
    if supervisor_pid():
        print(f"Shikari is already running (supervisor pid {supervisor_pid()}). Use: shikari restart")
        return 0
    settings = load_settings(args)
    port = settings["port"]
    if not port_free(port, settings["host"]):
        print(f"Port {port} is in use:")
        for pid, cmd in listeners(port):
            print(f"  pid {pid}: {cmd[:100]}")
        print("Stop it first (shikari stop --force stops an Shikari started another way), or use --port.")
        return 1
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [python(), str(Path(__file__).resolve()), "run"] + (["--skip-index"] if args.skip_index else [])
    with open_log("supervisor") as out:
        proc = subprocess.Popen(cmd, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
    print(f"Starting Shikari on port {port}", end="", flush=True)
    url = f"http://127.0.0.1:{port}/health"
    deadline = time.time() + (180 if not args.skip_index else 90)
    while time.time() < deadline:
        if http_ok(url, timeout=2):
            print(f"\nShikari is up: http://127.0.0.1:{port}")
            show_ollama(read_json(STATE_FILE, {}))
            return 0
        if proc.poll() is not None:
            print(f"\nThe supervisor exited ({proc.returncode}). See: shikari logs supervisor")
            return 1
        print(".", end="", flush=True)
        time.sleep(1)
    print("\nStill starting; the supervisor will keep trying. Check with: shikari status  (logs: shikari logs)")
    return 0


def cmd_run(args):
    if supervisor_pid() and supervisor_pid() != os.getpid():
        print(f"Shikari is already running (supervisor pid {supervisor_pid()})")
        return 1
    return supervise(load_settings(args if any_option(args) else None), skip_index=args.skip_index)


def any_option(args):
    return any(getattr(args, k, None) is not None for k in ("port", "host", "reload", "ollama", "ollama_models"))


def cmd_stop(args):
    pid = supervisor_pid()
    if pid:
        os.kill(pid, signal.SIGTERM)
        print("Stopping Shikari", end="", flush=True)
        for _ in range(40):
            if not pid_alive(pid):
                print("\nStopped.")
                return 0
            print(".", end="", flush=True)
            time.sleep(0.5)
        print(f"\nThe supervisor (pid {pid}) didn't stop; killing it.")
        os.kill(pid, signal.SIGKILL)
        state = read_json(STATE_FILE, {})
        for child in state.get("children", {}).values():
            if child.get("pid") and pid_alive(child["pid"]):
                try:
                    os.killpg(child["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
        return 0

    port = load_settings()["port"]
    stray = [(p, c) for p, c in listeners(port) if "shikari.app" in c]
    if not stray:
        print("Shikari isn't running.")
        return 0
    if not args.force:
        print(f"Shikari is running on port {port} but wasn't started with `shikari start`:")
        for p, c in stray:
            print(f"  pid {p}: {c[:100]}")
        print("Stop it with: shikari stop --force")
        return 1
    for p, _ in stray:
        try:
            os.killpg(os.getpgid(p), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            os.kill(p, signal.SIGTERM)
    time.sleep(2)
    print("Stopped." if not listeners(port) else "Some processes are still listening; check with: shikari status")
    return 0


def cmd_restart(args):
    cmd_stop(argparse.Namespace(force=True))
    time.sleep(1)
    return cmd_start(args)


def show_ollama(state):
    child = (state.get("children") or {}).get("ollama")
    up = http_ok(f"{OLLAMA_URL}/api/tags", timeout=2)
    if child:
        line = f"Ollama   {'running' if up else 'down'}   managed, models: {child.get('note')}"
        if child.get("restarts"):
            line += f", restarts: {child['restarts']}"
        print(line)
    else:
        print(f"Ollama   {'running (not managed by shikari)' if up else 'not running'}")


def cmd_status(args):
    pid = supervisor_pid()
    state = read_json(STATE_FILE, {}) if pid else {}
    settings = state.get("settings") or load_settings()
    port = settings["port"]
    healthy = http_ok(f"http://127.0.0.1:{port}/health")
    shikari = (state.get("children") or {}).get("shikari", {})

    if pid:
        line = f"Shikari   {'running' if healthy else 'starting or not responding'}   http://127.0.0.1:{port}"
        if shikari.get("pid"):
            line += f"   pid {shikari['pid']}, up {ago(time.time() - shikari['started'])}"
        print(line)
        if shikari.get("restarts"):
            last = shikari.get("last_exit") or {}
            when = datetime.fromtimestamp(last["at"]).strftime("%d %b %H:%M") if last.get("at") else "?"
            print(f"         restarted {shikari['restarts']}x after crashes (last: exit {last.get('code')} at {when})")
        print(f"         reload {'on' if settings['reload'] else 'off'}, supervisor pid {pid}")
    elif healthy:
        print(f"Shikari   running on port {port}, but not under `shikari start` (no crash restarts)")
    else:
        last = read_json(STATE_FILE, {})
        print("Shikari   stopped" + ("   (gave up after repeated crashes; see: shikari logs)" if last.get("status") == "failed" else ""))
    show_ollama(state)
    print(f"Logs     {LOG_DIR}/shikari.log  (shikari logs -f)")
    return 0 if healthy else 1


def cmd_logs(args):
    path = LOG_DIR / f"{args.name}.log"
    if not path.exists():
        print(f"No log yet: {path}")
        return 1
    tail = ["tail", "-n", str(args.lines)] + (["-F"] if args.follow else []) + [str(path)]
    os.execvp("tail", tail)


def cmd_install(args):
    # --system installs to a shared dir on everyone's PATH (needs root); otherwise a per-user bin dir.
    if args.system:
        target_dir = Path("/usr/local/bin")
    else:
        target_dir = Path.home() / ".local" / "bin"
        if str(target_dir) not in os.environ.get("PATH", "").split(os.pathsep):
            print(f"Add {target_dir} to your PATH (e.g. in ~/.zshrc): export PATH=\"$HOME/.local/bin:$PATH\"")
    link = target_dir / "shikari"
    source = ROOT / "bin" / "shikari"
    old = target_dir / "shikari-cli"  # the name from 2026-10-17 until the rename back to `shikari`
    retry = "shikari install" + (" --system" if args.system else "")
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        # Clear the previous `shikari-cli` symlink: it points at the old root launcher, now moved (dangling).
        if old.is_symlink() and (not old.exists() or old.resolve() == source.resolve()):
            old.unlink()
            print(f"Removed the old name: {old}")
        if link.is_symlink() or link.exists():
            if link.is_symlink() and link.resolve() == source.resolve():
                print(f"Already installed: {link} -> {source}")
                return 0
            if not args.force:
                print(f"{link} already exists. Replace it with: {retry} --force")
                return 1
            link.unlink()
        link.symlink_to(source)
    except PermissionError:
        # /usr/local/bin and other shared dirs need root; point the user at the one sudo command.
        print(f"Permission denied writing {link} — {target_dir} needs elevated rights.")
        print(f"Re-run with sudo:\n  sudo ln -sf \"{source}\" \"{link}\"")
        return 1
    print(f"Installed: {link} -> {source}")
    found = shutil.which("shikari")
    if found and Path(found) != link:
        print(f"Note: {found} comes earlier in your PATH and will run instead. Remove it or reorder PATH.")
    return 0


def cmd_docker(args):
    os.execvp("docker", ["docker", "compose", "-f", str(ROOT / "docker-compose.yml")] + args.args)


# command -> (module whose main() runs it, whether the command name stays in its argv)
HANDOVER = {
    "serve": ("shikari.app", False),
    "clear-cache": ("shikari.app", True),
    "console": ("shikari.cli.console", False),
    "preview": ("shikari.cli.preview", False),
    "mcp": ("shikari.mcp_server", False),
    "offline": ("shikari.cli.offline", False),
    "test": ("shikari.cli.test_data", False),
    "app": ("shikari.desktop", False),
    "caldera": ("shikari.cli.caldera", False),
}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in HANDOVER:
        # Commands that need the shikari package run in a fresh interpreter, so this file stays
        # importable (and stop/status keep working) when the app is broken
        module, keep_name = HANDOVER[argv[0]]
        rest = argv if keep_name else argv[1:]
        prog = "shikari" if keep_name else f"shikari {argv[0]}"
        os.chdir(ROOT)
        os.execv(python(), [python(), "-c", f"import sys; sys.path.insert(0, {str(ROOT)!r}); from {module} import main; "
                            f"sys.argv = [{prog!r}] + sys.argv[1:]; main()"] + rest)

    parser = argparse.ArgumentParser(prog="shikari", description="Shikari's command line: the server, the console and the pipeline.")
    sub = parser.add_subparsers(dest="command")

    def server_options(p):
        p.add_argument("--port", type=int, help="port (default 32453; remembered)")
        p.add_argument("--host", help="bind address (default 0.0.0.0; remembered)")
        p.add_argument("--reload", dest="reload", action="store_true", default=None, help="restart on code changes (default)")
        p.add_argument("--no-reload", dest="reload", action="store_false", help="don't restart on code changes")
        p.add_argument("--ollama", dest="ollama", action="store_true", default=None, help="start and supervise Ollama if it isn't running (default)")
        p.add_argument("--no-ollama", dest="ollama", action="store_false", help="leave Ollama alone")
        p.add_argument("--ollama-models", metavar="DIR", help="OLLAMA_MODELS folder for the Ollama shikari starts ('' = Ollama's default)")
        p.add_argument("--skip-index", action="store_true", help="don't refresh the OSINT technique index first")

    server_options(sub.add_parser("start", help="start in the background"))
    server_options(sub.add_parser("restart", help="stop, then start"))
    server_options(sub.add_parser("run", help="supervise in the foreground"))
    sub.add_parser("stop", help="stop Shikari (and the Ollama it started)").add_argument(
        "--force", action="store_true", help="also stop an Shikari that wasn't started with `shikari start`")
    sub.add_parser("status", help="show what's running")
    logs = sub.add_parser("logs", help="show a log")
    logs.add_argument("name", nargs="?", default="shikari", choices=["shikari", "ollama", "supervisor"])
    logs.add_argument("-f", "--follow", action="store_true")
    logs.add_argument("-n", "--lines", type=int, default=100)
    install = sub.add_parser("install", help="put `shikari` on your PATH")
    install.add_argument("--force", action="store_true")
    install.add_argument("--system", action="store_true",
                         help="install to /usr/local/bin for all users (needs sudo) instead of a per-user bin dir")
    docker = sub.add_parser("docker", help="docker compose with the project's compose file")
    docker.add_argument("args", nargs=argparse.REMAINDER)
    parser.epilog = ("Also: serve [--port N] (foreground, no supervisor) · clear-cache · console (interactive) · "
                     "preview <group> · mcp (MCP server on stdio) · offline generate|correlate|hunt|emulate · "
                     "caldera provision|enrol|list (provision + enrol CALDERA agents) · "
                     "test populate|depopulate|status (sample data for a guided tour) · "
                     "app install|uninstall|open (a desktop app with a Dock / Start menu entry)")

    args = parser.parse_args(argv)
    commands = {"start": cmd_start, "stop": cmd_stop, "restart": cmd_restart, "status": cmd_status,
                "logs": cmd_logs, "run": cmd_run, "install": cmd_install, "docker": cmd_docker}
    if not args.command:
        parser.print_help()
        return 0
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
