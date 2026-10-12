#!/usr/bin/env python3
"""
archer start | stop | restart | status | logs: run Archer (and Ollama) in the background
under a supervisor that restarts them when they crash.

Run as a file (python archer/service.py ...), not as archer.service: importing the archer
package loads the whole app, and stop/status should work even when the app is broken.
Standard library only.

    archer start [--port 8000] [--no-reload] [--no-ollama] [--ollama-models DIR] [--skip-index]
    archer stop
    archer restart [same options as start]
    archer status
    archer logs [archer|ollama|supervisor] [-f] [-n 100]
    archer run [options]          supervise in the foreground (Ctrl+C stops everything)
    archer install                put `archer` on your PATH (~/bin, or ~/.local/bin)
    archer docker <args>          docker compose with the project's docker-compose.yml

Options given to start or restart are remembered in data/run/settings.json.
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
RUN_DIR = ROOT / "data" / "run"
LOG_DIR = ROOT / "logs"
PID_FILE = RUN_DIR / "supervisor.pid"
STATE_FILE = RUN_DIR / "service.json"
SETTINGS_FILE = RUN_DIR / "settings.json"
LOG_ROTATE_BYTES = 20 * 1024 * 1024

DEFAULTS = {"host": "0.0.0.0", "port": 8000, "reload": True, "ollama": True, "ollama_models": ""}
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
    LOG_DIR.mkdir(exist_ok=True)
    path = LOG_DIR / f"{name}.log"
    if path.exists() and path.stat().st_size > LOG_ROTATE_BYTES:
        path.replace(path.with_suffix(".log.1"))
    return open(path, "a", buffering=1)


def log(msg):
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}", flush=True)


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
            log("ollama: already running, not managed by archer")
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

    cmd = [py, "-m", "uvicorn", "archer.app:app", "--host", settings["host"], "--port", str(settings["port"])]
    if settings["reload"]:
        cmd.append("--reload")
    children.append(Child("archer", cmd))

    def save(status):
        write_json(STATE_FILE, {"status": status, "supervisor": os.getpid(), "since": since,
                                "settings": settings, "children": {c.name: c.state() for c in children}})

    since = time.time()
    log(f"supervisor: started (pid {os.getpid()})")
    last = None
    try:
        while not stopping:
            ok = all(c.check() for c in children if c.name == "archer")
            for c in children:
                if c.name != "archer":
                    c.check()
            snapshot = json.dumps([c.state() for c in children], default=str)
            if snapshot != last:
                save("running")
                last = snapshot
            if not ok:
                break
            time.sleep(1)
    finally:
        failed = any(c.failed for c in children if c.name == "archer")
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
        print(f"Archer is already running (supervisor pid {supervisor_pid()}). Use: archer restart")
        return 0
    settings = load_settings(args)
    port = settings["port"]
    if not port_free(port, settings["host"]):
        print(f"Port {port} is in use:")
        for pid, cmd in listeners(port):
            print(f"  pid {pid}: {cmd[:100]}")
        print("Stop it first (archer stop --force stops an Archer started another way), or use --port.")
        return 1
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [python(), str(Path(__file__).resolve()), "run"] + (["--skip-index"] if args.skip_index else [])
    with open_log("supervisor") as out:
        proc = subprocess.Popen(cmd, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
    print(f"Starting Archer on port {port}", end="", flush=True)
    url = f"http://127.0.0.1:{port}/health"
    deadline = time.time() + (180 if not args.skip_index else 90)
    while time.time() < deadline:
        if http_ok(url, timeout=2):
            print(f"\nArcher is up: http://127.0.0.1:{port}")
            show_ollama(read_json(STATE_FILE, {}))
            return 0
        if proc.poll() is not None:
            print(f"\nThe supervisor exited ({proc.returncode}). See: archer logs supervisor")
            return 1
        print(".", end="", flush=True)
        time.sleep(1)
    print("\nStill starting; the supervisor will keep trying. Check with: archer status  (logs: archer logs)")
    return 0


def cmd_run(args):
    if supervisor_pid() and supervisor_pid() != os.getpid():
        print(f"Archer is already running (supervisor pid {supervisor_pid()})")
        return 1
    return supervise(load_settings(args if any_option(args) else None), skip_index=args.skip_index)


def any_option(args):
    return any(getattr(args, k, None) is not None for k in ("port", "host", "reload", "ollama", "ollama_models"))


def cmd_stop(args):
    pid = supervisor_pid()
    if pid:
        os.kill(pid, signal.SIGTERM)
        print("Stopping Archer", end="", flush=True)
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
    stray = [(p, c) for p, c in listeners(port) if "archer.app" in c]
    if not stray:
        print("Archer isn't running.")
        return 0
    if not args.force:
        print(f"Archer is running on port {port} but wasn't started with `archer start`:")
        for p, c in stray:
            print(f"  pid {p}: {c[:100]}")
        print("Stop it with: archer stop --force")
        return 1
    for p, _ in stray:
        try:
            os.killpg(os.getpgid(p), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            os.kill(p, signal.SIGTERM)
    time.sleep(2)
    print("Stopped." if not listeners(port) else "Some processes are still listening; check with: archer status")
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
        print(f"Ollama   {'running (not managed by archer)' if up else 'not running'}")


def cmd_status(args):
    pid = supervisor_pid()
    state = read_json(STATE_FILE, {}) if pid else {}
    settings = state.get("settings") or load_settings()
    port = settings["port"]
    healthy = http_ok(f"http://127.0.0.1:{port}/health")
    archer = (state.get("children") or {}).get("archer", {})

    if pid:
        line = f"Archer   {'running' if healthy else 'starting or not responding'}   http://127.0.0.1:{port}"
        if archer.get("pid"):
            line += f"   pid {archer['pid']}, up {ago(time.time() - archer['started'])}"
        print(line)
        if archer.get("restarts"):
            last = archer.get("last_exit") or {}
            when = datetime.fromtimestamp(last["at"]).strftime("%d %b %H:%M") if last.get("at") else "?"
            print(f"         restarted {archer['restarts']}x after crashes (last: exit {last.get('code')} at {when})")
        print(f"         reload {'on' if settings['reload'] else 'off'}, supervisor pid {pid}")
    elif healthy:
        print(f"Archer   running on port {port}, but not under `archer start` (no crash restarts)")
    else:
        last = read_json(STATE_FILE, {})
        print("Archer   stopped" + ("   (gave up after repeated crashes; see: archer logs)" if last.get("status") == "failed" else ""))
    show_ollama(state)
    print(f"Logs     {LOG_DIR}/archer.log  (archer logs -f)")
    return 0 if healthy else 1


def cmd_logs(args):
    path = LOG_DIR / f"{args.name}.log"
    if not path.exists():
        print(f"No log yet: {path}")
        return 1
    tail = ["tail", "-n", str(args.lines)] + (["-F"] if args.follow else []) + [str(path)]
    os.execvp("tail", tail)


def cmd_install(args):
    target_dir = next((Path.home() / d for d in ("bin", ".local/bin")
                       if str(Path.home() / d) in os.environ.get("PATH", "").split(os.pathsep)), None)
    if target_dir is None:
        target_dir = Path.home() / ".local" / "bin"
        print(f"Add {target_dir} to your PATH (e.g. in ~/.zshrc): export PATH=\"$HOME/.local/bin:$PATH\"")
    target_dir.mkdir(parents=True, exist_ok=True)
    link = target_dir / "archer"
    source = ROOT / "archer-cli"
    if link.is_symlink() or link.exists():
        if link.is_symlink() and link.resolve() == source.resolve():
            print(f"Already installed: {link} -> {source}")
            return 0
        if not args.force:
            print(f"{link} already exists. Replace it with: archer-cli install --force")
            return 1
        link.unlink()
    link.symlink_to(source)
    print(f"Installed: {link} -> {source}")
    found = shutil.which("archer")
    if found and Path(found) != link:
        print(f"Note: {found} comes earlier in your PATH and will run instead. Remove it or reorder PATH.")
    return 0


def cmd_docker(args):
    os.execvp("docker", ["docker", "compose", "-f", str(ROOT / "docker-compose.yml")] + args.args)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ("serve", "clear-cache"):
        # The app's own entry point: foreground server without supervision, or cache clearing
        os.chdir(ROOT)
        rest = argv[1:] if argv[0] == "serve" else argv
        os.execv(python(), [python(), "-c", "import sys; from archer.app import main; sys.argv = ['archer'] + sys.argv[1:]; main()"] + rest)

    parser = argparse.ArgumentParser(prog="archer", description="Run Archer in the background, restarting it if it crashes.")
    sub = parser.add_subparsers(dest="command")

    def server_options(p):
        p.add_argument("--port", type=int, help="port (default 8000; remembered)")
        p.add_argument("--host", help="bind address (default 0.0.0.0; remembered)")
        p.add_argument("--reload", dest="reload", action="store_true", default=None, help="restart on code changes (default)")
        p.add_argument("--no-reload", dest="reload", action="store_false", help="don't restart on code changes")
        p.add_argument("--ollama", dest="ollama", action="store_true", default=None, help="start and supervise Ollama if it isn't running (default)")
        p.add_argument("--no-ollama", dest="ollama", action="store_false", help="leave Ollama alone")
        p.add_argument("--ollama-models", metavar="DIR", help="OLLAMA_MODELS folder for the Ollama archer starts ('' = Ollama's default)")
        p.add_argument("--skip-index", action="store_true", help="don't refresh the OSINT technique index first")

    server_options(sub.add_parser("start", help="start in the background"))
    server_options(sub.add_parser("restart", help="stop, then start"))
    server_options(sub.add_parser("run", help="supervise in the foreground"))
    sub.add_parser("stop", help="stop Archer (and the Ollama it started)").add_argument(
        "--force", action="store_true", help="also stop an Archer that wasn't started with `archer start`")
    sub.add_parser("status", help="show what's running")
    logs = sub.add_parser("logs", help="show a log")
    logs.add_argument("name", nargs="?", default="archer", choices=["archer", "ollama", "supervisor"])
    logs.add_argument("-f", "--follow", action="store_true")
    logs.add_argument("-n", "--lines", type=int, default=100)
    sub.add_parser("install", help="put `archer` on your PATH").add_argument("--force", action="store_true")
    docker = sub.add_parser("docker", help="docker compose with the project's compose file")
    docker.add_argument("args", nargs=argparse.REMAINDER)
    parser.epilog = "Also: archer serve [--port N] (foreground, no supervisor), archer clear-cache"

    args = parser.parse_args(argv)
    commands = {"start": cmd_start, "stop": cmd_stop, "restart": cmd_restart, "status": cmd_status,
                "logs": cmd_logs, "run": cmd_run, "install": cmd_install, "docker": cmd_docker}
    if not args.command:
        parser.print_help()
        return 0
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
