"""
The desktop window on Windows on ARM64.

pywebview's Windows window loads WinForms through pythonnet. On the .NET Framework, pythonnet's
loader (clr_loader) needs a native shim that ships for x64 and x86 only, so a native ARM64 build
can't use it. On .NET (CoreCLR) it needs no shim, but needs the .NET Desktop Runtime, which
Windows doesn't include: install.ps1 downloads it on ARM64 (it isn't bundled, at ~55 MB), and
use_dotnet() finds it. Without it, or if that window fails, Archer opens in an Edge app window.

Edge is on every Windows 11 machine and is the same engine pywebview would have used (WebView2),
so an --app window (no tabs, no address bar) with its own profile looks and behaves the same, and
Python stays native rather than emulated, which is where Archer's time goes.

What pywebview's JS bridge did for the chooser, a loopback page does here: the chooser posts to
127.0.0.1 under a random path, so no other page can drive it. There's no Change Server menu; the
chooser shows whenever no server is saved or the saved one doesn't answer.
"""

import html
import json
import os
import platform
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# Swaps the chooser's pywebview.api calls for posts to the loopback page
BRIDGE = """<script>
const post = (what, body) => fetch(what, {method: 'POST', body: body || ''}).then(r => r.json());
window.pywebview = {api: {
  connect: u => post('connect', u).then(j => { if (j.url) { location.href = j.url; return ''; } return j.error; }),
  use_local: () => post('local').then(j => { if (j.url) location.href = j.url;
    else document.getElementById('error').textContent = j.error; }),
}};
</script>"""


def wanted() -> bool:
    if sys.platform != "win32" or os.environ.get("ARCHER_WINDOW") == "webview":
        return False
    return platform.machine().lower() in ("arm64", "aarch64") or os.environ.get("ARCHER_WINDOW") == "edge"


DESKTOP_RUNTIME = ("shared", "Microsoft.WindowsDesktop.App")
# Any .NET 8 or later Desktop Runtime: WinForms comes with it
RUNTIME_CONFIG = {"runtimeOptions": {"tfm": "net8.0", "rollForward": "LatestMajor",
                                     "framework": {"name": "Microsoft.WindowsDesktop.App", "version": "8.0.0"}}}


def dotnet_root() -> Optional[Path]:
    """Where a .NET with the Desktop Runtime is: DOTNET_ROOT, the machine-wide install, or the
    per-user one install.ps1 makes."""
    for base in (os.environ.get("DOTNET_ROOT"), os.path.join(os.environ.get("ProgramFiles") or "", "dotnet"),
                 os.path.join(os.environ.get("LOCALAPPDATA") or "", "Microsoft", "dotnet")):
        if not base:
            continue
        runtimes = Path(base).joinpath(*DESKTOP_RUNTIME)
        if runtimes.is_dir() and any(v.name.split(".")[0].isdigit() and int(v.name.split(".")[0]) >= 8
                                     for v in runtimes.iterdir()):
            return Path(base)
    return None


def use_dotnet(home: Path) -> bool:
    """Load pythonnet on .NET's Desktop Runtime, so pywebview's window works on ARM64. False when
    it isn't installed, Edge was asked for, or it won't load."""
    if os.environ.get("ARCHER_WINDOW") == "edge":
        return False
    root = dotnet_root()
    if root is None:
        print("No .NET Desktop Runtime: opening Archer in Edge")
        return False
    try:
        import pythonnet

        config = home / "archer.runtimeconfig.json"
        config.write_text(json.dumps(RUNTIME_CONFIG))
        os.environ["DOTNET_ROOT"] = str(root)
        os.environ["PYTHONNET_RUNTIME"] = "coreclr"
        pythonnet.load("coreclr", runtime_config=str(config), dotnet_root=str(root))
        print(f".NET Desktop Runtime in {root}")
        return True
    except Exception as e:  # noqa: BLE001 — Edge is always there to fall back on
        print(f".NET didn't load ({e!r}): opening Archer in Edge")
        return False


def edge_path() -> Optional[str]:
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA")):
        exe = Path(base or "") / "Microsoft" / "Edge" / "Application" / "msedge.exe"
        if base and exe.is_file():
            return str(exe)
    return None


def edge_holds(profile: Path) -> bool:
    """Whether an Edge process still has this profile open: Chromium holds its lockfile
    exclusively on Windows, so it can't be removed until the last one exits."""
    lock = profile / "lockfile"
    try:
        lock.unlink()
    except FileNotFoundError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return False


def page(body: str) -> str:
    return ("<!doctype html><meta charset='utf-8'><title>Archer</title>"
            "<div style='font:15px/1.5 system-ui,sans-serif;padding:40px;max-width:720px'>" + body + "</div>")


class Chooser:
    """The chooser on a loopback port, under a random path; it answers with where to go next."""

    def __init__(self, app, error: str = ""):
        from archer.desktop_app import CHOOSER

        self.app, self.token = app, secrets.token_urlsafe(16)
        current = app.choice.url if app.choice and app.choice.mode == "server" else ""
        markup = CHOOSER.replace("__CURRENT__", json.dumps(current)).replace("__ERROR__", json.dumps(error))
        self.html = markup.replace("<script>", BRIDGE + "<script>", 1).encode()
        chooser = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, body, kind):
                self.send_response(code)
                self.send_header("Content-Type", kind)
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == f"/{chooser.token}/":
                    return self._send(200, chooser.html, "text/html; charset=utf-8")
                self._send(404, b"", "text/plain")

            def do_POST(self):
                if not self.path.startswith(f"/{chooser.token}/"):
                    return self._send(404, b"", "text/plain")
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", "replace")
                action = self.path.rsplit("/", 1)[-1]
                answer = chooser.app.connect(body) if action == "connect" else chooser.app.use_local()
                self._send(200, json.dumps(answer).encode(), "application/json")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/{self.token}/"

    def stop(self):
        self.server.shutdown()


class EdgeApp:
    """The same choices as desktop_app.App (a server, or Archer on this computer), in Edge."""

    def __init__(self, home: Path, log):
        from archer import desktop_client as client

        self.client, self.home, self.log = client, home, log
        self.local = None
        self.choice = client.resolve(home)

    def connect(self, url: str) -> dict:
        try:
            url = self.client.normalise(url)
        except ValueError as e:
            return {"error": str(e)}
        ok, message = self.client.probe(url)
        if not ok:
            return {"error": message}
        self.choice = self.client.Choice("server", url, source="saved")
        self.client.save(self.home, self.choice)
        print(f"Opened {url}")
        return {"url": url}

    def use_local(self) -> dict:
        self.choice = self.client.Choice("local", source="saved")
        self.client.save(self.home, self.choice)
        url, error = self.start_local()
        return {"url": url} if url else {"error": f"Archer didn't start: {error}. The log is at {self.log}"}

    def start_local(self):
        """(url, None) once Archer answers on this computer, else (None, why)."""
        from archer import paths
        from archer.desktop_app import InProcessServer, free_port, seed, version

        if self.local is None:
            seed(self.home, version())
            paths.seed_bespoke()
            self.local = InProcessServer(free_port(), self.log)
            self.local.start()
        if self.local.wait():
            return self.local.url, None
        return None, repr(self.local.failed) if self.local.failed else "it took too long to start"

    def first_url(self):
        """Where the window opens, and the chooser if that's what it shows."""
        from archer.desktop_app import MANAGED_ERROR

        choice = self.choice
        if choice is not None and choice.mode == "local":
            url, error = self.start_local()
            return url or "data:text/html," + page(
                f"<h2>Archer didn't start</h2><p>{html.escape(error)}</p>"
                f"<p>The log is at <code>{html.escape(str(self.log))}</code>.</p>"), None
        if choice is not None:
            try:
                url = self.client.normalise(choice.url, allow_http=choice.source in ("managed", "env"))
                ok, message = self.client.probe(url)
            except ValueError as e:
                ok, message = False, str(e)
            if ok:
                print(f"Opened {url}")
                return url, None
            if choice.managed:
                return "data:text/html," + MANAGED_ERROR.replace("__MESSAGE__", html.escape(message)), None
            chooser = Chooser(self, message)
            return chooser.url, chooser
        chooser = Chooser(self)
        return chooser.url, chooser

    def run(self):
        edge = edge_path()
        if not edge:
            raise RuntimeError("Microsoft Edge isn't installed, and Archer's window on Windows on ARM needs it")
        url, chooser = self.first_url()
        if urlparse(url).scheme == "data":
            from urllib.parse import quote

            url = "data:text/html," + quote(url[len("data:text/html,"):])
        # Its own profile keeps Archer's cookies apart from the user's browsing, and makes this
        # process Edge's main one, so waiting on it waits for the window to close
        profile = self.home / "edge"
        proc = subprocess.Popen([edge, f"--app={url}", f"--user-data-dir={profile}", "--no-first-run",
                                 "--no-default-browser-check", "--window-size=1440,920"])
        print(f"Edge window (pid {proc.pid})")
        proc.wait()
        # Edge can hand the window to a process it starts itself (after an update, say), so the
        # window is closed when the profile's lock is free, not when the first process exits
        while edge_holds(profile):
            time.sleep(2)
        if chooser:
            chooser.stop()
        if self.local is not None:
            self.local.stop()
