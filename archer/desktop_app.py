"""
Archer as an installed application: what the .dmg / .msi / .deb built by desktop/stage.py
and Briefcase runs (python -m archer). A checkout uses `archer-cli app` (archer/desktop.py)
instead, which launches the repository's own server.

An installed app's own folder is read-only, so everything Archer writes goes to a per-user
folder, ARCHER_HOME (archer/paths.py):

    macOS     ~/Library/Application Support/Archer/home
    Windows   %LOCALAPPDATA%\\Archer\\home
    Linux     $XDG_DATA_HOME/archer/home (~/.local/share/archer/home)

Run locally, it's seeded on first use, and again after an upgrade, from the reference data the build
bundles (seed/: git's data/, the ATT&CK bundle and the procedures CSV built from it), and
bespoke/mappings gets the default mappings (archer/mappings/defaults). The database,
detections and your own mappings there are never overwritten.

It opens either an organisation's Archer server, as a client (archer/desktop_client.py says
which and how IT sets it), or Archer on this computer: then the server runs in this process
(uvicorn on 127.0.0.1, port 8000 or the next free one) and stops when the window closes. The
first launch asks which, unless IT or ARCHER_SERVER has decided; Archer > Change Server switches.
A client copies no data in and starts no server.
"""

import html
import json
import os
import shutil
import socket
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

NAME = "Archer"
ROOT = Path(__file__).resolve().parent.parent
SEED = ROOT / "seed"


def default_home():
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / NAME
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / NAME
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / NAME.lower()
    return base / "home"


def redirect_output(home):
    """A windowed app has no console (on Windows, stdout is None and the first print raises)."""
    logs = home / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    path = logs / "archer.log"
    if path.exists() and path.stat().st_size > 20 * 1024 * 1024:
        path.replace(path.with_suffix(".log.1"))
    out = open(path, "a", buffering=1, encoding="utf-8", errors="replace")
    sys.stdout = sys.stderr = out
    print(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} {NAME} starting (home {home})")
    return path


def seed(home, version):
    """Copy the bundled reference data in. Files that aren't there yet always; after an upgrade
    (a new version), the bundled ones again, since they're reference data the app ships."""
    if not SEED.is_dir():
        return
    marker = home / ".seed_version"
    upgraded = (marker.read_text().strip() if marker.exists() else "") != version
    copied = 0
    for src in SEED.rglob("*"):
        if not src.is_file() or src == SEED / "VERSION":
            continue
        dest = home / src.relative_to(SEED)
        if dest.exists() and not upgraded:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)  # keeps mtimes: the procedures CSV must stay newer than the ATT&CK bundle
        copied += 1
    marker.write_text(version)
    print(f"Seeded {copied} file(s) from the app" + (f" (version {version})" if upgraded else ""))


def free_port(preferred=8000, tries=20):
    # Stable when possible: the window's storage (theme, preferences) is per origin, port included
    for port in range(preferred, preferred + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class InProcessServer:
    """uvicorn in a background thread; the same wait()/url the window helper expects."""

    def __init__(self, port, log):
        import uvicorn

        self.url = f"http://127.0.0.1:{port}"
        self.log = log
        config = uvicorn.Config("archer.app:app", host="127.0.0.1", port=port, timeout_keep_alive=75,
                                log_config=None, access_log=False)
        self.server = uvicorn.Server(config)
        self.thread = None
        self.failed = None

    def start(self):
        def run():
            try:
                self.server.run()
            except BaseException as e:  # noqa: BLE001  (SystemExit from a failed bind, too)
                self.failed = e
                print(f"The server stopped: {e!r}")
        self.thread = threading.Thread(target=run, name="uvicorn", daemon=True)
        self.thread.start()

    def wait(self, timeout=600):
        # First run downloads ATT&CK (if the build didn't bundle it) and builds caches: allow minutes
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.server.started:
                return True
            if self.failed or not self.thread.is_alive():
                return False
            time.sleep(0.25)
        return False

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=10)


def version():
    try:
        from importlib.metadata import version as dist_version
        return dist_version("archer")
    except Exception:
        return (SEED / "VERSION").read_text().strip() if (SEED / "VERSION").exists() else "dev"


CHOOSER = """<!doctype html><html><head><meta charset="utf-8"><style>
:root{--bg:#fff;--fg:#1f2937;--muted:#6b7280;--line:#d1d5db;--field:#fff;--accent:#C53030}
@media(prefers-color-scheme:dark){:root{--bg:#111827;--fg:#e5e7eb;--muted:#9ca3af;--line:#374151;--field:#1f2937;--accent:#ff6b6b}}
html,body{height:100%;margin:0;background:var(--bg);color:var(--fg);font:15px -apple-system,'Segoe UI',sans-serif}
main{max-width:440px;margin:0 auto;padding:12vh 24px 0}
h1{font-size:24px;font-weight:500;margin:0 0 6px}p{color:var(--muted);margin:0 0 22px;line-height:1.5}
label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
input{box-sizing:border-box;width:100%;padding:10px 12px;font:inherit;color:var(--fg);background:var(--field);border:1px solid var(--line);border-radius:6px}
input:focus{outline:2px solid var(--accent);outline-offset:-1px}
button{margin-top:12px;width:100%;padding:10px;font:inherit;font-weight:600;color:#fff;background:var(--accent);border:0;border-radius:6px;cursor:pointer}
button:disabled{opacity:.6;cursor:default}
#error{color:var(--accent);font-size:13px;min-height:18px;margin-top:10px;line-height:1.4}
.or{margin-top:28px;padding-top:18px;border-top:1px solid var(--line);font-size:14px;color:var(--muted)}
.or a{color:var(--fg);cursor:pointer;text-decoration:underline}
</style></head><body><main>
<h1>Connect to Archer</h1>
<p>Enter your organisation's Archer address to share its detections, library and users.</p>
<form id="f"><label for="url">Server address</label>
<input id="url" placeholder="https://archer.example.org" autocomplete="url" autofocus spellcheck="false">
<button id="go">Connect</button><div id="error"></div></form>
<div class="or">Working on your own? <a id="local">Run Archer on this computer</a></div>
</main><script>
const url=document.getElementById('url'),go=document.getElementById('go'),err=document.getElementById('error');
url.value=__CURRENT__;err.textContent=__ERROR__;
document.getElementById('f').onsubmit=e=>{e.preventDefault();go.disabled=true;go.textContent='Connecting\u2026';err.textContent='';
  pywebview.api.connect(url.value).then(m=>{if(m){err.textContent=m;go.disabled=false;go.textContent='Connect';}});};
document.getElementById('local').onclick=()=>pywebview.api.use_local();
</script></body></html>"""

MANAGED_ERROR = """<!doctype html><html><head><meta charset="utf-8"><style>
html,body{margin:0;background:#fff;color:#1f2937;font:15px -apple-system,'Segoe UI',sans-serif}
@media(prefers-color-scheme:dark){html,body{background:#111827;color:#e5e7eb}}
main{max-width:480px;margin:0 auto;padding:14vh 24px 0;line-height:1.5}h1{font-size:22px;font-weight:500}
</style></head><body><main><h1>Archer isn't available</h1><p>__MESSAGE__</p>
<p>Your organisation set this server, so contact IT if it carries on.</p></main></body></html>"""


class ChooserApi:
    """What the chooser page can call (pywebview.api.*). pywebview hands this to every page the
    window loads, the organisation's server's included, so it does nothing unless the chooser is
    what's showing: a script on the server can't repoint the app somewhere else."""

    def __init__(self, app):
        self._app = app

    def connect(self, url):
        return self._app.connect(url) if self._app.choosing else "Not available"

    def use_local(self):
        if self._app.choosing:
            self._app.use_local()


class App:
    """The window: the chooser, an organisation's server, or Archer on this computer."""

    def __init__(self, home, log):
        from archer import desktop_client as client

        self.client, self.home, self.log = client, home, log
        self.window = None
        self.local = None
        self.choosing = False
        self.choice = client.resolve(home)

    # --- from the chooser page, through ChooserApi ---
    def connect(self, url):
        try:
            url = self.client.normalise(url)
        except ValueError as e:
            return str(e)
        ok, message = self.client.probe(url)
        if not ok:
            return message
        self.choice = self.client.Choice("server", url, source="saved")
        self.client.save(self.home, self.choice)
        self.open_server(url)
        return ""

    def use_local(self):
        self.choice = self.client.Choice("local", source="saved")
        self.client.save(self.home, self.choice)
        self.open_local()

    # --- the window ---
    def show_chooser(self, error=""):
        current = self.choice.url if self.choice and self.choice.mode == "server" else ""
        self.choosing = True
        self.window.set_title("Archer")
        self.window.load_html(CHOOSER.replace("__CURRENT__", json.dumps(current)).replace("__ERROR__", json.dumps(error)))

    def open_server(self, url):
        self.choosing = False
        self.stop_local()
        self.window.set_title(f"Archer \u2014 {urlparse(url).hostname}")
        self.window.load_url(url)
        print(f"Opened {url}")

    def open_local(self):
        from archer import desktop

        self.choosing = False
        self.window.set_title("Archer")
        self.window.load_html(desktop.LOADING)
        if self.local is None:
            # Only a local Archer needs the bundled data and its own server
            seed(self.home, version())
            from archer import paths
            paths.seed_bespoke()
            self.local = InProcessServer(free_port(), self.log)
            self.local.start()
        if self.local.wait():
            self.window.load_url(self.local.url)
        else:
            reason = html.escape(repr(self.local.failed) if self.local.failed else "it took too long to start")
            self.window.set_title("Archer didn't start")
            self.window.load_html(
                "<div style='font:15px/1.5 system-ui,sans-serif;padding:40px;max-width:720px'>"
                f"<h2 style='margin:0 0 12px'>Archer didn't start</h2><p>{reason}</p>"
                f"<p>The log is at <code>{html.escape(str(self.log))}</code>.</p></div>")

    def stop_local(self):
        if self.local is not None:
            self.local.stop()
            self.local = None

    def boot(self):
        """Runs once the window exists (pywebview's start func, on its own thread)."""
        choice = self.choice
        if choice is None:
            self.show_chooser()
        elif choice.mode == "local":
            self.open_local()
        else:
            try:
                url = self.client.normalise(choice.url, allow_http=choice.source in ("managed", "env"))
                ok, message = self.client.probe(url)
            except ValueError as e:
                ok, message = False, str(e)
            if ok:
                self.open_server(url)
            elif choice.managed:
                self.window.load_html(MANAGED_ERROR.replace("__MESSAGE__", html.escape(message)))
            else:
                self.show_chooser(message)

    def run(self):
        import webview
        from webview.menu import Menu, MenuAction
        from archer import desktop

        webview.settings["ALLOW_DOWNLOADS"] = True
        webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
        # Never: a certificate the OS doesn't trust is an error, not a prompt to click through
        webview.settings["IGNORE_SSL_ERRORS"] = False
        self.window = webview.create_window(NAME, html=desktop.LOADING, js_api=ChooserApi(self), width=1440, height=920,
                                            min_size=(900, 600), text_select=True, zoomable=True)
        managed = bool(self.choice and self.choice.managed)
        menu = [] if managed else [Menu(NAME, [MenuAction("Change Server\u2026", lambda: self.show_chooser())])]
        desktop.brand_process()
        webview.start(self.boot, private_mode=False, storage_path=str(self.home / "webview"), menu=menu)
        self.stop_local()


def main():
    # Before anything imports archer.paths, which reads ARCHER_HOME once
    home = Path(os.environ.get("ARCHER_HOME") or default_home()).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    os.environ["ARCHER_HOME"] = str(home)
    os.chdir(home)  # what archer/config.py's relative paths ("data/...") resolve against
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    log = redirect_output(home)

    from archer import desktop

    lock = desktop.single_instance(home)
    if lock is None:
        print("Already running")
        return 0
    try:
        App(home, log).run()
    finally:
        print("Window closed")
    # Background threads (feed collection, CVE refresh) are daemons, but some block in network
    # calls: don't wait for them
    os._exit(0)


if __name__ == "__main__":
    sys.exit(main())
