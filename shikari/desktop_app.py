"""
Shikari as an installed application: what the .dmg / .msi / .deb built by desktop/stage.py
and Briefcase runs (python -m shikari). A checkout uses `shikari app` (shikari/desktop.py)
instead, which launches the repository's own server.

An installed app's own folder is read-only, so everything Shikari writes goes to a per-user
folder, SHIKARI_HOME (shikari/paths.py):

    macOS     ~/Library/Application Support/Shikari/home
    Windows   %LOCALAPPDATA%\\Shikari\\home
    Linux     $XDG_DATA_HOME/shikari/home (~/.local/share/shikari/home)

Run locally, it's seeded on first use, and again after an upgrade, from the reference data the build
bundles (seed/: git's data/, the ATT&CK bundle and the procedures CSV built from it), and
bespoke/mappings gets the default mappings (shikari/mappings/defaults). The database,
detections and your own mappings there are never overwritten.

It opens either an organisation's Shikari server, as a client (shikari/desktop_client.py says
which and how IT sets it), or Shikari on this computer: then the server runs in this process
(uvicorn on 127.0.0.1, port 32453 or the next free one) and stops when the window closes. The
first launch asks which, unless IT or SHIKARI_SERVER has decided; Shikari > Change Server switches.
A client copies no data in and starts no server.
"""

import html
import json
import os
import secrets
import shutil
import socket
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

NAME = "Shikari"
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
    path = logs / "shikari.log"
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
        if not src.is_file() or src in (SEED / "VERSION", SEED / "LICENSE", SEED / "install.sh", SEED / "install.ps1"):
            continue
        dest = home / src.relative_to(SEED)
        if dest.exists() and not upgraded:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)  # keeps mtimes: the procedures CSV must stay newer than the ATT&CK bundle
        copied += 1
    marker.write_text(version)
    print(f"Seeded {copied} file(s) from the app" + (f" (version {version})" if upgraded else ""))


def free_port(preferred=32453, tries=20):
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
        config = uvicorn.Config("shikari.app:app", host="127.0.0.1", port=port, timeout_keep_alive=75,
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
        return dist_version("shikari")
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
<h1>Connect to Shikari</h1>
<p>Enter your organisation's Shikari address to share its detections, library and users.</p>
<form id="f"><label for="url">Server address</label>
<input id="url" placeholder="https://shikari.example.org" autocomplete="url" autofocus spellcheck="false">
<button id="go">Connect</button><div id="error"></div></form>
<div class="or">Working on your own? <a id="local">Run Shikari on this computer</a></div>
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
</style></head><body><main><h1>Shikari isn't available</h1><p>__MESSAGE__</p>
<p>Your organisation set this server, so contact IT if it carries on.</p></main></body></html>"""

# Help menu windows. Links carry target=_blank so pywebview opens them in the browser.
_HELP_STYLE = """<style>
:root{--bg:#fff;--fg:#1f2937;--muted:#6b7280;--line:#e5e7eb}
@media(prefers-color-scheme:dark){:root{--bg:#111827;--fg:#e5e7eb;--muted:#9ca3af;--line:#374151}}
html,body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,'Segoe UI',sans-serif}
main{padding:28px 32px}h1{font-size:22px;font-weight:600;margin:0}a{color:inherit}
.muted{color:var(--muted)}.gloss b{font-weight:600}.gloss i{margin:0 8px}
footer{margin-top:22px;padding-top:14px;border-top:1px solid var(--line);font-size:12px;color:var(--muted)}
pre{white-space:pre-wrap;font:12px/1.45 ui-monospace,Menlo,Consolas,monospace;border-top:1px solid var(--line);padding-top:14px}
</style>"""

ABOUT = """<!doctype html><html><head><meta charset="utf-8">""" + _HELP_STYLE + """</head><body><main>
<h1>Shikari</h1><div class="muted">Version __VERSION__</div>
<p class="gloss"><b>shi&middot;ka&middot;ri</b><i>\\shi-&#712;k&auml;r-&#275;\\</i>a professional big-game hunter or guide</p>
<p>Automated multi-vendor threat hunting and detection.</p>
<p><a href="https://github.com/cmdaltr" target="_blank">@cmdaltr</a> on GitHub</p>
<p class="muted">Free software under the GNU Affero General Public License v3.0; a commercial licence is
available for organisations that can't meet its terms. See Help &rarr; Licence.</p>
<footer>Splunk&reg;, Microsoft&reg;, Google&reg; and Elastic&reg; names and logos are trademarks of their
respective companies.</footer></main></body></html>"""

LICENCE = """<!doctype html><html><head><meta charset="utf-8">""" + _HELP_STYLE + """</head><body><main>
<h1>Licence</h1>
<p>Shikari is free software under the GNU Affero General Public License v3.0 (AGPL-3.0-only): you can use,
study, change and share it, and if you change it and let others use it, over a network included, you must
make your changed source available to them under the same licence.</p>
<p>Organisations that can't meet the AGPL's terms, for example to keep changes private or to build Shikari
into a closed product, can get a commercial licence instead: contact
<a href="https://github.com/cmdaltr" target="_blank">@cmdaltr</a> on GitHub.</p>
<pre>__TEXT__</pre></main></body></html>"""


# The update notice, dropped into whichever page is showing (Shikari's own or an organisation's
# server's): bottom left, clear of Ask Shikari. __DATA__ is {version, url, linux}.
UPDATE_NOTICE = """(function (d) {
  var old = document.getElementById('shikari-update'); if (old) old.remove();
  var b = document.createElement('div'); b.id = 'shikari-update';
  b.style.cssText = 'position:fixed;left:20px;bottom:20px;z-index:2147483000;max-width:380px;padding:14px 16px;'
    + 'background:#1f2937;color:#e5e7eb;border:1px solid #C53030;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.35);'
    + 'font:14px/1.45 -apple-system,"Segoe UI",sans-serif';
  var how = d.linux ? '<div style="margin-top:8px;color:#9ca3af">Install it from a terminal: '
    + '<code style="color:#e5e7eb">shikari update</code></div>' : '';
  b.innerHTML = '<div><b>Shikari ' + d.version + '</b> is available.'
    + (d.url ? ' <a href="' + d.url + '" target="_blank" style="color:#e5e7eb">What&rsquo;s new</a>' : '') + '</div>' + how
    + '<div style="margin-top:10px;display:flex;gap:8px">'
    + (d.linux ? '' : '<button data-a="now" style="padding:6px 12px;border:0;border-radius:6px;background:#C53030;color:#fff;font:inherit;font-weight:600;cursor:pointer">Update</button>')
    + '<button data-a="later" style="padding:6px 12px;border:1px solid #4b5563;border-radius:6px;background:none;color:#e5e7eb;font:inherit;cursor:pointer">Later</button>'
    + '<button data-a="skip" style="padding:6px 12px;border:0;background:none;color:#9ca3af;font:inherit;cursor:pointer">Skip this version</button></div>';
  b.onclick = function (e) {
    var a = e.target.getAttribute('data-a'); if (!a || !window.pywebview) return;
    if (a === 'now') { b.innerHTML = 'Downloading Shikari ' + d.version + '. Shikari closes, installs it and reopens: a minute or two.'; pywebview.api.update_now(); }
    else { b.remove(); pywebview.api[a === 'skip' ? 'update_skip' : 'update_later'](); }
  };
  document.body.appendChild(b);
})(__DATA__);"""

# Help > Check for Updates...: the answer, and whether to check once a day
UPDATE_CHECK = """<!doctype html><html><head><meta charset="utf-8">""" + _HELP_STYLE + """</head><body><main>
<h1>__TITLE__</h1><p>__MESSAGE__</p>__ACTION__
<footer><label><input type="checkbox" id="auto" __CHECKED__> Check for updates once a day</label>
<div style="margin-top:6px">The check asks GitHub for Shikari's latest release and sends nothing else.</div></footer>
</main><script>
document.getElementById('auto').onchange = function () { pywebview.api.set_update_checks(this.checked); };
var u = document.getElementById('update');
if (u) u.onclick = function () { u.disabled = true; u.textContent = 'Starting\u2026'; pywebview.api.update_now(); };
</script></body></html>"""


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

    def change_server(self):
        # The nav's Connect button. Only from Shikari on this computer, so an organisation's server
        # can't pop the chooser over itself; it only shows the page, the user still picks
        if self._app.local is not None and not self._app.choosing:
            self._app.show_chooser()

    # The update notice and Help > Check for Updates. Only once the app itself has found a newer
    # release on GitHub: a page can't make it install anything else
    def update_now(self):
        if self._app.update:
            self._app.update_now()

    def update_later(self):
        self._app.update_hidden = True

    def update_skip(self):
        if self._app.update:
            self._app.skip_update()

    def set_update_checks(self, enabled):
        from shikari import updates
        updates.set_checks(self._app.home, bool(enabled))


class App:
    """The window: the chooser, an organisation's server, or Shikari on this computer."""

    def __init__(self, home, log):
        from shikari import desktop_client as client

        self.client, self.home, self.log = client, home, log
        self.window = None
        self.local = None
        self.choosing = False
        self.choice = client.resolve(home)
        self.update = None          # a newer release, once the daily check finds one
        self.update_hidden = False  # Later: not again this session

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
        self.window.set_title("Shikari")
        self.window.load_html(CHOOSER.replace("__CURRENT__", json.dumps(current)).replace("__ERROR__", json.dumps(error)))

    def open_server(self, url):
        self.choosing = False
        self.stop_local()
        self.window.set_title(f"Shikari \u2014 {urlparse(url).hostname}")
        self.window.load_url(url)
        print(f"Opened {url}")

    def open_local(self):
        from shikari import desktop

        self.choosing = False
        self.window.set_title("Shikari")
        self.window.load_html(desktop.LOADING)
        if self.local is None:
            # The local app runs its own server on the user's machine, so provisioning a CALDERA lab
            # here (shikari.lab.caldera_provision) is in scope — a client of a central server never
            # reaches this path. setdefault so SHIKARI_ALLOW_LAB_PROVISION=0 can still turn it off.
            os.environ.setdefault("SHIKARI_ALLOW_LAB_PROVISION", "1")
            # One person's own copy: nothing held back (emulation planning included), and the nav
            # offers Connect (to an organisation's server) in place of Log in / Log out
            os.environ.setdefault("ENABLE_EMULATION", "true")
            os.environ["SHIKARI_DESKTOP"] = "1"
            # The window signs itself in with this, once; a browser on the same port still logs in
            os.environ["SHIKARI_DESKTOP_TOKEN"] = secrets.token_urlsafe(32)
            # Only a local Shikari needs the bundled data and its own server
            self.step("Unpacking the bundled data")
            seed(self.home, version())
            from shikari import paths
            paths.seed_bespoke()
            self.step("Starting the server and building its caches")
            self.local = InProcessServer(free_port(), self.log)
            self.local.start()
        if self.local.wait():
            self.window.load_url(f"{self.local.url}/desktop/enter?token={os.environ['SHIKARI_DESKTOP_TOKEN']}")
        else:
            reason = html.escape(repr(self.local.failed) if self.local.failed else "it took too long to start")
            self.window.set_title("Shikari didn't start")
            self.window.load_html(
                "<div style='font:15px/1.5 system-ui,sans-serif;padding:40px;max-width:720px'>"
                f"<h2 style='margin:0 0 12px'>Shikari didn't start</h2><p>{reason}</p>"
                f"<p>The log is at <code>{html.escape(str(self.log))}</code>.</p></div>")

    def show_about(self):
        import webview
        webview.create_window(f"About {NAME}", html=ABOUT.replace("__VERSION__", html.escape(version())),
                              width=480, height=400, resizable=False, background_color="#111827")

    def show_licence(self):
        import webview
        path = next((p for p in (SEED / "LICENSE", ROOT / "LICENSE") if p.exists()), ROOT / "LICENSE")
        text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        webview.create_window(f"{NAME} Licence", html=LICENCE.replace("__TEXT__", html.escape(text)),
                              width=720, height=760, background_color="#111827")

    # --- updates ---
    def daily_update_check(self):
        """In the background once the window is up: GitHub at most once a day (shikari.updates)."""
        from shikari import updates
        latest = updates.daily_check(self.home, version())
        if latest:
            print(f"Update available: {latest['tag']}")
            self.update = latest
            self.show_update_notice()

    def show_update_notice(self, *_):
        if not self.update or self.update_hidden or self.choosing:
            return
        data = {"version": html.escape(self.update["version"]), "url": self.update.get("url", ""),
                "linux": sys.platform.startswith("linux")}
        try:
            self.window.evaluate_js(UPDATE_NOTICE.replace("__DATA__", json.dumps(data)))
        except Exception:  # noqa: BLE001  (a page mid-load; the next load shows it)
            pass

    def check_for_updates(self):
        """Help > Check for Updates...: ask now, whatever the daily check last saw."""
        import webview
        from shikari import updates

        current = version()
        action = ""
        try:
            latest = updates.latest_release()
        except updates.UpdateError as e:
            title, message = "Couldn't check for updates", html.escape(str(e)[:1].upper() + str(e)[1:]) + "."
        else:
            if updates.is_newer(latest["version"], current):
                self.update = latest
                title = f"Shikari {html.escape(latest['version'])} is available"
                message = f"You have {html.escape(current)}."
                if latest.get("url"):
                    message += f' <a href="{html.escape(latest["url"])}" target="_blank">What&rsquo;s new</a>'
                action = ('<p>Install it from a terminal: <code>shikari update</code></p>'
                          if sys.platform.startswith("linux") else
                          '<p><button id="update" style="padding:8px 16px;border:0;border-radius:6px;background:#C53030;'
                          'color:#fff;font:inherit;font-weight:600;cursor:pointer">Update now</button></p>')
            else:
                title, message = "Shikari is up to date", f"You have {html.escape(current)}, the latest release."
        page = (UPDATE_CHECK.replace("__TITLE__", title).replace("__MESSAGE__", message).replace("__ACTION__", action)
                .replace("__CHECKED__", "checked" if updates.checks_enabled(self.home) else ""))
        webview.create_window("Check for Updates", html=page, js_api=ChooserApi(self), width=480, height=330,
                              resizable=False, background_color="#111827")

    def skip_update(self):
        from shikari import updates
        updates.skip(self.home, self.update["version"])
        self.update = None

    def update_now(self):
        """Hand over to the install script, which waits for the app to quit, installs and reopens it."""
        import webview
        from shikari import updates

        script = updates.install_script(SEED)
        if sys.platform.startswith("linux") or not script:
            return
        log = self.home / "logs" / "update.log"
        print(f"Updating to {self.update['tag']} with {script} (log: {log})")
        updates.start_installer(script, self.update["tag"], os.getpid(), log)
        # Long enough to read what's happening, then quit so the installer can replace the app
        time.sleep(4)
        for w in list(webview.windows):
            w.destroy()

    def step(self, text):
        """Name the stage on the loading screen, so a slow first start doesn't look stuck."""
        print(text)
        try:
            self.window.evaluate_js(f"window.shikariStep && shikariStep({json.dumps(text)})")
        except Exception:  # noqa: BLE001  (the splash may not have loaded yet; the clock still runs)
            pass

    def stop_local(self):
        if self.local is not None:
            self.local.stop()
            self.local = None

    def boot(self):
        """Runs once the window exists (pywebview's start func, on its own thread)."""
        # pywebview gives up on a window that takes 20 s to show, and WebKit's first start on a slow
        # or emulated machine can take longer: wait for it here instead
        if not self.window.events.shown.wait(600):
            print("The window never appeared")
            return
        # Shown isn't ready: WebView2 (Windows) starts up after the window does, and a page sent
        # before it has loaded the splash is dropped without an error, leaving the splash up for good
        if not self.window.events.loaded.wait(600):
            print("The window's web view never loaded")
            return
        choice = self.choice
        print(f"Opening: {choice.mode + (' ' + choice.url if choice.url else '') if choice else 'the chooser'}")
        threading.Thread(target=self.daily_update_check, name="update-check", daemon=True).start()
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
        from shikari import desktop

        webview.settings["ALLOW_DOWNLOADS"] = True
        webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
        # Never: a certificate the OS doesn't trust is an error, not a prompt to click through
        webview.settings["IGNORE_SSL_ERRORS"] = False
        # background_color (default white) is what the native window paints in any
        # repaint gap — e.g. when macOS reactivates the app from the Dock. Match the
        # dark loading splash so it never flashes white behind the page.
        self.window = webview.create_window(NAME, html=desktop.LOADING, js_api=ChooserApi(self), width=1440, height=920,
                                            min_size=(900, 600), text_select=True, zoomable=True,
                                            background_color="#111827")
        managed = bool(self.choice and self.choice.managed)
        menu = [] if managed else [Menu(NAME, [MenuAction("Change Server\u2026", lambda: self.show_chooser())])]
        # macOS puts it in the menu bar; Windows and Linux in the window's own menu bar
        menu.append(Menu("Help", [MenuAction(f"About {NAME}", self.show_about),
                                  MenuAction("Check for Updates\u2026", self.check_for_updates),
                                  MenuAction("Licence", self.show_licence)]))
        # Every page load (Shikari's or a server's) brings the notice back until it's dealt with
        self.window.events.loaded += self.show_update_notice
        desktop.brand_process()
        try:
            webview.start(self.boot, private_mode=False, storage_path=str(self.home / "webview"), menu=menu)
        finally:
            self.stop_local()


def hide_console_windows():
    """Windows: the app has no console, so every console program it runs (git, docker, powershell,
    where, ollama...) got a console window of its own, popping up over the app. Start them with none,
    unless the caller asked for a console or a detached process."""
    if sys.platform != "win32":
        return
    import subprocess

    if getattr(subprocess.Popen, "_shikari_no_window", False):
        return
    original = subprocess.Popen.__init__
    own_console = subprocess.CREATE_NEW_CONSOLE | subprocess.DETACHED_PROCESS

    def __init__(self, *args, **kwargs):
        flags = kwargs.get("creationflags", 0) or 0
        if not flags & own_console:
            kwargs["creationflags"] = flags | subprocess.CREATE_NO_WINDOW
        original(self, *args, **kwargs)

    subprocess.Popen.__init__ = __init__
    subprocess.Popen._shikari_no_window = True


def bundled_git():
    """The Windows installer carries MinGit (desktop/stage.py), since Windows has no git. It goes
    last on PATH, so a git the user installed (with their credentials and config) still wins."""
    mingit = ROOT / "mingit" / "cmd"
    if mingit.is_dir():
        os.environ["PATH"] = os.pathsep.join(filter(None, [os.environ.get("PATH"), str(mingit)]))


def cli_update(argv):
    """`shikari update [--check]` from the installed app (the .deb's shikari command, or the app's
    executable on macOS and Windows): the same release and install script as the Help menu."""
    from shikari import updates

    current = version()
    print(f"Shikari {current}")
    try:
        latest = updates.latest_release()
    except updates.UpdateError as e:
        print(f"Couldn't check for updates: {e}")
        return 1
    if not updates.is_newer(latest["version"], current):
        print(f"Up to date (the latest release is {latest['tag']}).")
        return 0
    print(f"Shikari {latest['version']} is available: {latest['url']}")
    if "--check" in argv:
        print("Install it with: shikari update")
        return 0
    script = updates.install_script(SEED)
    if not script:
        print("This copy of Shikari has no install script: download the installer from the release page.")
        return 1
    return updates.run_installer(script, latest["tag"])


def main():
    if sys.argv[1:2] == ["update"]:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        return cli_update(sys.argv[2:])
    # Before anything imports shikari.paths, which reads SHIKARI_HOME once
    home = Path(os.environ.get("SHIKARI_HOME") or default_home()).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    os.environ["SHIKARI_HOME"] = str(home)
    os.chdir(home)  # what shikari/config.py's relative paths ("data/...") resolve against
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    log = redirect_output(home)
    hide_console_windows()
    bundled_git()

    from shikari import desktop

    lock = desktop.single_instance(home)
    if lock is None:
        print("Already running")
        return 0
    try:
        from shikari import desktop_edge

        if desktop_edge.wanted() and not desktop_edge.use_dotnet(home):
            desktop_edge.EdgeApp(home, log).run()
        else:
            try:
                App(home, log).run()
            except Exception:
                if not desktop_edge.wanted():
                    raise
                # ARM64 on .NET: whatever stopped the window, Edge can still show Shikari
                import traceback

                traceback.print_exc()
                print("The .NET window failed: opening Shikari in Edge")
                desktop_edge.EdgeApp(home, log).run()
    except BaseException:
        # Briefcase's launcher swallows what reaches it (an ARM64 Windows build failed with nothing
        # in the log): write it here first
        import traceback

        traceback.print_exc()
        raise
    finally:
        print("Window closed")
    # Background threads (feed collection, CVE refresh) are daemons, but some block in network
    # calls: don't wait for them
    os._exit(0)


if __name__ == "__main__":
    sys.exit(main())
