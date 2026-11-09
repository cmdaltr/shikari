#!/usr/bin/env python3
"""
shikari app: Shikari as a desktop application with its own Dock / Start menu / launcher entry.

    shikari app install [--dock]   add Shikari to Applications (macOS), the Start menu and desktop
                                      (Windows) or the application menu (Linux); --dock also pins it
                                      to the macOS Dock
    shikari app uninstall          remove what install added
    shikari app open               what the app runs: start the server if it isn't up, then
                                      show Shikari in a window

The app is a launcher for this checkout, not a frozen copy: it runs the repository's .venv, so
it always matches the code and `git pull` updates it. The window is pywebview when it's
installed (pip install -e '.[desktop]'), otherwise a Chrome/Edge/Brave/Chromium app window,
otherwise the default browser.

A server the app started is stopped when its window closes; one that was already running
(`shikari start`) is left alone. Windows has no supervisor (shikari/service.py is POSIX), so
there the app runs the server itself.

On Windows, run it as: .venv\\Scripts\\python shikari\\desktop.py install
"""

import argparse
import base64
import os
import plistlib
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from shikari import service  # noqa: E402  (stdlib only)

NAME = "Shikari"
BUNDLE_ID = "com.cmdaltr.shikari"
ICONS = ROOT / "desktop" / "icons"
WINDOWS = sys.platform == "win32"
MACOS = sys.platform == "darwin"

# The screeching bateleur over the loading words, inline: the splash shows before there's a server
try:
    _BIRD = "data:image/webp;base64," + base64.b64encode(
        (ROOT / "static" / "images" / "shikari" / "shikari-screech-loading.webp").read_bytes()).decode()
except OSError:
    _BIRD = ""

LOADING = """<!doctype html><html><head><meta charset="utf-8"><style>
html,body{height:100%;margin:0;background:#fff;color:#444;font:16.5px -apple-system,'Segoe UI',sans-serif}
@media(prefers-color-scheme:dark){html,body{background:#111827;color:#d1d5db}}
body{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px}
.bar{width:180px;height:3px;background:#e5e7eb;overflow:hidden;border-radius:2px}
.bar i{display:block;width:40%;height:100%;background:#C53030;animation:s 1.2s infinite ease-in-out}
@keyframes s{0%{margin-left:-40%}100%{margin-left:100%}}
.step{font-size:14.3px;opacity:.75}.note{max-width:462px;text-align:center;font-size:14.3px;line-height:1.5;opacity:.6;margin:6px 0 0}
.gloss{position:fixed;bottom:22px;font-size:14.3px;opacity:.7}
.title{position:relative}.bird{position:absolute;left:50%;bottom:100%;transform:translateX(calc(-50% - 10px));margin-bottom:28px;width:520px;max-width:90vw;max-height:calc(50vh - 120px);object-fit:contain;object-position:bottom;pointer-events:none}.gloss b{font-weight:600}.gloss i{margin:0 8px;opacity:.8}
</style></head>
<body><div class="title">__BIRD__Starting Shikari&hellip;</div><div class="bar"><i></i></div>
<div class="step"><span id="step">Getting ready</span> &middot; <span id="elapsed">0:00</span></div>
<p class="note">The first start takes a few minutes while Shikari unpacks MITRE ATT&amp;CK and builds its
database. After that it starts in seconds.</p>
<div class="gloss"><b>shi&middot;ka&middot;ri</b><i>\\shi-&#712;k&auml;r-&#275;\\</i>a professional big-game hunter or guide</div>
<script>
// The app reports each stage with shikariStep(); the clock shows it hasn't stalled
var t0=Date.now();window.shikariStep=function(s){document.getElementById('step').textContent=s};
setInterval(function(){var s=Math.floor((Date.now()-t0)/1000);
document.getElementById('elapsed').textContent=Math.floor(s/60)+':'+String(s%60).padStart(2,'0')},1000);
</script></body></html>""".replace("__BIRD__", f'<img class="bird" alt="" src="{_BIRD}">' if _BIRD else "")


def venv_python(windowed=False):
    if WINDOWS:
        exe = ROOT / ".venv" / "Scripts" / ("pythonw.exe" if windowed else "python.exe")
        return str(exe) if exe.exists() else sys.executable
    return service.python()


def app_log(msg):
    service.LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(service.LOG_DIR / "app.log", "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")


# --- the server --------------------------------------------------------------------------------

class Server:
    def __init__(self):
        self.port = service.load_settings()["port"]
        self.url = f"http://127.0.0.1:{self.port}"
        self.started_here = False
        self.proc = None
        self.log = f"{service.LOG_DIR / 'shikari.log'} (or run: shikari status)"

    def healthy(self):
        return service.http_ok(f"{self.url}/health", timeout=2)

    def start(self):
        """Start the server if it isn't up. Returns at once; wait() blocks until it answers."""
        if self.healthy():
            app_log(f"server already running on port {self.port}")
            return
        self.started_here = True
        service.LOG_DIR.mkdir(parents=True, exist_ok=True)
        if WINDOWS:
            out = open(service.LOG_DIR / "shikari.log", "a")
            flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            # uvicorn directly: `serve` hands over with os.execv, which on Windows is a new process
            # that taskkill on this one wouldn't reach
            cmd = [venv_python(), "-m", "uvicorn", "shikari.app:app", "--host", "127.0.0.1", "--port", str(self.port),
                   "--timeout-keep-alive", "75"]
            self.proc = subprocess.Popen(cmd,
                                         cwd=ROOT, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                         creationflags=flags)
        else:
            # The supervisor, as `shikari start` runs it (crash restarts, remembered settings)
            out = open(service.LOG_DIR / "app.log", "a")
            self.proc = subprocess.Popen([venv_python(), str(ROOT / "shikari" / "service.py"), "start"],
                                         cwd=ROOT, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        app_log(f"starting the server on port {self.port}")

    def wait(self, timeout=180):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.healthy():
                return True
            # On POSIX the `start` process exits once the supervisor is up; a non-zero exit is a failure
            if self.proc and self.proc.poll() not in (None, 0):
                return False
            time.sleep(0.5)
        return False

    def stop(self):
        if not self.started_here:
            return
        app_log("stopping the server the app started")
        if WINDOWS:
            if self.proc and self.proc.poll() is None:
                subprocess.run(["taskkill", "/PID", str(self.proc.pid), "/T", "/F"], capture_output=True)
        else:
            subprocess.run([venv_python(), str(ROOT / "shikari" / "service.py"), "stop"], cwd=ROOT, capture_output=True)


# --- the window --------------------------------------------------------------------------------

def single_instance(directory):
    """Hold a lock for as long as the app runs. None if another copy already holds it."""
    Path(directory).mkdir(parents=True, exist_ok=True)
    handle = open(Path(directory) / "app.lock", "a+")
    try:
        if WINDOWS:
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    return handle


def _set_dock_icon_now():
    """The actual AppKit call. Must run on the main thread."""
    from AppKit import NSApplication, NSBundle, NSImage
    icns = ICONS / "shikari.icns"
    if not icns.exists():
        # The installed app has no desktop/icons: Briefcase put the same icon in the bundle. Set at
        # runtime it shows as drawn, a hexagon; the bundle icon alone gets macOS 26's grey square
        bundled = NSBundle.mainBundle().pathForResource_ofType_("shikari", "icns")
        icns = Path(bundled) if bundled else icns
    if icns.exists():
        # Eager load, not initByReferencingFile_: keep the bitmap in memory so a Dock redraw
        # never re-reads the file from OneDrive (that read came back blank → white tile).
        image = NSImage.alloc().initWithContentsOfFile_(str(icns))
        if image and image.isValid():
            NSApplication.sharedApplication().setApplicationIconImage_(image)


def set_dock_icon(*_):
    """Set the Dock tile to Shikari's icon. Safe to call repeatedly, from any thread. On macOS the
    app icon has to be re-asserted after the WKWebView finishes loading the real page: that
    navigation makes the process active and macOS resets a non-bundled process's tile to the
    generic (white) icon, so a one-off set before the GUI loop starts shows on the splash and is
    then lost on load. pywebview fires the `loaded` event on a background thread, and AppKit only
    takes a new app icon from the main thread, so marshal the call onto the main run loop."""
    if not MACOS:
        return
    try:
        from PyObjCTools.AppHelper import callAfter
        callAfter(_set_dock_icon_now)
    except Exception as e:
        app_log(f"couldn't set the Dock icon: {e}")


def brand_process():
    """Name and icon for the Dock / taskbar entry while the window is open."""
    if MACOS:
        try:
            from Foundation import NSBundle
            info = NSBundle.mainBundle().localizedInfoDictionary() or NSBundle.mainBundle().infoDictionary()
            info["CFBundleName"] = NAME
        except Exception as e:
            app_log(f"couldn't set the Dock name: {e}")
        set_dock_icon()
    elif WINDOWS:
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(BUNDLE_ID)
        except Exception:
            pass
    else:
        try:
            from gi.repository import GLib
            GLib.set_prgname(NAME)  # matches StartupWMClass in the .desktop file
            GLib.set_application_name(NAME)
        except Exception:
            pass


def open_webview(server, storage):
    """The window: a loading page until server.wait() returns, then server.url. Blocks until it closes."""
    import webview

    webview.settings["ALLOW_DOWNLOADS"] = True  # YAML / XLSX exports
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
    # text_select: pywebview blocks selection by default, and queries get copied out by hand
    # background_color (default white) shows in any native repaint gap, e.g. when
    # macOS reactivates the app from the Dock; match the dark splash, not white.
    window = webview.create_window(NAME, html=LOADING, width=1440, height=920, min_size=(900, 600),
                                   text_select=True, zoomable=True, background_color="#111827")

    def boot():
        if server.wait():
            window.load_url(server.url)
        else:
            window.load_html(f"<p style='font:15px sans-serif;padding:40px'>Shikari didn't start. "
                             f"See {server.log}.</p>")

    # Re-assert the Dock icon every time a navigation completes: loading server.url makes the
    # process active and macOS drops a non-bundled process back to the generic white tile.
    if MACOS:
        window.events.loaded += set_dock_icon

    brand_process()
    icon = ICONS / "shikari.png"
    # On macOS, brand_process + the loaded handler set the Dock icon. Don't pass it to pywebview too:
    # pywebview sets it with a lazy NSImage, which re-read the OneDrive file after load and went white.
    # Other platforms use this for the window/taskbar icon.
    use_icon = None if MACOS else (str(icon) if icon.exists() else None)
    # Not private, so the login cookie and theme survive between launches
    webview.start(boot, private_mode=False, storage_path=str(storage), icon=use_icon)


def chromium():
    if MACOS:
        apps = ["Google Chrome", "Microsoft Edge", "Brave Browser", "Chromium"]
        for app in apps:
            for base in (Path("/Applications"), Path.home() / "Applications"):
                exe = base / f"{app}.app" / "Contents" / "MacOS" / app
                if exe.exists():
                    return str(exe)
        return None
    if WINDOWS:
        for env in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            base = os.environ.get(env)
            for rel in (r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe",
                        r"BraveSoftware\Brave-Browser\Application\brave.exe"):
                if base and Path(base, rel).exists():
                    return str(Path(base, rel))
        return None
    return next((shutil.which(n) for n in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge", "brave-browser")
                 if shutil.which(n)), None)


def open_browser(server):
    """No pywebview: an app window in a Chromium browser, or a tab. Can't tell when it closes."""
    ok = server.wait()
    url = server.url if ok else f"{server.url}/health"
    browser = chromium()
    if browser:
        # Its own profile, so it's a separate window (and Dock entry) that keeps its own login
        profile = service.RUN_DIR / "browser-profile"
        subprocess.Popen([browser, f"--app={url}", f"--user-data-dir={profile}", "--no-first-run",
                          "--no-default-browser-check", "--window-size=1440,920"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        webbrowser.open(url)
    return ok


def cmd_open(args):
    lock = single_instance(service.RUN_DIR)
    server = Server()
    if lock is None:
        # Already open: on macOS the Dock just focuses it; elsewhere bring Shikari up in the browser
        if not MACOS:
            webbrowser.open(server.url)
        return 0
    server.start()
    try:
        import webview  # noqa: F401
    except ImportError:
        app_log("pywebview isn't installed; using a browser window (pip install -e '.[desktop]')")
        return 0 if open_browser(server) else 1
    try:
        open_webview(server, service.RUN_DIR / "webview")
    finally:
        server.stop()
    return 0


# --- install -----------------------------------------------------------------------------------

def mac_app_path():
    return Path.home() / "Applications" / f"{NAME}.app"


def launch_command():
    return [venv_python(windowed=True), str(ROOT / "shikari" / "desktop.py"), "open"]


def install_macos(args):
    # Rewritten in place, not deleted and rebuilt: macOS keys the "access files in OneDrive"
    # consent to this bundle, and a new one asks again
    app = mac_app_path()
    (app / "Contents" / "MacOS").mkdir(parents=True, exist_ok=True)
    (app / "Contents" / "Resources").mkdir(exist_ok=True)
    shutil.copy(ICONS / "shikari.icns", app / "Contents" / "Resources" / "shikari.icns")
    version = "2.0.0"
    try:
        import tomllib
        version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    except Exception:
        pass
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump({
            "CFBundleName": NAME, "CFBundleDisplayName": NAME, "CFBundleIdentifier": BUNDLE_ID,
            "CFBundleExecutable": NAME, "CFBundleIconFile": "shikari", "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": version, "CFBundleVersion": version,
            "LSMinimumSystemVersion": "11.0", "NSHighResolutionCapable": True,
            "LSApplicationCategoryType": "public.app-category.developer-tools",
        }, f)
    # Finder starts apps with a bare PATH; the supervisor wants lsof, and Ollama from Homebrew.
    # exec, so the Python process is the app the Dock tracks
    script = app / "Contents" / "MacOS" / NAME
    py, entry, verb = launch_command()
    script.write_text("#!/bin/bash\n"
                      'export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"\n'
                      f'exec "{py}" "{entry}" {verb}\n')
    script.chmod(0o755)
    lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
    if os.path.exists(lsregister):
        subprocess.run([lsregister, "-f", str(app)], capture_output=True)
    print(f"Installed: {app}")
    if args.dock:
        dock_add(app)
    else:
        print("Open it from Launchpad or Spotlight; to keep it in the Dock: shikari app install --dock")


def dock_add(app):
    current = subprocess.run(["defaults", "read", "com.apple.dock", "persistent-apps"], capture_output=True, text=True).stdout
    if str(app) in current or f"{NAME}.app" in current:
        print("Already in the Dock.")
        return
    tile = ("<dict><key>tile-data</key><dict><key>file-data</key><dict>"
            f"<key>_CFURLString</key><string>file://{app}/</string>"
            "<key>_CFURLStringType</key><integer>15</integer></dict></dict></dict>")
    subprocess.run(["defaults", "write", "com.apple.dock", "persistent-apps", "-array-add", tile], check=True)
    subprocess.run(["killall", "Dock"], capture_output=True)
    print("Added to the Dock.")


def dock_remove():
    out = subprocess.run(["defaults", "export", "com.apple.dock", "-"], capture_output=True).stdout
    if not out:
        return
    prefs = plistlib.loads(out)
    apps = prefs.get("persistent-apps", [])
    kept = [a for a in apps if f"/{NAME}.app" not in a.get("tile-data", {}).get("file-data", {}).get("_CFURLString", "")]
    if len(kept) == len(apps):
        return
    prefs["persistent-apps"] = kept
    subprocess.run(["defaults", "import", "com.apple.dock", "-"], input=plistlib.dumps(prefs), check=True)
    subprocess.run(["killall", "Dock"], capture_output=True)
    print("Removed from the Dock.")


def linux_paths():
    data = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return data / "applications" / "shikari.desktop", data / "icons" / "hicolor" / "512x512" / "apps" / "shikari.png"


def install_linux(args):
    entry, icon = linux_paths()
    icon.parent.mkdir(parents=True, exist_ok=True)
    entry.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(ICONS / "shikari.png", icon)
    exec_line = " ".join(f'"{part}"' if " " in part else part for part in launch_command())
    entry.write_text("[Desktop Entry]\nType=Application\n"
                     f"Name={NAME}\nComment=Threat hunting and detection engineering\n"
                     f"Exec={exec_line}\nIcon=shikari\nTerminal=false\n"
                     f"Categories=Development;Security;Network;\nStartupWMClass={NAME}\nStartupNotify=true\n")
    entry.chmod(0o755)
    for tool in (["update-desktop-database", str(entry.parent)], ["gtk-update-icon-cache", "-q", str(icon.parents[2])]):
        if shutil.which(tool[0]):
            subprocess.run(tool, capture_output=True)
    print(f"Installed: {entry}")
    print("It's in your application menu; right-click it there and pick Add to Favourites (or Pin) for the dock.")


def windows_shortcuts():
    start_menu = Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / f"{NAME}.lnk"
    desktop = Path(os.environ["USERPROFILE"]) / "Desktop" / f"{NAME}.lnk"
    return [start_menu, desktop]


def install_windows(args):
    py, entry, verb = launch_command()
    for link in windows_shortcuts():
        link.parent.mkdir(parents=True, exist_ok=True)
        ps = ("$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:LNK); "
              "$s.TargetPath = $env:TARGET; $s.Arguments = $env:ARGS; $s.WorkingDirectory = $env:ROOTDIR; "
              "$s.IconLocation = $env:ICON; $s.Description = 'Shikari'; $s.Save()")
        env = {**os.environ, "LNK": str(link), "TARGET": py, "ARGS": f'"{entry}" {verb}',
               "ROOTDIR": str(ROOT), "ICON": str(ICONS / "shikari.ico")}
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], env=env, check=True)
        print(f"Installed: {link}")
    print("To pin it to the taskbar: Start > Shikari > right-click > Pin to taskbar.")


def cmd_install(args):
    if not (ICONS / "shikari.png").exists():
        print(f"Missing icons in {ICONS}; run: .venv/bin/python desktop/make_icons.py")
        return 1
    if not Path(venv_python()).is_relative_to(ROOT):
        print("Note: no .venv in the repository; the app will run with", venv_python())
    {"darwin": install_macos, "win32": install_windows}.get(sys.platform, install_linux)(args)
    try:
        import webview  # noqa: F401
    except ImportError:
        print("For a native window rather than a browser one: pip install -e '.[desktop]'")
    return 0


def cmd_uninstall(args):
    if MACOS:
        dock_remove()
        targets = [mac_app_path()]
    elif WINDOWS:
        targets = windows_shortcuts()
    else:
        targets = list(linux_paths())
    for path in targets:
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
        else:
            continue
        print(f"Removed: {path}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="shikari app", description="Shikari as a desktop application.")
    sub = parser.add_subparsers(dest="command", required=True)
    install = sub.add_parser("install", help="add Shikari to Applications / the Start menu / the app menu")
    install.add_argument("--dock", action="store_true", help="macOS: also keep it in the Dock")
    sub.add_parser("uninstall", help="remove what install added")
    sub.add_parser("open", help="start the server if needed and open the window")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    return {"install": cmd_install, "uninstall": cmd_uninstall, "open": cmd_open}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
