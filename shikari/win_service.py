r"""First-class Windows service for the Shikari team server (#29).

Registers Shikari as an SCM service through pywin32, so it starts at boot and restarts on failure with
no Scheduled Task and no third-party supervisor. The service launches the bundled uvicorn as a *child*
process — a crashing worker takes the child down, not the service controller — and reads its config from
``%ProgramData%\Shikari\shikari.env``, the Windows counterpart of ``/etc/shikari/shikari.env``.

This module imports pywin32 only on Windows and is shipped only in the Windows server bundle (the
``service`` extra — see deploy/packaging/). Register / control it with pywin32's own command line, using
the bundled interpreter:

    python.exe -m shikari.win_service --startup auto install
    python.exe -m shikari.win_service start
    python.exe -m shikari.win_service stop
    python.exe -m shikari.win_service remove

Single worker only: Shikari keeps session, lab-job and in-browser-console state in-process, so more than
one worker breaks reconnect and job polling.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SERVICE_NAME = "Shikari"
SERVICE_DISPLAY = "Shikari team server"
SERVICE_DESCRIPTION = ("Serves the central Shikari instance (uvicorn) that browsers and desktop "
                       "clients connect to.")


def data_dir() -> Path:
    """Where Shikari keeps its state: SHIKARI_HOME if set, else %ProgramData%\\Shikari."""
    override = os.environ.get("SHIKARI_HOME")
    if override:
        return Path(override)
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Shikari"


def load_env(env_path: Path) -> dict:
    """Parse the KEY=VALUE env file shared with the Linux unit. Deliberately minimal — no interpolation,
    optional surrounding quotes stripped — matching how systemd reads an EnvironmentFile."""
    values: dict = {}
    if env_path.is_file():
        for raw in env_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip().strip('"').strip("'")
    return values


def uvicorn_argv(config: dict) -> list:
    # The bundled python.exe sits at sys.prefix; under the service host sys.executable is
    # pythonservice.exe, so resolve the real interpreter from the prefix.
    python_exe = Path(sys.prefix) / "python.exe"
    return [str(python_exe), "-m", "uvicorn", "shikari.app:app",
            "--host", config.get("SHIKARI_HOST", "127.0.0.1"),
            "--port", str(config.get("SHIKARI_PORT", "8000")),
            "--workers", "1"]


def app_dir() -> Path:
    # Install layout: <InstallDir>\python and <InstallDir>\app (the .pth in site-packages points here).
    return Path(sys.prefix).parent / "app"


if sys.platform == "win32":
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class ShikariService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            super().__init__(args)
            self._stop = win32event.CreateEvent(None, 0, 0, None)
            self._proc: subprocess.Popen | None = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            proc = self._proc
            if proc and proc.poll() is None:
                proc.terminate()  # CTRL-less terminate; uvicorn shuts its workers down
            win32event.SetEvent(self._stop)

        def SvcDoRun(self):
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                                  servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))
            data = data_dir()
            data.mkdir(parents=True, exist_ok=True)
            config = load_env(data / "shikari.env")

            env = dict(os.environ)
            env["SHIKARI_HOME"] = config.get("SHIKARI_HOME", str(data))

            self._proc = subprocess.Popen(uvicorn_argv(config), cwd=str(app_dir()), env=env)

            # Run until SCM asks us to stop, or the child exits on its own (SCM recovery then restarts us).
            while True:
                if win32event.WaitForSingleObject(self._stop, 2000) == win32event.WAIT_OBJECT_0:
                    break
                if self._proc.poll() is not None:
                    servicemanager.LogErrorMsg(
                        f"{self._svc_name_}: uvicorn exited with {self._proc.returncode}")
                    break

            proc = self._proc
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()


def main():
    if sys.platform != "win32":
        sys.exit("The Shikari Windows service runs on Windows only.")
    win32serviceutil.HandleCommandLine(ShikariService)


if __name__ == "__main__":
    main()
