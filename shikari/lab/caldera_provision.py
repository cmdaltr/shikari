"""
Build → Emulate → Lab → CALDERA: stand up a disposable CALDERA lab on this macOS host in one
job (#30, Stage 1). This is the in-app equivalent of scripts/telemetry/caldera-lab.sh: it installs
the dependencies, builds and runs the server, enrols the agents, and writes the server's URL and
red key into the signed-in user's profile.

It crosses the line shikari.lab.hosts otherwise holds — "detect and guide, don't install" — so it is
deliberately narrow: macOS only, admin only, and only when SHIKARI_ALLOW_LAB_PROVISION is set, so it
can never fire on a shared server where the host isn't the operator's own machine.

The two steps that need a human (Homebrew's sudo password, OrbStack's first launch) don't block the
job: the task goes to `waiting`, shows the exact command to run, and re-probes the host every 10 s,
advancing itself the moment the dependency appears. The page polls the job's task list meanwhile.
"""

import os
import re
import subprocess
import time
from typing import Callable, Optional

from shikari.lab import hosts
from shikari.lab.runner import LabError, run, run_ok, which

# Where brew/orb/docker land, so the job finds them straight after an install without a new shell.
_BREW_BINS = ["/opt/homebrew/bin", "/usr/local/bin"]
_POLL_SECS = 10
_WAIT_CAP = 30 * 60  # give up waiting on a human after half an hour

# The task list the page renders. Order is the order they run in.
TASKS = [
    ("check", "Check this host"),
    ("homebrew", "Install Homebrew"),
    ("orbstack", "Install OrbStack (Docker + Linux VMs)"),
    ("server", "Build and run the CALDERA server"),
    ("agents", "Create and enrol the agents"),
    ("configure", "Save the server and key to your profile"),
]


def initial_tasks() -> list:
    return [{"id": tid, "label": label, "state": "pending", "detail": "", "action": ""} for tid, label in TASKS]


def can_provision(is_admin: bool) -> tuple:
    """(True, "") if in-app provisioning is allowed here, else (False, why). Narrow on purpose:
    macOS, admin, and an explicit opt-in — never on a shared server."""
    if hosts.os_name() != "macos":
        return False, "In-app provisioning is macOS only. On other hosts, use scripts/telemetry/caldera-lab.sh."
    if not is_admin:
        return False, "Provisioning needs an admin account."
    if os.environ.get("SHIKARI_ALLOW_LAB_PROVISION", "").strip() not in ("1", "true", "yes"):
        return False, "Set SHIKARI_ALLOW_LAB_PROVISION=1 on this host to enable in-app provisioning (keep it off on shared servers)."
    return True, ""


def _env() -> dict:
    """The job's environment with Homebrew's bin dirs on PATH, so a just-installed tool is found."""
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join(_BREW_BINS + [env.get("PATH", "")])
    return env


def _stream(argv, say, cwd: Optional[str] = None, extra_env: Optional[dict] = None) -> int:
    """Run a long command, relaying its output line by line. Returns the exit code."""
    env = _env()
    if extra_env:
        env.update(extra_env)
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            stdin=subprocess.DEVNULL, env=env, cwd=cwd)
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip()
        if line:
            say(f"  {line}")
    proc.wait()
    return proc.returncode


def _docker_ready() -> bool:
    return run_ok(["docker", "info", "--format", "{{.ServerVersion}}"])


def lab_up() -> bool:
    """True when the local caldera-lab.sh server container is running — i.e. Shikari provisioned a
    lab on this host and it's still up. Lets the panel offer Re-provision / De-provision."""
    if which("docker") is None:
        return False
    try:
        out = run(["docker", "ps", "--filter", "name=caldera", "--format", "{{.Names}}"],
                  timeout=10, check=False)
    except LabError:
        return False
    return any(line.strip() == "caldera" for line in out.splitlines())


def _wait_for(check: Callable[[], bool], task, tid: str, action: str, poll: int = _POLL_SECS) -> bool:
    """Park a task in `waiting`, showing what the human needs to do, and re-probe every `poll`
    seconds until `check` passes or the cap is reached. Advances itself — no click needed."""
    if check():
        return True
    task(tid, state="waiting", action=action)
    waited = 0
    while waited < _WAIT_CAP:
        time.sleep(poll)
        waited += poll
        if check():
            return True
    return False


def _script() -> str:
    from shikari import paths

    path = os.path.join(paths.ROOT, "scripts", "telemetry", "caldera-lab.sh")
    if not os.path.exists(path):
        raise LabError("Can't find caldera-lab.sh", f"expected it at {path}")
    return path


def provision(say: Callable[[str], None], task: Callable[..., None], save_key: Callable[[str, str, bool], None]) -> None:
    """Run the whole flow, updating each task's state as it goes. `task(id, state=, detail=, action=)`
    mutates the shared task list the page polls; `save_key(url, key, verify_tls)` stores the result."""
    script = _script()

    # 1. Check the host — fail fast with a clear reason rather than part-way through.
    task("check", state="running")
    if hosts.os_name() != "macos":
        task("check", state="failed", detail="Not a macOS host")
        raise LabError("In-app provisioning is macOS only")
    have_brew = which("brew") is not None
    have_docker = _docker_ready()
    task("check", state="done",
         detail=f"macOS · Homebrew {'present' if have_brew else 'missing'} · Docker {'running' if have_docker else 'not running'}")

    # 2. Homebrew. Try the non-interactive installer; it fails fast without a TTY for sudo, so if it
    #    can't self-install we park the task and poll until the user installs it in a terminal.
    if which("brew"):
        task("homebrew", state="done", detail="already installed")
    else:
        task("homebrew", state="running", detail="installing (may need your password in Terminal)")
        installer = '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
        try:
            subprocess.run(["/bin/bash", "-c", installer], env={**_env(), "NONINTERACTIVE": "1"},
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600)
        except Exception:  # noqa: BLE001 — any failure just means we fall back to the manual path
            pass
        action = ('In Terminal, run:  /bin/bash -c "$(curl -fsSL '
                  'https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')
        if not _wait_for(lambda: which("brew") is not None, task, "homebrew", action):
            task("homebrew", state="failed", detail="Homebrew still not on PATH")
            raise LabError("Homebrew not installed", "Install it, then run Provision again.")
        task("homebrew", state="done")

    # 3. OrbStack — gives both the docker command and the Linux VMs the agents run in. After the
    #    install it may need its first launch, so we open it and poll until the daemon answers.
    if _docker_ready():
        task("orbstack", state="done", detail="Docker already running")
    else:
        task("orbstack", state="running")
        if which("orb") is None and which("docker") is None:
            rc = _stream(["brew", "install", "--cask", "orbstack"], say)
            if rc != 0:
                task("orbstack", state="failed", detail="brew install --cask orbstack failed")
                raise LabError("OrbStack install failed", "See the log above.")
        run(["open", "-a", "OrbStack"], check=False)
        if not _wait_for(_docker_ready, task, "orbstack", "Open OrbStack once and approve its setup prompt."):
            task("orbstack", state="failed", detail="Docker daemon still not answering")
            raise LabError("OrbStack not running", "Open OrbStack, finish its setup, then run Provision again.")
        task("orbstack", state="done")

    # 4+5. Server and agents — caldera-lab.sh up does both (clone+build the server on first run,
    #      then create and enrol the Linux agents). Its ">>" lines carry the stage, so we move the
    #      agents task to running once the server is up.
    task("server", state="running", detail="first run builds the image — this is slow")
    task("agents", state="pending")
    rc = _stream(["/bin/bash", script, "up"], say)
    # caldera-lab.sh up can exit non-zero even when the lab is actually healthy — a re-enrol ssh
    # hiccup after the server is already up, say. So judge success by the result, not the exit code:
    # read config and confirm the server container is running.
    out = run(["/bin/bash", script, "config"], timeout=60, check=False)
    url, key = _field(out, "url"), _field(out, "api_key")
    if not (url and key and lab_up()):
        task("server", state="failed")
        task("agents", state="failed")
        raise LabError("caldera-lab.sh up failed", "The server didn't come up — see the log above.")
    if rc != 0:
        say(f"caldera-lab.sh up exited {rc}, but the server and key are present — continuing.")
    task("server", state="done")
    task("agents", state="done")

    # 6. Store the server's URL and red key on the user, encrypted, as if they'd typed them into
    #    Profile → Emulation Tools.
    task("configure", state="running")
    save_key(url, key, False)  # lab server over http on the LAN — verify_tls off, as the script sets
    task("configure", state="done", detail=url)
    say(f"CALDERA ready at {url} — saved to your profile.")


def deprovision(say: Callable[[str], None]) -> None:
    """Tear the lab down: stop the server and delete the agent machines (caldera-lab.sh down with
    STOP_SERVER). The caller also clears the saved key from the user's profile."""
    script = _script()
    rc = _stream(["/bin/bash", script, "down"], say, extra_env={"STOP_SERVER": "1"})
    if rc != 0:
        raise LabError("caldera-lab.sh down failed", "See the log above.")
    say("Lab torn down.")


def _field(yaml_text: str, name: str) -> str:
    """Pull one quoted scalar out of caldera-lab.sh's `config` output (a tiny fixed YAML block)."""
    m = re.search(rf'^\s*{re.escape(name)}:\s*"?([^"\n]+)"?\s*$', yaml_text, re.MULTILINE)
    return m.group(1).strip() if m else ""
