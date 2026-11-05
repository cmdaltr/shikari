#!/usr/bin/env python3
"""
Build a native Shikari **team-server** package — .deb (Debian/Ubuntu) or .rpm (Rocky/RHEL 9) — with its
own bundled Python, installing a systemd service (#29).

This is the server counterpart to desktop/build_deb.py: same SHA-pinned standalone CPython
(python-build-standalone), but no GUI/GTK dependencies, and instead of a desktop launcher it installs
`shikari.service`, a dedicated `shikari` user, data under /var/lib/shikari and config in /etc/shikari.

    # On Debian/Ubuntu, with dpkg-deb:
    python3 deploy/packaging/build_server_pkg.py --format deb --out dist
    # On Rocky/RHEL 9, with rpmbuild:
    python3 deploy/packaging/build_server_pkg.py --format rpm --out dist

Build on the OLDEST distro you intend to support: the compiled dependency wheels link against its glibc.
The package installs as `shikari-server` (so it can coexist with the desktop `shikari` package) and puts
the CLI on PATH as `shikari`.

Layout installed:
    /usr/lib/shikari/python                 standalone CPython + the server's dependencies
    /usr/lib/shikari/app                    shikari/ templates/ static/ (shikari.paths.ROOT)
    /usr/bin/shikari                        the CLI launcher (shikari status|logs|…)
    /lib/systemd/system/shikari.service     the service (runs uvicorn as the shikari user)
    /usr/share/shikari/shikari.env.example   copied to /etc/shikari/shikari.env on first install
    /var/lib/shikari                         data (SHIKARI_HOME) — created by the post-install script
"""
import argparse
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
PREFIX = "usr/lib/shikari"
SOURCES = ("shikari", "templates", "static")   # no `seed` — that's the desktop sample data

# Pinned to the release's published SHA-256s (same release the desktop build carries). Keyed by machine.
PYTHON_RELEASE = "https://github.com/astral-sh/python-build-standalone/releases/download/20261009"
PYTHON = {
    "x86_64": ("cpython-3.11.17+20261009-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
               "89db7607ebadb77a64709d159b86555d995368ec385a2ab33b00477790c543b0", "amd64", "x86_64"),
    "aarch64": ("cpython-3.11.17+20261009-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz",
                "7e7e24eee3467dd666aff379c34c4ef3e6bc7142aec7d5ba783765df7da999a6", "arm64", "aarch64"),
}

LAUNCHER = """#!/bin/sh
# The Shikari CLI (status, logs, console, offline…). The server itself runs under systemd; manage it
# with: systemctl {start,stop,status} shikari
exec /usr/lib/shikari/python/bin/python3 -m shikari.service "$@"
"""

# Shared post-install / pre-remove / post-remove logic, as shell snippets reused by both deb and rpm.
POSTINST = """\
set -e
# Dedicated service user.
if ! id shikari >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/shikari --shell /usr/sbin/nologin shikari 2>/dev/null \\
        || useradd --system --home-dir /var/lib/shikari --shell /sbin/nologin shikari
fi
mkdir -p /var/lib/shikari /etc/shikari
chown -R shikari:shikari /var/lib/shikari
chmod 750 /var/lib/shikari
# First install only: seed the config.
if [ ! -f /etc/shikari/shikari.env ]; then
    cp /usr/share/shikari/shikari.env.example /etc/shikari/shikari.env
    chmod 640 /etc/shikari/shikari.env
fi
# Seed the ATT&CK STIX cache so the server starts without network on first boot (it refreshes when
# online). Without a cache, startup hard-fails offline or where egress is blocked (e.g. SELinux).
SHIKARI_HOME=$(. /etc/shikari/shikari.env 2>/dev/null; echo "${SHIKARI_HOME:-/var/lib/shikari}")
CACHE="$SHIKARI_HOME/shikari/data/cache"
mkdir -p "$CACHE"
if [ ! -f "$CACHE/enterprise-attack.json" ] && [ -f /usr/share/shikari/enterprise-attack.json ]; then
    cp /usr/share/shikari/enterprise-attack.json "$CACHE/enterprise-attack.json"
fi
chown -R shikari:shikari "$SHIKARI_HOME"
# SELinux: label the port if enforcing (Rocky/RHEL).
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ] && command -v semanage >/dev/null 2>&1; then
    PORT=$(. /etc/shikari/shikari.env; echo "${SHIKARI_PORT:-8000}")
    semanage port -a -t http_port_t -p tcp "$PORT" 2>/dev/null || true
fi
systemctl daemon-reload || true
systemctl enable --now shikari.service || true
"""

PRERM = """\
set -e
systemctl disable --now shikari.service 2>/dev/null || true
"""

POSTRM_PURGE = """\
# Only on a full purge: remove data, config and the user.
rm -rf /var/lib/shikari /etc/shikari
id shikari >/dev/null 2>&1 && userdel shikari 2>/dev/null || true
systemctl daemon-reload || true
"""


def fetch_python(machine, dest):
    name, sha256 = PYTHON[machine][0], PYTHON[machine][1]
    print(f"Fetching {name}")
    with urllib.request.urlopen(f"{PYTHON_RELEASE}/{name}", timeout=300) as r:
        body = r.read()
    if hashlib.sha256(body).hexdigest() != sha256:
        sys.exit(f"{name} doesn't match its pinned SHA-256: refusing to bundle it")
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
        tar.extractall(dest, filter="tar")   # archive's top folder is python/


ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
              "enterprise-attack/enterprise-attack.json")


def fetch_attack(dest):
    """Download the ATT&CK STIX bundle to ship in the package, so the server starts without network on
    first boot. Non-fatal: a build host with no egress still produces a package (just not offline-ready)."""
    print("Fetching the ATT&CK STIX bundle (seeds the offline cache)")
    try:
        with urllib.request.urlopen(ATTACK_URL, timeout=120) as r:
            dest.write_bytes(r.read())
    except Exception as exc:  # noqa: BLE001
        print(f"  warning: couldn't fetch ATT&CK ({exc}); the package won't seed a cache and the "
              f"server will need network on first start")


def read_project(python):
    """Read version + dependencies from pyproject.toml using the *bundled* interpreter, so the host's
    Python version doesn't matter (tomllib is 3.11+; the oldest supported build hosts ship 3.9/3.10)."""
    snippet = ("import tomllib, json, sys;"
               "d = tomllib.load(open(sys.argv[1], 'rb'))['project'];"
               "print(json.dumps([d['version'], d['dependencies']]))")
    out = subprocess.run([str(python), "-c", snippet, str(REPO / "pyproject.toml")],
                         capture_output=True, text=True, check=True).stdout
    version, deps = json.loads(out)
    return version, deps


def stage_payload(machine, root):
    """Fill `root` with the full install tree (everything except the packaging metadata). Returns the
    project version read via the bundled interpreter."""
    prefix = root / PREFIX
    prefix.mkdir(parents=True)
    fetch_python(machine, prefix)
    python = prefix / "python" / "bin" / "python3"

    version, deps = read_project(python)
    print(f"Installing {len(deps)} dependencies into the bundled Python")
    subprocess.run([str(python), "-m", "pip", "install", "-q", "--no-cache-dir",
                    "--no-warn-script-location", *deps], check=True)

    for name in SOURCES:
        shutil.copytree(REPO / name, prefix / "app" / name)
    site = Path(subprocess.run([str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
                               capture_output=True, text=True, check=True).stdout.strip())
    (site / "shikari-app.pth").write_text(f"/{PREFIX}/app\n")
    subprocess.run([str(python), "-m", "compileall", "-q", "-j", "0", str(prefix / "app")], check=True)

    (root / "usr/bin").mkdir(parents=True)
    (root / "usr/bin/shikari").write_text(LAUNCHER)
    (root / "usr/bin/shikari").chmod(0o755)

    unit_dir = root / "lib/systemd/system"
    unit_dir.mkdir(parents=True)
    # The packaged unit runs the bundled Python directly; no /opt checkout. Working directory is the
    # writable data home (SHIKARI_HOME), not the read-only code: the app writes several paths relative
    # to the cwd (data/shikari.db, data/groups, bespoke/…), so cwd must be the one dir the hardened unit
    # allows writes to. Imports come from the .pth (absolute) and templates/static from paths.ROOT, so
    # the cwd doesn't affect code loading.
    unit = (HERE.parent / "linux" / "shikari.service").read_text()
    unit = unit.replace("WorkingDirectory=/opt/shikari", "WorkingDirectory=/var/lib/shikari")
    unit = unit.replace("/opt/shikari/.venv/bin/python",
                        f"/{PREFIX}/python/bin/python3")
    (unit_dir / "shikari.service").write_text(unit)

    share = root / "usr/share/shikari"
    share.mkdir(parents=True)
    shutil.copy2(HERE.parent / "linux" / "shikari.env.example", share / "shikari.env.example")
    fetch_attack(share / "enterprise-attack.json")
    doc = root / "usr/share/doc/shikari-server"
    doc.mkdir(parents=True)
    shutil.copy2(REPO / "LICENSE", doc / "copyright")
    return version


def normalise_modes(root):
    for p in root.rglob("*"):
        if p.is_symlink():
            continue
        p.chmod(0o755 if p.is_dir() or p.stat().st_mode & 0o111 else 0o644)


def build_deb(machine, out):
    arch = PYTHON[machine][2]
    root = out / "deb-root"
    shutil.rmtree(root, ignore_errors=True)
    version = stage_payload(machine, root)

    installed_kb = sum(f.stat().st_size for f in root.rglob("*") if f.is_file()) // 1024
    debian = root / "DEBIAN"
    debian.mkdir()
    (debian / "control").write_text(
        f"Package: shikari-server\n"
        f"Version: {version}-1\n"
        f"Architecture: {arch}\n"
        f"Maintainer: Shikari <https://github.com/cmdaltr/shikari>\n"
        f"Depends: adduser\n"
        f"Installed-Size: {installed_kb}\n"
        f"Section: admin\n"
        f"Priority: optional\n"
        f"Homepage: https://github.com/cmdaltr/shikari\n"
        f"Description: Shikari team server (systemd service)\n"
        f" The central Shikari instance browsers and desktop clients connect to, with its own\n"
        f" bundled Python, run as a systemd service under a dedicated user.\n")
    # /etc/shikari/shikari.env is NOT a dpkg conffile: it isn't shipped in the package, postinst
    # generates it on first install (and leaves it alone on upgrade). Listing an unshipped file in
    # conffiles makes dpkg-deb refuse to build. The rpm side marks it %ghost for the same reason.
    (debian / "postinst").write_text("#!/bin/sh\n" + POSTINST)
    (debian / "prerm").write_text("#!/bin/sh\n" + PRERM)
    # Debian passes "purge" to postrm; only then remove data.
    (debian / "postrm").write_text('#!/bin/sh\nset -e\nif [ "$1" = "purge" ]; then\n' + POSTRM_PURGE + "fi\n")
    for s in ("postinst", "prerm", "postrm"):
        (debian / s).chmod(0o755)

    normalise_modes(root)
    deb = out / f"shikari-server_{version}-1_{arch}.deb"
    subprocess.run(["dpkg-deb", "--root-owner-group", "-Zxz", "--build", str(root), str(deb)], check=True)
    shutil.rmtree(root)
    print(f"Built {deb}")


def build_rpm(machine, out):
    arch = PYTHON[machine][3]
    payload = out / "rpm-payload"
    shutil.rmtree(payload, ignore_errors=True)
    version = stage_payload(machine, payload)
    normalise_modes(payload)

    top = out / "rpmbuild"
    for d in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS", "BUILDROOT"):
        (top / d).mkdir(parents=True, exist_ok=True)
    spec = top / "SPECS" / "shikari-server.spec"
    # %install copies the pre-staged payload into the buildroot; scriptlets mirror the .deb's.
    spec.write_text(f"""\
Name:           shikari-server
Version:        {version}
Release:        1%{{?dist}}
Summary:        Shikari team server (systemd service)
License:        AGPL-3.0
URL:            https://github.com/cmdaltr/shikari
BuildArch:      {arch}
Requires:       shadow-utils, systemd
# Everything is bundled (its own CPython + the wheels' private .so files). Stop rpmbuild auto-scanning
# those ELFs and emitting Requires/Provides the distro can't satisfy (libgfortran, libjpeg, the bundled
# python3 by its build path, ...). The explicit Requires above are all this package genuinely needs.
AutoReqProv:    no
%global __os_install_post %{{nil}}
%global debug_package %{{nil}}

%description
The central Shikari instance browsers and desktop clients connect to, with its own bundled
Python, run as a systemd service under a dedicated user.

%install
cp -a {payload}/. %{{buildroot}}/

%files
/usr/lib/shikari
/usr/bin/shikari
/lib/systemd/system/shikari.service
/usr/share/shikari
/usr/share/doc/shikari-server
%config(noreplace) %ghost /etc/shikari/shikari.env

%post
{POSTINST}
%preun
if [ "$1" = 0 ]; then
{PRERM}fi
%postun
if [ "$1" = 0 ]; then
{POSTRM_PURGE}fi
""")
    subprocess.run(["rpmbuild", "-bb", "--define", f"_topdir {top}", str(spec)], check=True)
    built = list((top / "RPMS").rglob("shikari-server-*.rpm"))
    for f in built:
        shutil.copy2(f, out / f.name)
        print(f"Built {out / f.name}")
    shutil.rmtree(payload, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--format", choices=("deb", "rpm"), required=True)
    parser.add_argument("--out", type=Path, default=Path("dist"))
    args = parser.parse_args()

    machine = platform.machine()
    if sys.platform != "linux" or machine not in PYTHON:
        sys.exit(f"Builds on Linux x86_64 or aarch64, not {sys.platform} {machine}")
    args.out.mkdir(parents=True, exist_ok=True)

    if args.format == "deb":
        if not shutil.which("dpkg-deb"):
            sys.exit("dpkg-deb not found — run this on Debian/Ubuntu (apt install dpkg-dev).")
        build_deb(machine, args.out)
    else:
        if not shutil.which("rpmbuild"):
            sys.exit("rpmbuild not found — run this on Rocky/RHEL (dnf install rpm-build).")
        build_rpm(machine, args.out)


if __name__ == "__main__":
    main()
