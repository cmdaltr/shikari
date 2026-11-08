#!/usr/bin/env python3
"""
Build the Linux .deb from a tree desktop/stage.py staged, with its own Python.

    python3 desktop/stage.py --out STAGE
    python3 desktop/build_deb.py --stage STAGE --out dist

Briefcase's Linux system package always runs on the distro's python3, so the app's
dependencies were compiled for whatever Python that distro shipped. This bundles a
standalone CPython (python-build-standalone, the same 3.11 the macOS and Windows builds
carry) under /usr/lib/shikari/python instead. GTK and WebKit still come from the distro:
they have to match its display stack, and they're dependencies apt installs.

Runs on Linux, with dpkg-deb and the headers PyGObject and pycairo build against
(libgirepository1.0-dev, libcairo2-dev, pkg-config). Build on the oldest distro the
package should support: the compiled modules link against its glibc and GTK.

    /usr/lib/shikari/python     standalone CPython, with the dependencies in its site-packages
    /usr/lib/shikari/app        shikari/ templates/ static/ seed/ (shikari.paths.ROOT)
    /usr/bin/shikari            launcher
"""

import argparse
import hashlib
import io
import platform
import shutil
import subprocess
import sys
import tarfile
import tomllib
import urllib.request
from pathlib import Path

PREFIX = "usr/lib/shikari"
# Pinned to the release's published SHA-256s. Keyed by platform.machine().
PYTHON_RELEASE = "https://github.com/astral-sh/python-build-standalone/releases/download/20261009"
PYTHON = {
    "x86_64": ("cpython-3.11.17+20261009-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
               "89db7607ebadb77a64709d159b86555d995368ec385a2ab33b00477790c543b0", "amd64"),
    "aarch64": ("cpython-3.11.17+20261009-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz",
                "7e7e24eee3467dd666aff379c34c4ef3e6bc7142aec7d5ba783765df7da999a6", "arm64"),
}
SOURCES = ("shikari", "templates", "static", "seed")
RUNTIME_DEPENDS = ["libgirepository-1.0-1", "libcairo-gobject2", "gir1.2-gtk-3.0", "gir1.2-webkit2-4.1"]

LAUNCHER = """#!/bin/sh
exec /usr/lib/shikari/python/bin/python3 -m shikari "$@"
"""

DESKTOP_ENTRY = """[Desktop Entry]
Type=Application
Name=Shikari
Comment={comment}
Exec=shikari
Icon=shikari
Categories=Development;Security;
StartupWMClass=shikari
"""


def fetch_python(machine, dest, cache):
    """Unpack the pinned CPython into dest, from cache when an earlier build downloaded it there."""
    name, sha256, _ = PYTHON[machine]
    cached = cache / name
    body = cached.read_bytes() if cached.exists() else b""
    if hashlib.sha256(body).hexdigest() != sha256:
        with urllib.request.urlopen(f"{PYTHON_RELEASE}/{name}", timeout=300) as r:
            body = r.read()
        if hashlib.sha256(body).hexdigest() != sha256:
            sys.exit(f"{name} doesn't match its pinned SHA-256: refusing to bundle it")
        cache.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(body)
    # The archive's top folder is python/
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
        tar.extractall(dest, filter="tar")
    return name


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--stage", type=Path, required=True, help="the tree desktop/stage.py staged")
    parser.add_argument("--out", type=Path, default=Path("dist"))
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "shikari" / "python",
                        help="where the downloaded CPython is kept between builds")
    args = parser.parse_args()

    machine = platform.machine()
    if sys.platform != "linux" or machine not in PYTHON:
        sys.exit(f"Builds on Linux x86_64 or aarch64, not {sys.platform} {machine}")
    stage = args.stage.resolve()
    staged = tomllib.loads((stage / "pyproject.toml").read_text())
    project = staged["project"]
    app = staged["tool"]["briefcase"]["app"]["shikari"]
    arch = PYTHON[machine][2]

    root = args.out.resolve() / "deb-root"
    shutil.rmtree(root, ignore_errors=True)
    prefix = root / PREFIX
    prefix.mkdir(parents=True)
    print(f"Bundling {fetch_python(machine, prefix, args.cache)}")
    python = prefix / "python" / "bin" / "python3"

    requirements = [*project["dependencies"], *app["linux"]["requires"]]
    subprocess.run([str(python), "-m", "pip", "install", "-q", "--no-cache-dir", "--no-warn-script-location",
                    "--find-links", str(stage / "wheels"), *requirements], check=True)

    for name in SOURCES:
        shutil.copytree(stage / name, prefix / "app" / name)
    # The app's folder on the bundled Python's path, so the launcher is a plain "-m shikari"
    site = Path(subprocess.run([str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
                               capture_output=True, text=True, check=True).stdout.strip())
    (site / "shikari-app.pth").write_text(f"/{PREFIX}/app\n")
    # /usr/lib is read-only to the user, so compile now rather than on every start
    subprocess.run([str(python), "-m", "compileall", "-q", "-j", "0", str(prefix / "app")], check=True)

    (root / "usr/bin").mkdir(parents=True)
    (root / "usr/bin/shikari").write_text(LAUNCHER)
    (root / "usr/bin/shikari").chmod(0o755)
    (root / "usr/share/applications").mkdir(parents=True)
    (root / "usr/share/applications/shikari.desktop").write_text(DESKTOP_ENTRY.format(comment=app["description"]))
    for size in (16, 32, 64, 128, 256, 512):
        icon = root / f"usr/share/icons/hicolor/{size}x{size}/apps/shikari.png"
        icon.parent.mkdir(parents=True)
        shutil.copy2(stage / "icons" / f"shikari-{size}.png", icon)
    doc = root / "usr/share/doc/shikari"
    doc.mkdir(parents=True)
    shutil.copy2(stage / "LICENSE", doc / "copyright")

    installed_kb = sum(f.stat().st_size for f in root.rglob("*") if f.is_file()) // 1024
    (root / "DEBIAN").mkdir()
    (root / "DEBIAN/control").write_text(
        f"Package: shikari\n"
        f"Version: {project['version']}-1\n"
        f"Architecture: {arch}\n"
        f"Maintainer: {staged['tool']['briefcase']['author']} <{staged['tool']['briefcase']['url']}>\n"
        f"Depends: {', '.join(RUNTIME_DEPENDS)}\n"
        f"Installed-Size: {installed_kb}\n"
        f"Section: utils\n"
        f"Priority: optional\n"
        f"Homepage: {staged['tool']['briefcase']['url']}\n"
        f"Description: {app['description']}\n"
        f" {app['long_description'].strip()}\n")

    # Readable by everyone whatever the umask the build ran under; the launcher, the Python
    # binaries and the compiled extensions stay executable
    for p in root.rglob("*"):
        if p.is_symlink():
            continue
        p.chmod(0o755 if p.is_dir() or p.stat().st_mode & 0o111 else 0o644)

    deb = args.out.resolve() / f"shikari_{project['version']}-1_{arch}.deb"
    subprocess.run(["dpkg-deb", "--root-owner-group", "-Zxz", "--build", str(root), str(deb)], check=True)
    shutil.rmtree(root)
    print(f"Built {deb}")


if __name__ == "__main__":
    main()
