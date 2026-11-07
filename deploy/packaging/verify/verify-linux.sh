#!/usr/bin/env bash
# Build, install and smoke-test the native Shikari server package on this Linux box (#29).
#
# Run it inside (or pointed at) a Shikari checkout, on a throwaway VM that matches a target you ship to
# (Debian/Ubuntu for .deb, Rocky/RHEL 9 for .rpm). It builds the package with its own bundled Python,
# installs it, waits for the systemd service to answer /health, prints the result, and uninstalls again
# unless you pass --keep.
#
#   sudo ./verify-linux.sh                 # auto: .deb on apt systems, .rpm on dnf systems
#   sudo ./verify-linux.sh --format rpm    # force a format
#   sudo ./verify-linux.sh --keep          # leave the service installed and running
#   sudo SHIKARI_REPO=/path/to/shikari ./verify-linux.sh   # checkout elsewhere
#
# Needs: python3 (3.11+), and the packaging toolchain — dpkg-dev (dpkg-deb) for .deb, rpm-build (rpmbuild)
# for .rpm. The script checks and tells you what to install. Run as root (it installs a system package).
set -euo pipefail

FORMAT=auto
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --format) FORMAT="$2"; shift 2 ;;
        --keep)   KEEP=1; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

# Repo root: $SHIKARI_REPO, else three levels up (deploy/packaging/verify/ -> repo), else the cwd.
here="$(cd "$(dirname "$0")" && pwd)"
REPO="${SHIKARI_REPO:-$(cd "$here/../../.." 2>/dev/null && pwd)}"
[ -f "$REPO/deploy/packaging/build_server_pkg.py" ] || REPO="$PWD"
[ -f "$REPO/deploy/packaging/build_server_pkg.py" ] || {
    echo "Can't find the Shikari checkout. Run from inside it or set SHIKARI_REPO." >&2; exit 1; }

if [ "$FORMAT" = auto ]; then
    if command -v dpkg-deb >/dev/null 2>&1 || command -v apt-get >/dev/null 2>&1; then FORMAT=deb
    elif command -v rpmbuild >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then FORMAT=rpm
    else echo "Can't tell deb from rpm here — pass --format deb|rpm." >&2; exit 1; fi
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing '$1' — $2" >&2; exit 1; }; }
need python3 "install Python 3.11+"
if [ "$FORMAT" = deb ]; then need dpkg-deb "apt install dpkg-dev"; else need rpmbuild "dnf install rpm-build"; fi

[ "$(id -u)" = 0 ] || { echo "Run as root (sudo) — it installs a system package." >&2; exit 1; }

echo "==> Building the $FORMAT package (bundled Python; downloads CPython + deps)"
rm -rf "$REPO/dist"
python3 "$REPO/deploy/packaging/build_server_pkg.py" --format "$FORMAT" --out "$REPO/dist"

pkg="$(ls -t "$REPO"/dist/shikari-server*.${FORMAT} 2>/dev/null | head -1)"
[ -n "$pkg" ] || { echo "no .$FORMAT produced in $REPO/dist" >&2; exit 1; }
echo "==> Built $pkg"

echo "==> Installing"
if [ "$FORMAT" = deb ]; then
    apt-get install -y "$pkg" || { dpkg -i "$pkg"; apt-get -f install -y; }
else
    dnf install -y "$pkg" || rpm -i "$pkg"
fi

# Port from the installed config (default 32453).
port="$(. /etc/shikari/shikari.env 2>/dev/null; echo "${SHIKARI_PORT:-32453}")"
echo "==> Waiting for the service on 127.0.0.1:$port"
ok=0
python3 "$here/healthcheck.py" --url "http://127.0.0.1:$port/health" --timeout 120 && ok=1 || true

echo "==> systemctl status:"; systemctl --no-pager --full status shikari || true
if [ "$ok" != 1 ]; then
    echo "==> /health never answered. Recent logs:" >&2
    journalctl -u shikari --no-pager -n 60 || true
fi

if [ "$KEEP" = 1 ]; then
    echo "==> --keep: leaving shikari-server installed and running."
else
    echo "==> Uninstalling (purge)"
    if [ "$FORMAT" = deb ]; then apt-get purge -y shikari-server || dpkg --purge shikari-server
    else dnf remove -y shikari-server || rpm -e shikari-server; rm -rf /var/lib/shikari /etc/shikari; fi
fi

[ "$ok" = 1 ] && echo "PASS" || { echo "FAIL" >&2; exit 1; }
