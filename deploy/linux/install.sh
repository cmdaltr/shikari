#!/usr/bin/env bash
# Install Shikari as a systemd team server on Ubuntu/Debian or Rocky/RHEL 9 (#29).
#
# Runs Shikari as a dedicated `shikari` system user, code in /opt/shikari, data in /var/lib/shikari,
# config in /etc/shikari, under a systemd unit that starts at boot and restarts on failure. Idempotent:
# safe to re-run to pick up a new checkout or dependency changes.
#
# Usage (as root, from a Shikari checkout):
#     sudo deploy/linux/install.sh [--code-dir /opt/shikari] [--data-dir /var/lib/shikari]
#
# TLS, firewall and SELinux port labelling are reported, not forced — see docs/deployment/README.md.
set -euo pipefail

CODE_DIR=/opt/shikari
DATA_DIR=/var/lib/shikari
CONF_DIR=/etc/shikari
SERVICE_USER=shikari
UNIT=/etc/systemd/system/shikari.service

while [ $# -gt 0 ]; do
    case "$1" in
        --code-dir) CODE_DIR=$2; shift 2 ;;
        --data-dir) DATA_DIR=$2; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/../.." && pwd)   # the checkout this script lives in

echo "==> Shikari team-server install"
echo "    code: $CODE_DIR   data: $DATA_DIR   config: $CONF_DIR"

# --- Python 3.11+ ----------------------------------------------------------------------------------
PY=$(command -v python3.12 || command -v python3.11 || command -v python3 || true)
[ -n "$PY" ] || { echo "python3.11+ not found. Install it (apt install python3.11 / dnf install python3.11) and re-run." >&2; exit 1; }
PYV=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
case "$PYV" in 3.1[1-9]|3.[2-9][0-9]) ;; *) echo "Need Python 3.11+, found $PYV ($PY)." >&2; exit 1 ;; esac
echo "    python: $PY ($PYV)"

# --- service user ----------------------------------------------------------------------------------
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    echo "==> creating system user $SERVICE_USER"
    useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
        || useradd --system --home-dir "$DATA_DIR" --shell /sbin/nologin "$SERVICE_USER"
fi

# --- code: sync the checkout into CODE_DIR ---------------------------------------------------------
echo "==> installing code to $CODE_DIR"
mkdir -p "$CODE_DIR"
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete --exclude '.venv' --exclude 'data' --exclude 'bespoke' "$SRC"/ "$CODE_DIR"/
else
    cp -a "$SRC"/. "$CODE_DIR"/
fi

# --- virtualenv + dependencies ---------------------------------------------------------------------
echo "==> building virtualenv"
[ -d "$CODE_DIR/.venv" ] || "$PY" -m venv "$CODE_DIR/.venv"
"$CODE_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$CODE_DIR/.venv/bin/pip" install --quiet -e "$CODE_DIR"

# --- data + config dirs ----------------------------------------------------------------------------
echo "==> laying out $DATA_DIR and $CONF_DIR"
mkdir -p "$DATA_DIR" "$CONF_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
chmod 750 "$DATA_DIR"

if [ ! -f "$CONF_DIR/shikari.env" ]; then
    sed "s#^SHIKARI_HOME=.*#SHIKARI_HOME=$DATA_DIR#" "$HERE/shikari.env.example" > "$CONF_DIR/shikari.env"
    echo "    wrote $CONF_DIR/shikari.env (edit host/port/TLS there)"
else
    echo "    kept existing $CONF_DIR/shikari.env"
fi
chmod 640 "$CONF_DIR/shikari.env"

# --- systemd unit ----------------------------------------------------------------------------------
echo "==> installing systemd unit"
sed -e "s#^WorkingDirectory=.*#WorkingDirectory=$CODE_DIR#" \
    -e "s#^ExecStart=.*#ExecStart=$CODE_DIR/.venv/bin/python -m uvicorn shikari.app:app --host \${SHIKARI_HOST} --port \${SHIKARI_PORT} --workers \${SHIKARI_WORKERS}#" \
    -e "s#^ReadWritePaths=.*#ReadWritePaths=$DATA_DIR#" \
    "$HERE/shikari.service" > "$UNIT"

# --- SELinux (Rocky/RHEL): label the port if it isn't a default http port --------------------------
PORT=$(. "$CONF_DIR/shikari.env"; echo "${SHIKARI_PORT:-8000}")
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
    echo "==> SELinux is enforcing"
    if command -v semanage >/dev/null 2>&1; then
        semanage port -a -t http_port_t -p tcp "$PORT" 2>/dev/null \
            || semanage port -m -t http_port_t -p tcp "$PORT" 2>/dev/null || true
        echo "    labelled tcp/$PORT as http_port_t"
    else
        echo "    semanage not found — install policycoreutils-python-utils and run:"
        echo "      semanage port -a -t http_port_t -p tcp $PORT"
    fi
    command -v restorecon >/dev/null 2>&1 && restorecon -R "$DATA_DIR" || true
fi

# --- enable + (re)start ----------------------------------------------------------------------------
echo "==> enabling and starting shikari.service"
systemctl daemon-reload
systemctl enable shikari.service >/dev/null 2>&1 || true
# restart picks up new code/deps when re-run as an in-place upgrade; start otherwise.
systemctl restart shikari.service

# --- health check ----------------------------------------------------------------------------------
echo "==> waiting for /health"
ok=
for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
done
if [ -n "$ok" ]; then
    echo "    healthy on 127.0.0.1:$PORT"
else
    echo "    NOT healthy yet — check: journalctl -u shikari -n 50" >&2
fi

cat <<EOF

Shikari is installed as a systemd service.
  status:   systemctl status shikari
  logs:     journalctl -u shikari -f
  config:   $CONF_DIR/shikari.env   (restart after changes: systemctl restart shikari)

Next: put TLS in front of it (reverse proxy on 443 -> 127.0.0.1:$PORT) and open the firewall.
See docs/deployment/README.md for TLS, firewall, upgrade, and backup/restore.
EOF
