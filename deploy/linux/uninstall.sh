#!/usr/bin/env bash
# Remove the Shikari systemd team server (#29). Keeps data by default.
#
# Usage (as root):
#     sudo deploy/linux/uninstall.sh [--purge]
#
# --purge also removes the data dir (/var/lib/shikari), the config (/etc/shikari) and the service user.
# The code dir (/opt/shikari) is always left in place; remove it by hand if you want it gone.
set -euo pipefail

DATA_DIR=/var/lib/shikari
CONF_DIR=/etc/shikari
SERVICE_USER=shikari
UNIT=/etc/systemd/system/shikari.service
PURGE=

[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" = 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

echo "==> stopping and disabling shikari.service"
systemctl disable --now shikari.service 2>/dev/null || true
rm -f "$UNIT"
systemctl daemon-reload

if [ -n "$PURGE" ]; then
    echo "==> purging data, config and user"
    rm -rf "$DATA_DIR" "$CONF_DIR"
    id "$SERVICE_USER" >/dev/null 2>&1 && userdel "$SERVICE_USER" 2>/dev/null || true
    echo "    removed $DATA_DIR, $CONF_DIR and user $SERVICE_USER"
else
    echo "    kept data ($DATA_DIR) and config ($CONF_DIR). Re-run with --purge to remove them."
fi
