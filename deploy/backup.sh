#!/usr/bin/env bash
# Back up or restore a Shikari team server's data (#29): the database, bespoke/ config and telemetry —
# everything under SHIKARI_HOME. Code is not backed up (it's a checkout; reinstall it).
#
# Usage:
#   deploy/backup.sh backup  [--data-dir /var/lib/shikari] [--out /path/shikari-backup-DATE.tar.gz]
#   deploy/backup.sh restore <archive.tar.gz> [--data-dir /var/lib/shikari]
#
# Stop the service around a restore: systemctl stop shikari && ... && systemctl start shikari
set -euo pipefail

DATA_DIR=/var/lib/shikari
CMD=${1:-}; shift || true
OUT=

ARCHIVE=
while [ $# -gt 0 ]; do
    case "$1" in
        --data-dir) DATA_DIR=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) ARCHIVE=$1; shift ;;
    esac
done

case "$CMD" in
    backup)
        OUT=${OUT:-"shikari-backup-$(date +%Y%m%d-%H%M%S).tar.gz"}
        [ -d "$DATA_DIR" ] || { echo "no data dir at $DATA_DIR" >&2; exit 1; }
        # -C the parent so the archive holds a single top-level dir.
        tar -czf "$OUT" -C "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")"
        echo "backed up $DATA_DIR -> $OUT ($(du -h "$OUT" | cut -f1))"
        ;;
    restore)
        [ -n "$ARCHIVE" ] && [ -f "$ARCHIVE" ] || { echo "give an archive: deploy/backup.sh restore <file.tar.gz>" >&2; exit 1; }
        systemctl is-active --quiet shikari 2>/dev/null && \
            echo "WARNING: shikari is running — stop it first (systemctl stop shikari)." >&2
        mkdir -p "$DATA_DIR"
        tar -xzf "$ARCHIVE" -C "$(dirname "$DATA_DIR")"
        command -v restorecon >/dev/null 2>&1 && restorecon -R "$DATA_DIR" 2>/dev/null || true
        echo "restored $ARCHIVE -> $DATA_DIR. Start the service: systemctl start shikari"
        ;;
    *)
        echo "usage: deploy/backup.sh backup|restore [...]" >&2; exit 2 ;;
esac
