#!/usr/bin/env bash
# One-off cleanup after the archer -> shikari rename.
# Handles the bits the agent sandbox blocked (recursive delete) and refreshes
# package metadata under the new name. Safe to run once, then delete this file.
set -euo pipefail
cd "$(dirname "$0")"

# 1) Remove stale editable-install metadata for the OLD package name.
rm -rf archer.egg-info

# 2) Reinstall so the metadata is regenerated as 'shikari' (idempotent).
if [ -x .venv/bin/pip ]; then
  .venv/bin/pip install -e . --quiet
fi

# 3) Optional: once you're happy the branch is good, the old live DB copy can go.
#    The rename left data/archer.db in place (untracked) as a safety copy; the app
#    now uses data/shikari.db. Uncomment to remove the old copy:
# rm -f data/archer.db

echo "Cleanup done: archer.egg-info removed, package reinstalled as 'shikari'."
