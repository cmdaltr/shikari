#!/usr/bin/env bash
# restore-elastic-splunk.sh — reintegrate Elastic and/or Splunk after Stage 1 soft-disable.
#
# Background: Elastic and Splunk were soft-disabled on 2026-08-15 (backend
# generation + UI checkboxes removed) via three tagged commits:
#   pre-elastic-stage2            — Elastic disabled on backend
#   pre-splunk-stage2             — Splunk disabled on backend
#   pre-splunk-elastic-ui-stage2  — both removed from UI checkboxes
#
# Usage:
#   bash scripts/restore-elastic-splunk.sh              # generates a review patch (safe, default)
#   bash scripts/restore-elastic-splunk.sh --force       # applies directly, no review step
#
# The --force path is only safe if the affected files (below) haven't been
# meaningfully changed since the disable. When in doubt, use the default
# patch-review mode and read the diff before applying.

set -euo pipefail

REPO_DIR="$HOME/OneDrive/Projects/GitHub/archer"
AFFECTED_FILES="templates/index.html archer/build/detections.py archer/build/yaml.py"
PATCH_FILE="restore-elastic-splunk.patch"

cd "$REPO_DIR"

echo "→ Locating the commit right before Elastic was disabled..."
PRE_DISABLE_COMMIT=$(git log --oneline --grep="Stage 1: soft-disable Elastic" --format="%H" | tail -1)

if [ -z "$PRE_DISABLE_COMMIT" ]; then
    echo "✕ Could not find the 'Stage 1: soft-disable Elastic' commit in history."
    echo "  Run 'git log --oneline | grep Stage' to locate it manually."
    exit 1
fi

PRE_DISABLE_PARENT=$(git rev-parse "${PRE_DISABLE_COMMIT}^")
echo "✓ Found: restoring to state as of commit ${PRE_DISABLE_PARENT:0:8} (just before disable)"

if [[ "${1:-}" == "--force" ]]; then
    echo "→ --force mode: applying directly (no review step)"
    git checkout "$PRE_DISABLE_PARENT" -- $AFFECTED_FILES
    echo "✓ Files restored to pre-disable state. Review 'git status' and 'git diff --staged', then commit:"
    echo "  git commit -m 'Revert: fully restore Elastic and Splunk integration'"
else
    echo "→ Generating review patch (default, safe mode)..."
    git diff pre-splunk-elastic-ui-stage2 "$PRE_DISABLE_PARENT" -- $AFFECTED_FILES > "$PATCH_FILE"

    if [ ! -s "$PATCH_FILE" ]; then
        echo "✕ Generated patch is empty — nothing to restore, or tags/commits have changed."
        rm -f "$PATCH_FILE"
        exit 1
    fi

    echo "✓ Patch written to: $PATCH_FILE"
    echo ""
    echo "Review it with:"
    echo "  less $PATCH_FILE"
    echo ""
    echo "If it looks correct, apply with:"
    echo "  git apply $PATCH_FILE"
    echo ""
    echo "If the affected files have changed significantly since the disable,"
    echo "this patch may not apply cleanly — resolve conflicts manually or"
    echo "re-add the SIEM support by hand using this patch as a reference."
fi
