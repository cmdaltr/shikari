#!/usr/bin/env bash
# caldera-lab.sh — stand up / tear down a disposable CALDERA 5.2 lab for Archer (#30).
#
#   caldera-lab.sh up               build+run the server, create the agent machines, enrol them
#   caldera-lab.sh status           print URL, red key, group, agent count
#   caldera-lab.sh agents           list every agent (paw, host, trusted, last seen)
#   caldera-lab.sh config           print the caldera: block for Archer's bespoke/config.yaml
#   caldera-lab.sh down             delete the agent machines  (STOP_SERVER=1 also stops the server)
#   caldera-lab.sh win <vm>         install + run the agent on an existing UTM Windows VM (group WIN_GROUP)
#   caldera-lab.sh mac <vm>         create (if needed) a Tart macOS VM and enrol the agent (group MAC_GROUP)
#   caldera-lab.sh capture-test <vm>  run a Windows operation and validate endpoint-log capture
#
# Tunables (env): COUNT=2 GROUP=disposable DISTRO=ubuntu PREFIX=cal TAG=5.2.0
#                 WIN_GROUP=winlab  MAC_GROUP=maclab  MAC_IMAGE=ghcr.io/cirruslabs/macos-sequoia-base:latest
#                 REPO=<archer-caldera checkout>  CANON=<checkout with data/groups>
#
# Assumptions: macOS host, Docker (OrbStack) for the server, OrbStack Linux machines for the
# agents (reached over `ssh <name>@orb`). Everything is idempotent — re-run `up` any time.
set -euo pipefail

COUNT="${COUNT:-2}"; GROUP="${GROUP:-disposable}"
DISTRO="${DISTRO:-ubuntu}"; PREFIX="${PREFIX:-cal}"; TAG="${TAG:-5.2.0}"
WIN_GROUP="${WIN_GROUP:-winlab}"
MAC_GROUP="${MAC_GROUP:-maclab}"
# cirruslabs' macOS base images ship the Tart guest agent and an admin/admin login, so `tart exec`
# drives them with nothing to install. The first pull is large (~25–30 GB).
MAC_IMAGE="${MAC_IMAGE:-ghcr.io/cirruslabs/macos-sequoia-base:latest}"
# This script lives in scripts/telemetry/, so the repo root is two levels up. REPO is the checkout
# whose code + venv capture-test uses; CANON is a checkout whose data/groups holds the detections to
# check against (the same one by default). Override either with an env var when running a copy.
SELF_REPO="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." 2>/dev/null && pwd || true)"
REPO="${REPO:-${SELF_REPO:-$PWD}}"
CANON="${CANON:-$REPO}"
SRC="$HOME/caldera-src"; WORK="$HOME/.caldera-lab"
mkdir -p "$WORK"

# The Mac's LAN IP on its default route — the address agents and the sandbox reach the server on.
lan_ip() { ipconfig getifaddr "$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')" 2>/dev/null; }
# The red API key, read from the running container's config (never printed to a log by the server).
redkey() { docker exec caldera sh -c "grep -h api_key_red conf/*.yml | head -1 | awk '{print \$2}'" 2>/dev/null; }

server_up() {
  if ! docker ps --format '{{.Names}}' | grep -qx caldera; then
    if ! docker image inspect caldera:5.2 >/dev/null 2>&1; then
      echo ">> cloning + building CALDERA $TAG (first run only; this is slow)…"
      rm -rf "$SRC"
      git clone --branch "$TAG" --recursive --depth 1 https://github.com/mitre/caldera.git "$SRC"
      ( cd "$SRC" && docker build --build-arg VARIANT=full -t caldera:5.2 . )
    fi
    echo ">> starting the server…"
    docker rm -f caldera >/dev/null 2>&1 || true
    # The image entrypoint is already `python server.py`, so pass ONLY flags here.
    docker run -d --name caldera --restart unless-stopped \
      -p 8888:8888 -p 7010:7010 -p 7011:7011/udp -p 7012:7012 \
      caldera:5.2 --insecure >/dev/null
  fi
  echo ">> waiting for the server…"
  for _ in $(seq 1 90); do
    [ "$(docker inspect -f '{{.State.Status}}' caldera 2>/dev/null)" = running ] \
      && curl -sf http://127.0.0.1:8888/ >/dev/null 2>&1 && return 0
    sleep 2
  done
  echo "!! server did not come up"; docker logs caldera 2>&1 | tail -20; exit 1
}

enrol() {  # $1 = machine name; downloads the agent once, copies it in, runs it with a fixed paw
  local m="$1" ip; ip="$(lan_ip)"
  orb list 2>/dev/null | awk '{print $1}' | grep -qx "$m" || { echo ">> creating machine $m"; orb create "$DISTRO" "$m"; }
  [ -s "$WORK/sc" ] || curl -s -XPOST -Hfile:sandcat.go -Hplatform:linux "http://$ip:8888/file/download" -o "$WORK/sc"
  scp -q "$WORK/sc" "$m@orb:~/sc"
  # Fixed -paw = stable identity, so re-running never multiplies agents. Kill any prior one first.
  ssh "$m@orb" "chmod +x ~/sc; pkill -f -- '-server http://' 2>/dev/null; sleep 1; \
    nohup ~/sc -paw $m -server http://$ip:8888 -group $GROUP -v >/tmp/sc.log 2>&1 & \
    sleep 1; echo \"   $m: \$(pgrep -c sc) agent process\""
}

cmd_up() {
  server_up
  rm -f "$WORK/sc"   # a fresh agent each 'up', in case the server image was rebuilt
  for n in $(seq 1 "$COUNT"); do enrol "$PREFIX$n"; done
  cmd_status
}

cmd_status() {
  local ip k n; ip="$(lan_ip)"; k="$(redkey)"
  n="$(curl -s -H "KEY: $k" "http://$ip:8888/api/v2/agents" 2>/dev/null | grep -o '"paw"' | wc -l | tr -d ' ')"
  echo "================ CALDERA lab ================"
  echo "  URL    : http://$ip:8888   (UI login red / admin)"
  echo "  Key    : $k"
  echo "  Group  : $GROUP"
  echo "  Agents : ${n:-0} total (includes any aged-out duplicates)"
  echo "  Config : $0 config   # the block for Archer's bespoke/config.yaml"
  echo "============================================"
}

cmd_agents() {
  local ip k; ip="$(lan_ip)"; k="$(redkey)"
  curl -s -H "KEY: $k" "http://$ip:8888/api/v2/agents" 2>/dev/null \
    | python3 -c "import sys,json;[print(f\"  {a['paw']:10} host={a.get('host','?'):8} trusted={a.get('trusted')} seen={a.get('last_seen')}\") for a in json.load(sys.stdin)]" \
    || echo "  (no agents, or could not parse)"
}

cmd_config() {
  local ip k; ip="$(lan_ip)"; k="$(redkey)"
  printf 'caldera:\n  url: "http://%s:8888"\n  api_key: "%s"\n  verify_tls: false\n' "$ip" "$k"
}

cmd_win() {   # $1 = an existing UTM Windows VM name (build it + install SPICE guest tools first)
  local vm="${1:-${VM:-}}" ip; ip="$(lan_ip)"
  [ -n "$vm" ] || { echo "usage: $0 win <utm-windows-vm-name>   (names: utmctl list)"; exit 2; }
  command -v utmctl >/dev/null || { echo "!! utmctl not found — is UTM installed?"; exit 1; }

  echo ">> starting UTM VM $vm…"; utmctl start --hide "$vm" 2>/dev/null || true
  echo ">> waiting for the QEMU guest agent (needs UTM's SPICE guest tools in the VM)…"
  local ok=0 out
  for _ in $(seq 1 24); do
    # Check the actual output, not the exit code — utmctl exec returns 0 even when the agent is dead.
    out="$(utmctl exec --hide "$vm" --cmd cmd /c echo utmok 2>/dev/null)"
    case "$out" in *utmok*) ok=1; break;; esac
    sleep 5
  done
  [ "$ok" = 1 ] || { echo "!! QEMU guest agent not responding in $vm — install UTM's SPICE guest tools (it includes the QEMU Guest Agent service), reboot, then re-run."; exit 1; }

  echo ">> downloading the Windows agent on the Mac…"
  curl -s -XPOST -Hfile:sandcat.go -Hplatform:windows "http://$ip:8888/file/download" -o "$WORK/sc.exe"
  [ -s "$WORK/sc.exe" ] || { echo "!! agent download failed"; exit 1; }

  echo ">> pushing the agent into C:\\Windows\\Temp\\sc.exe…"
  local push='$b=[Console]::In.ReadToEnd(); [IO.File]::WriteAllBytes("C:\Windows\Temp\sc.exe",[Convert]::FromBase64String($b))'
  base64 < "$WORK/sc.exe" | utmctl exec --hide "$vm" --input --cmd powershell -NoProfile -Command "$push"

  echo ">> installing PowerShell 7 (optional — capture uses Windows PowerShell 5.1, so this is best-effort)…"
  local pwsh='try { winget install --id Microsoft.PowerShell -e --accept-package-agreements --accept-source-agreements | Out-Null; "pwsh installed" } catch { "winget unavailable — skipping (not needed for capture)" }'
  utmctl exec --hide "$vm" --cmd powershell -NoProfile -Command "$pwsh" 2>/dev/null || echo "   (pwsh step skipped)"

  echo ">> starting the agent in group '$WIN_GROUP' (paw=$vm)…"
  local run="Start-Process -WindowStyle Hidden 'C:\\Windows\\Temp\\sc.exe' -ArgumentList '-server','http://$ip:8888','-group','$WIN_GROUP','-paw','$vm','-v'"
  utmctl exec --hide "$vm" --cmd powershell -NoProfile -Command "$run"
  sleep 3
  echo ">> done. Confirm it enrolled:  $0 agents   (look for host=$vm group=$WIN_GROUP)"
}

cmd_mac() {   # $1 = a Tart macOS VM name; clones the base image if it doesn't exist, then enrols the agent
  local vm="${1:-${VM:-}}" ip; ip="$(lan_ip)"
  [ -n "$vm" ] || { echo "usage: $0 mac <tart-macos-vm-name>"; exit 2; }
  command -v tart >/dev/null || { echo "!! tart not found — install it: brew install cirruslabs/cli/tart"; exit 1; }

  # Unlike UTM, Tart can create from an image, so this is as turnkey as the Linux lab: clone if the
  # VM isn't there yet (the agent then runs in a disposable VM, never on this Mac).
  if ! tart list --format json 2>/dev/null | grep -q "\"$vm\""; then
    echo ">> cloning the macOS base image into $vm (first pull is large; slow)…"
    tart clone "$MAC_IMAGE" "$vm"
  fi

  echo ">> starting $vm headless…"
  tart run "$vm" --no-graphics >/dev/null 2>&1 &
  echo ">> waiting for the Tart guest agent…"
  local ok=0
  for _ in $(seq 1 60); do
    tart exec "$vm" true 2>/dev/null && { ok=1; break; }
    sleep 5
  done
  [ "$ok" = 1 ] || { echo "!! guest agent not responding in $vm — check 'tart run $vm' opens, then re-run."; exit 1; }

  echo ">> downloading the macOS agent on the Mac…"
  curl -s -XPOST -Hfile:sandcat.go -Hplatform:darwin "http://$ip:8888/file/download" -o "$WORK/sc-mac"
  [ -s "$WORK/sc-mac" ] || { echo "!! agent download failed"; exit 1; }

  # The binary is written inside the guest (not downloaded there), so it carries no quarantine xattr
  # and runs without Gatekeeper prompts. Fixed -paw = stable identity; kill any prior one first.
  echo ">> pushing + starting the agent in group '$MAC_GROUP' (paw=$vm)…"
  base64 < "$WORK/sc-mac" | tart exec "$vm" bash -lc \
    "base64 -d > ~/sc; chmod +x ~/sc; pkill -f -- '-server http://' 2>/dev/null; sleep 1; \
     nohup ~/sc -paw '$vm' -server http://$ip:8888 -group '$MAC_GROUP' -v >/tmp/sc.log 2>&1 & \
     sleep 1; echo \"   $vm: \$(pgrep -c sc) agent process\""
  echo ">> done. Confirm it enrolled:  $0 agents   (look for host=$vm group=$MAC_GROUP)"
}

cmd_capture_test() {   # $1 = the UTM Windows VM running an agent in WIN_GROUP
  local vm="${1:-${VM:-}}"
  [ -n "$vm" ] || { echo "usage: $0 capture-test <utm-windows-vm-name>"; exit 2; }
  # A macOS Python with the project deps. The checkout's .venv is the sandbox's (Linux) one, so use
  # a separate macOS venv. Override with PY=/path/to/python if you keep deps elsewhere.
  local PY="${PY:-$REPO/.venv-mac/bin/python}"
  [ -x "$PY" ] || { echo "!! no macOS python at $PY"; \
    echo "   create one once:  cd '$REPO' && python3 -m venv .venv-mac && .venv-mac/bin/pip install -r requirements.txt"; \
    echo "   or run with:      PY=/path/to/python $0 capture-test $vm"; exit 1; }
  [ -d "$CANON/data/groups" ] || { echo "!! no detections at $CANON/data/groups — set CANON to a checkout with them"; exit 1; }

  local home="$WORK/archer-home"
  mkdir -p "$home/bespoke" "$home/data/telemetry"
  "$0" config > "$home/bespoke/config.yaml"
  echo ">> running the full Windows flow on the Mac (operate → collect → capture → check)…"
  ( cd "$REPO" && ARCHER_HOME="$home" "$PY" - "$vm" "$CANON/data/groups" "$WIN_GROUP" <<'PY'
import sys
from archer.lab import caldera as c
vm, gen, group = sys.argv[1], sys.argv[2], sys.argv[3]
log = lambda m: print("  ", m)
client = c.Client.from_settings()
techs = c.resolve_techniques("technique", "T1033,T1082,T1057", gen)
print(">> operate", techs, "on", group)
run = c.operate(client, techs, group, name="win-capture", execute=True, say=log)
print(">> state:", c.wait(client, run["operation_id"], say=log))
m = c.collect(client, run["operation_id"], say=log, rebuild=False)
print(">> collected", len(m["steps"]), "step(s) on", sorted({s["host"] for s in m["steps"]}))
m = c.capture("utm", vm, "windows", m, say=log)
print(">> captured flag:", m.get("captured"))
from archer.telemetry.lab import runs
print(">> lab runs now:", [r[0] for r in runs()])
res = c.check_operation(m, gen)
print(">> check evidence:", res["evidence"], "| summary:", res["summary"])
PY
  )
}

cmd_down() {
  for m in $(orb list 2>/dev/null | awk '{print $1}' | grep "^$PREFIX[0-9]"); do
    echo ">> deleting machine $m"; orb delete "$m" 2>/dev/null || orb delete -f "$m" 2>/dev/null || true
  done
  if [ "${STOP_SERVER:-0}" = 1 ]; then echo ">> stopping the server"; docker rm -f caldera >/dev/null 2>&1 || true; fi
  echo ">> done"
}

case "${1:-up}" in
  up) cmd_up ;;
  status) cmd_status ;;
  agents) cmd_agents ;;
  config) cmd_config ;;
  win) shift; cmd_win "${1:-}" ;;
  mac) shift; cmd_mac "${1:-}" ;;
  capture-test) shift; cmd_capture_test "${1:-}" ;;
  down) cmd_down ;;
  *) echo "usage: $0 up|status|agents|config|win <vm>|mac <vm>|capture-test <vm>|down"; exit 2 ;;
esac
