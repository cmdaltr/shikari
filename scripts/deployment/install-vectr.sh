#!/usr/bin/env bash
#
# install-vectr.sh — all-in-one installer for VECTR Community Edition.
#
# Fetches the VECTR CE release, generates the secrets its .env needs, and brings the stack up with
# Docker Compose. Idempotent: re-running keeps the existing .env (so the Postgres credentials and
# data key aren't rotated out from under an initialised database).
#
# VECTR is the campaign/assessment side Archer integrates with (issue #26); this stands up the
# instance that integration needs. See docs/implementation-plans/26-vectr.md.
#
# Prerequisites (per docs.vectr.io): a Docker host on x86-64 — ARM is NOT supported, so run this on
# the Intel homelab box or a Linux VM, not the ARM MacBook. 4+ cores, 8 GB+ RAM, 100 GB+ SSD.
# Docker Engine + the compose plugin (the script offers to install them on Ubuntu if missing).
#
# Usage:
#   sudo ./install-vectr.sh
#   VECTR_HOSTNAME=mac-mini.tail1234.ts.net VECTR_PORT=8081 INSTALL_DIR=/opt/vectr sudo ./install-vectr.sh
#
set -euo pipefail

# ---- Configuration (override via environment) ------------------------------
VECTR_VERSION="${VECTR_VERSION:-9.14.0}"            # VECTR CE release to install
INSTALL_DIR="${INSTALL_DIR:-/opt/vectr}"            # where the release unpacks and runs
VECTR_HOSTNAME="${VECTR_HOSTNAME:-localhost}"       # the name you browse to; IP access redirects here
VECTR_PORT="${VECTR_PORT:-8081}"                    # Tomcat HTTPS port (VECTR is HTTPS only)
POSTGRES_USER="${POSTGRES_USER:-vectr}"
POSTGRES_DB="${POSTGRES_DB:-vectr}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-vectr}"

RELEASE_TAG="ce-${VECTR_VERSION}"
RELEASE_ZIP="sra-vectr-runtime-${VECTR_VERSION}-ce.zip"
RELEASE_URL="https://github.com/SecurityRiskAdvisors/VECTR/releases/download/${RELEASE_TAG}/${RELEASE_ZIP}"

say()  { printf '\033[0;36m[vectr]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[vectr] WARNING:\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[vectr] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ---- Pre-flight ------------------------------------------------------------
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) ;;
  *) warn "architecture is '$arch' — VECTR only supports x86-64. It will not run on ARM. Continuing anyway at your risk." ;;
esac

secret() { openssl rand -base64 "${1:-24}" | tr -d '\n/+=' | cut -c1-"${2:-24}"; }
command -v openssl >/dev/null 2>&1 || die "openssl is required (for generating secrets)."
command -v unzip   >/dev/null 2>&1 || die "unzip is required."

# Docker + compose
if ! command -v docker >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    say "Docker not found. Installing Docker Engine + compose plugin (Ubuntu)…"
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    . /etc/os-release
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  else
    die "Docker not found and this isn't an apt system. Install Docker + the compose plugin, then re-run."
  fi
fi

# Pick the compose command (plugin preferred)
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  die "Docker Compose not found. Install the 'docker compose' plugin and re-run."
fi
docker info >/dev/null 2>&1 || die "Cannot talk to the Docker daemon. Start Docker (or run with sudo) and re-run."

# ---- Fetch and unpack the release -----------------------------------------
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if [ ! -f "$RELEASE_ZIP" ]; then
  say "Downloading VECTR CE ${VECTR_VERSION}…"
  if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$RELEASE_ZIP" "$RELEASE_URL"
  else wget -O "$RELEASE_ZIP" "$RELEASE_URL"; fi
fi
unzip -o -q "$RELEASE_ZIP" -d "$INSTALL_DIR"

# The release ships a docker-compose file and a .env; find the compose file it brought.
COMPOSE_FILE="$(ls -1 "$INSTALL_DIR"/docker-compose*.yml "$INSTALL_DIR"/docker-compose*.yaml 2>/dev/null | head -1 || true)"
[ -n "$COMPOSE_FILE" ] || die "No docker-compose file found in the release — check the zip contents in $INSTALL_DIR."
say "Using compose file: $(basename "$COMPOSE_FILE")"

# ---- .env: generate secrets once, then preserve ---------------------------
ENV_FILE="$INSTALL_DIR/.env"
MARKER="# archer-vectr-installer: configured — do not regenerate (would orphan the database)"

set_env() {  # set_env KEY VALUE — update in place or append
  local key="$1" val="$2"
  if grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
    # use a non-/ delimiter since values may contain base64 chars
    sed -i.bak -E "s|^${key}=.*|${key}=${val}|" "$ENV_FILE" && rm -f "${ENV_FILE}.bak"
  else
    printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"
  fi
}

if grep -q "archer-vectr-installer" "$ENV_FILE" 2>/dev/null; then
  say "Existing configured .env found — keeping its secrets. Updating hostname/port only."
  set_env VECTR_HOSTNAME "$VECTR_HOSTNAME"
  set_env VECTR_PORT "$VECTR_PORT"
else
  say "Generating a fresh .env with new secrets…"
  [ -f "$ENV_FILE" ] || : > "$ENV_FILE"   # the release .env is the base if present
  # Two distinct keys, >=16 chars, as VECTR requires.
  JWS_KEY="$(secret 32 32)"
  JWE_KEY="$(secret 32 32)"
  [ "$JWS_KEY" != "$JWE_KEY" ] || JWE_KEY="$(secret 32 32)x"
  set_env VECTR_HOSTNAME       "$VECTR_HOSTNAME"
  set_env VECTR_PORT           "$VECTR_PORT"
  set_env POSTGRES_USER        "$POSTGRES_USER"
  set_env POSTGRES_DB          "$POSTGRES_DB"
  set_env POSTGRES_PASSWORD    "$(secret 24 24)"
  set_env VECTR_DATA_KEY       "$(secret 32 32)"
  set_env JWS_KEY              "$JWS_KEY"
  set_env JWE_KEY              "$JWE_KEY"
  set_env COMPOSE_PROJECT_NAME "$COMPOSE_PROJECT_NAME"
  printf '%s\n' "$MARKER" >> "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  say "Secrets written to $ENV_FILE (chmod 600). Back this file up — it holds the data key."
fi

# Hostname resolution reminder: VECTR redirects IP access to VECTR_HOSTNAME.
if [ "$VECTR_HOSTNAME" != "localhost" ] && ! getent hosts "$VECTR_HOSTNAME" >/dev/null 2>&1; then
  warn "'$VECTR_HOSTNAME' does not resolve on this host. Add it to DNS, or to /etc/hosts, or you won't be able to log in:"
  warn "    echo '127.0.0.1 $VECTR_HOSTNAME' | sudo tee -a /etc/hosts"
fi

# ---- Bring it up -----------------------------------------------------------
say "Starting VECTR (first run pulls images from Docker Hub — this takes a few minutes)…"
$COMPOSE -f "$COMPOSE_FILE" up -d

say "Waiting for VECTR to answer on https://${VECTR_HOSTNAME}:${VECTR_PORT} …"
URL="https://${VECTR_HOSTNAME}:${VECTR_PORT}/"
for _ in $(seq 1 60); do
  code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$URL" || true)"
  case "$code" in
    200|302|401) ready=1; break ;;
  esac
  sleep 10
done

echo
if [ "${ready:-}" = "1" ]; then
  say "VECTR is up."
else
  warn "VECTR didn't answer yet — it can take several minutes on first boot. Check: $COMPOSE -f '$COMPOSE_FILE' logs -f"
fi

cat <<EOF

────────────────────────────────────────────────────────────────────────
 VECTR CE ${VECTR_VERSION}
────────────────────────────────────────────────────────────────────────
 URL:       https://${VECTR_HOSTNAME}:${VECTR_PORT}   (HTTPS only; self-signed cert — accept the warning)
 Login:     admin  /  11_ThisIsTheFirstPassword_11    (change it immediately: Profile menu)

 Next, for the Archer integration (#26):
   1. Change the admin password.
   2. Profile icon (top right) -> Profile -> API Key tab -> Create API Key.
      Copy the ID and Secret now — the secret is shown only once.
   3. Archer auth header:  Authorization: VEC1 <key_id>:<key_secret>
   4. GraphQL endpoint:    https://${VECTR_HOSTNAME}:${VECTR_PORT}/sra-purpletools-rest/graphql
      (queries take a 'db' argument, e.g. db: "FS_THREAT_INDEX")

 Manage:
   Stop:     $COMPOSE -f "$COMPOSE_FILE" down
   Logs:     $COMPOSE -f "$COMPOSE_FILE" logs -f
   Config:   $ENV_FILE   (back this up — it holds VECTR_DATA_KEY)
────────────────────────────────────────────────────────────────────────
EOF
