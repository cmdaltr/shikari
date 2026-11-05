#!/usr/bin/env bash
# Stand up a local VECTR community edition for the #26 integration work.
#
# VECTR ships its own docker compose bundle (app + MongoDB + generated TLS) as a release asset, so this
# fetches that bundle rather than hand-rolling a compose file that would drift from theirs. It pins a
# version (override with VECTR_VERSION=...), downloads the release with `gh`, unpacks it, and brings it
# up. First launch builds the DB and can take a few minutes.
#
#   scripts/vectr/up.sh            # fetch + start
#   scripts/vectr/up.sh down       # stop (keeps data volumes)
#   VECTR_VERSION=ce-9.13.1 scripts/vectr/up.sh
#
# Needs: docker (with the compose plugin) and gh (authenticated). ~2GB of images on first pull.
set -euo pipefail

VERSION="${VECTR_VERSION:-ce-9.13.1}"
REPO="SecurityRiskAdvisors/VECTR"
DEST="${VECTR_DIR:-$HOME/.cache/shikari/vectr/$VERSION}"
ACTION="${1:-up}"

have() { command -v "$1" >/dev/null 2>&1; }
compose() {
  if docker compose version >/dev/null 2>&1; then docker compose "$@"
  elif have docker-compose; then docker-compose "$@"
  else echo "No docker compose plugin or docker-compose binary found." >&2; exit 1; fi
}

find_compose_dir() {
  # The release layout nests the compose file; find the directory that holds it.
  local f
  f="$(find "$DEST" -maxdepth 3 -iname 'docker-compose*.yml' | head -1 || true)"
  [ -n "$f" ] && dirname "$f"
}

if [ "$ACTION" = "down" ]; then
  dir="$(find_compose_dir || true)"
  [ -z "${dir:-}" ] && { echo "Nothing to stop: no bundle under $DEST"; exit 0; }
  ( cd "$dir" && compose down )
  echo "Stopped. Data volumes kept (use 'docker volume ls' / 'docker volume rm' to purge)."
  exit 0
fi

have docker || { echo "docker is required." >&2; exit 1; }
have gh || { echo "gh (GitHub CLI) is required to download the release. See https://cli.github.com" >&2; exit 1; }

if [ -z "$(find_compose_dir || true)" ]; then
  echo ">> Downloading VECTR $VERSION from $REPO ..."
  mkdir -p "$DEST"
  gh release download "$VERSION" -R "$REPO" -D "$DEST" --clobber \
    || { echo "Release download failed. List versions: gh release list -R $REPO" >&2; exit 1; }
  # Unpack any archive assets the release shipped (zip/tgz), leaving plain compose assets in place.
  shopt -s nullglob
  for z in "$DEST"/*.zip;      do unzip -oq "$z" -d "$DEST"; done
  for t in "$DEST"/*.tar.gz "$DEST"/*.tgz; do tar -xzf "$t" -C "$DEST"; done
  shopt -u nullglob
fi

dir="$(find_compose_dir || true)"
[ -z "${dir:-}" ] && {
  echo "Could not find a docker-compose file under $DEST after download." >&2
  echo "Inspect $DEST and the release notes: https://github.com/$REPO/releases/tag/$VERSION" >&2
  exit 1
}

echo ">> Bringing VECTR up from: $dir"
echo "   (first run builds the database and generates a self-signed cert; give it a few minutes)"
( cd "$dir" && compose up -d )

cat <<EOF

VECTR is starting. When it is healthy:
  UI:       https://localhost:8081   (self-signed cert — your browser will warn)
  GraphQL:  https://localhost:8081/sra-purpletools-rest/graphql

First login: the default admin credentials and the forced password change are in the bundle's own
README under $dir (they vary by release — do not assume). Then create an API key in Administration
(it is shown only once), and probe the schema:

  export VECTR_API_KEY='keyId:secret'
  .venv/bin/python scripts/vectr/probe_schema.py

Stop it later with:  scripts/vectr/up.sh down
EOF
