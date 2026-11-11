#!/usr/bin/env bash
#
# Issue a Shikari Pro licence (licensor only).
#
# A thin wrapper over scripts/admin/sign_licence.py so issuing a licence is one line. It signs a
# licence with YOUR private signing key and writes it to a file the customer installs at
# Assessments -> Report branding -> Licence (or drops in as data/licence.json).
#
# One-time setup:
#   export SHIKARI_LICENCE_KEY=/path/to/your/signing-key.pem      # keep this file safe, never commit it
#   (add that line to your shell profile so it's always set)
#
# Usage:
#   ./scripts/admin/issue-pro.sh "Acme Security Ltd"
#   ./scripts/admin/issue-pro.sh "Acme Security Ltd" ops@acme.example 2027-12-31
#   ./scripts/admin/issue-pro.sh "Acme Security Ltd" ops@acme.example 2027-12-31 pro
#
# Arguments (only the first is required):
#   1  licensee   who the licence is for (quote it if it has spaces)
#   2  email      licensee contact                       (default: none)
#   3  expires    YYYY-MM-DD, or "perpetual"/"-"         (default: 1 year from today)
#   4  features   space/comma list, or "pro" for all     (default: report-branding)
#
# Generate a signing keypair the first time:
#   ./scripts/admin/issue-pro.sh --keygen
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SIGNER="$SCRIPT_DIR/sign_licence.py"

# Prefer the repo venv, else whatever python3 is on PATH.
if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
  PY="$REPO_ROOT/.venv/bin/python"
else
  PY="$(command -v python3 || true)"
fi
[[ -n "$PY" ]] || { echo "error: no python found (expected $REPO_ROOT/.venv/bin/python or python3 on PATH)" >&2; exit 1; }

if [[ "${1:-}" == "--keygen" ]]; then
  exec "$PY" "$SIGNER" keygen
fi

LICENSEE="${1:-}"
if [[ -z "$LICENSEE" ]]; then
  echo "usage: $0 \"Licensee Name\" [email] [YYYY-MM-DD|perpetual] [features|pro]" >&2
  echo "       $0 --keygen" >&2
  exit 1
fi
EMAIL="${2:-}"
EXPIRES="${3:-}"
FEATURES="${4:-report-branding}"

if [[ -z "${SHIKARI_LICENCE_KEY:-}" ]]; then
  echo "error: SHIKARI_LICENCE_KEY is not set — point it at your signing key (PEM)." >&2
  echo "       export SHIKARI_LICENCE_KEY=/path/to/signing-key.pem" >&2
  echo "       (no key yet? run: $0 --keygen)" >&2
  exit 1
fi

# Default expiry: one year out. "perpetual" or "-" means no expiry.
EXPIRES_ARG=()
if [[ -z "$EXPIRES" ]]; then
  if date -v+1y +%Y-%m-%d >/dev/null 2>&1; then
    EXPIRES="$(date -v+1y +%Y-%m-%d)"          # BSD/macOS date
  else
    EXPIRES="$(date -d '+1 year' +%Y-%m-%d)"   # GNU/Linux date
  fi
  EXPIRES_ARG=(--expires "$EXPIRES")
elif [[ "$EXPIRES" != "perpetual" && "$EXPIRES" != "-" ]]; then
  EXPIRES_ARG=(--expires "$EXPIRES")
fi

# Output file named after the licensee: "Acme Security Ltd" -> acme-security-ltd-shikari-licence.json
SLUG="$(printf '%s' "$LICENSEE" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-//;s/-$//')"
OUT="${OUT:-${SLUG}-shikari-licence.json}"

# shellcheck disable=SC2086
"$PY" "$SIGNER" sign \
  --licensee "$LICENSEE" \
  ${EMAIL:+--email "$EMAIL"} \
  --features $FEATURES \
  "${EXPIRES_ARG[@]}" \
  -o "$OUT"

echo
echo "Issued for: $LICENSEE"
echo "Features:   $FEATURES"
echo "Expires:    ${EXPIRES:-perpetual}"
echo "Licence:    $OUT"
echo "Send that file to the customer; they install it under Report branding -> Licence."
