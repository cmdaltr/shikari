#!/usr/bin/env bash
# Verify the Windows server bundle on a throwaway Azure VM, entirely from the CLI (#29).
#
# Creates a Windows Server 2022 B2s, pushes a build+install+smoke script to it with `az vm run-command`
# (no RDP, no inbound ports opened), prints PASS/FAIL, and deletes the whole resource group. On the $200
# Azure trial credit a run of an hour or two is effectively free; outside it, a B2s is ~$0.10-0.15/hr
# (Windows licence included) — so create, verify, delete in one sitting.
#
# Prerequisites on your Mac:
#   brew install azure-cli        # the `az` CLI
#   az login                      # sign in (opens a browser once)
#   export GITHUB_TOKEN=ghp_...   # a token that can READ cmdaltr/shikari (fine-grained, contents:read)
#
# Then:
#   ./azure-windows-verify.sh                 # x64, auto-teardown
#   REF=main ./azure-windows-verify.sh        # a branch/tag/sha other than main
#   KEEP=1 ./azure-windows-verify.sh          # leave the VM up (delete it yourself afterwards!)
set -euo pipefail

: "${GITHUB_TOKEN:?set GITHUB_TOKEN to a token that can read cmdaltr/shikari}"
REPO_SLUG="${REPO_SLUG:-cmdaltr/shikari}"
REF="${REF:-main}"
LOCATION="${LOCATION:-uksouth}"
RG="${RG:-shikari-verify-$RANDOM}"
VM="${VM:-win}"
ADMIN_USER="${ADMIN_USER:-shikariadmin}"
# A fresh random admin password (never reused, VM is thrown away). Meets Azure's complexity rule.
ADMIN_PASS="${ADMIN_PASS:-Sk$(openssl rand -hex 8)!A9}"

command -v az >/dev/null || { echo "az CLI not found — brew install azure-cli" >&2; exit 1; }

cleanup() {
    if [ "${KEEP:-0}" = 1 ]; then
        echo "KEEP=1: leaving $RG up. Delete it with: az group delete -n $RG --yes --no-wait"
    else
        echo "==> Deleting resource group $RG"
        az group delete -n "$RG" --yes --no-wait || true
    fi
}
trap cleanup EXIT

echo "==> Resource group $RG in $LOCATION"
az group create -n "$RG" -l "$LOCATION" -o none

echo "==> Creating Windows Server 2022 B2s (no inbound ports; run-command only)"
az vm create -g "$RG" -n "$VM" \
    --image MicrosoftWindowsServer:WindowsServer:2022-datacenter-azure-edition:latest \
    --size Standard_B2s \
    --admin-username "$ADMIN_USER" --admin-password "$ADMIN_PASS" \
    --public-ip-sku Standard --nsg-rule NONE -o none
echo "    VM up (admin: $ADMIN_USER / $ADMIN_PASS — throwaway)"

# The PowerShell that runs ON the VM: fetch the repo as a zip (token in a header, no git needed), build
# the bundle, install the service, wait on /health, print PASS/FAIL. $slug/$ref/$tok come in as params.
read -r -d '' REMOTE <<'PS1' || true
param($slug, $ref, $tok)
$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'
$root = "$env:TEMP\shikari-verify"; Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $root | Out-Null
Write-Host "Downloading $slug@$ref"
Invoke-WebRequest -UseBasicParsing -Headers @{ Authorization = "Bearer $tok"; 'User-Agent' = 'shikari-verify' } `
    "https://api.github.com/repos/$slug/zipball/$ref" -OutFile "$root\src.zip"
Expand-Archive "$root\src.zip" "$root\src"
$repo = (Get-ChildItem "$root\src" -Directory | Select-Object -First 1).FullName
Write-Host "Repo at $repo"
& "$repo\deploy\packaging\verify\verify-windows.ps1"
exit $LASTEXITCODE
PS1

echo "==> Running build+install+smoke on the VM (this is where it spends its time)"
set +e
out=$(az vm run-command invoke -g "$RG" -n "$VM" --command-id RunPowerShellScript \
    --scripts "$REMOTE" \
    --parameters "slug=$REPO_SLUG" "ref=$REF" "tok=$GITHUB_TOKEN" \
    --query 'value[].message' -o tsv)
rc=$?
set -e
echo "----- VM output -----"; echo "$out"; echo "---------------------"

if [ $rc -eq 0 ] && echo "$out" | grep -q "PASS"; then
    echo "AZURE VERIFY: PASS"
else
    echo "AZURE VERIFY: FAIL" >&2
    exit 1
fi
