#!/usr/bin/env bash
# Turn on nested virtualisation (and set CPUs and memory) for a VMware Fusion VM, by editing its
# .vmx with the VM powered off. This is Fusion's "Virtualize Intel VT-x/EPT or AMD-V/RVI" tick
# box (Settings > Processors & Memory > Advanced options), written as vhv.enable = "TRUE".
#
# Run it on the Mac Mini, or from the MacBook:
#   ssh macmini 'bash -s' -- "<path to .vmx>" 4 12288 < scripts/lab/host-engine-tests/fusion-nested.sh
#
#   fusion-nested.sh <path to .vmx> [cpus] [memory MB]
#
# It refuses to touch a running VM (Fusion rewrites the .vmx on shutdown and would undo the edit),
# keeps a .vmx.bak beside the original, and prints the keys it set.
set -euo pipefail

vmx=${1:?usage: fusion-nested.sh <path to .vmx> [cpus] [memory MB]}
cpus=${2:-4}
mem=${3:-8192}
vmrun="/Applications/VMware Fusion.app/Contents/Library/vmrun"

[ -f "$vmx" ] || { echo "No such .vmx: $vmx" >&2; exit 1; }
[ -x "$vmrun" ] || { echo "vmrun not found at $vmrun (is VMware Fusion installed?)" >&2; exit 1; }
if "$vmrun" -T fusion list | tail -n +2 | grep -Fxq "$vmx"; then
  echo "The VM is running. Shut it down first:  \"$vmrun\" -T fusion stop \"$vmx\" soft" >&2
  exit 1
fi
if grep -q '^encryption\.data' "$vmx" && ! grep -q '^memsize' "$vmx"; then
  # A fully encrypted VM keeps its settings inside encryption.data, out of reach of a text edit.
  # (A VM encrypted only for its vTPM keeps them in plain text, and is edited as normal.)
  echo "This VM's settings are encrypted: set Processors & Memory > Advanced options in Fusion instead." >&2
  exit 1
fi

cp -p "$vmx" "$vmx.bak"

set_key() {  # replace key = "..." in place, or append it
  local key=$1 value=$2
  if grep -qE "^${key//./\\.} *=" "$vmx"; then
    sed -i '' -E "s|^${key//./\\.} *=.*|${key} = \"${value}\"|" "$vmx"
  else
    printf '%s = "%s"\n' "$key" "$value" >> "$vmx"
  fi
}

set_key vhv.enable TRUE
set_key numvcpus "$cpus"
set_key cpuid.coresPerSocket "$cpus"
set_key memsize "$mem"

echo "Set in $vmx (backup: $vmx.bak):"
grep -E '^(vhv\.enable|numvcpus|cpuid\.coresPerSocket|memsize) ' "$vmx"
echo "Start it with:  \"$vmrun\" -T fusion start \"$vmx\" nogui"
