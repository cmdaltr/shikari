#!/usr/bin/env bash
# The KVM/libvirt lifecycle test: an Ubuntu 24.04 cloud-image VM made from the ubuntu-kvm template,
# taken through create, start, exec, snapshot, change, revert, check, stop and delete.
# Run inside the Ubuntu VM from the Shikari checkout, once prepare-kvm-host.sh is done.
#
#   bash scripts/lab/host-engine-tests/run-kvm.sh [--keep] [--name NAME]
set -euo pipefail
cd "$(dirname "$0")/../../.."
[ -x .venv/bin/python ] || { echo "No .venv here: python3 -m venv .venv && .venv/bin/pip install -e ." >&2; exit 1; }
id -nG | grep -qw libvirt || { echo "Not in the libvirt group yet: sign out and in, or newgrp libvirt" >&2; exit 1; }
exec .venv/bin/python scripts/lab/host-engine-tests/lifecycle.py --engine libvirt --template ubuntu-kvm "$@"
