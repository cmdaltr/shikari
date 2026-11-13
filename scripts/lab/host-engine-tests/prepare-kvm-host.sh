#!/usr/bin/env bash
# Prepare an Ubuntu Server 24.04 VM to be a KVM/libvirt host for Shikari: check nested
# virtualisation reached it, install QEMU/KVM, libvirt and virt-install, make sure the default
# NAT network and storage pool exist, and put this user in the libvirt and kvm groups.
# Run it inside the Ubuntu VM, as the user who will run Shikari (it uses sudo).
#
#   bash scripts/lab/host-engine-tests/prepare-kvm-host.sh
#
# Safe to run again. It doesn't install Shikari (see the README) or create any VM.
set -euo pipefail

say() { printf '\n== %s\n' "$*"; }

say "CPU virtualisation flags (nested virtualisation from Fusion)"
flags=$(grep -cE '(vmx|svm)' /proc/cpuinfo || true)
echo "vCPUs with vmx/svm: $flags"
if [ "$flags" -eq 0 ]; then
  echo "None: vhv.enable isn't on for this VM. Power it off and run fusion-nested.sh on the Mini." >&2
  exit 1
fi

say "Packages"
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  qemu-system-x86 qemu-utils libvirt-daemon-system libvirt-clients virtinst cpu-checker \
  python3-venv python3-pip git rsync

say "kvm-ok"
sudo kvm-ok  # expect: INFO: /dev/kvm exists / KVM acceleration can be used

say "libvirt daemon"
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt,kvm "$USER"

say "Default NAT network"
if ! sudo virsh net-info default >/dev/null 2>&1; then
  sudo virsh net-define /usr/share/libvirt/networks/default.xml
fi
sudo virsh net-autostart default >/dev/null
sudo virsh net-info default | grep -q 'Active: *yes' || sudo virsh net-start default
# libvirt's default network is 192.168.122.0/24; it mustn't be the subnet this VM sits on
if ip -4 route | grep -q '^192\.168\.122\.0/24 .* dev ens'; then
  echo "WARNING: this VM's own network is 192.168.122.0/24, the same as libvirt's default." >&2
fi

say "Default storage pool"
if ! sudo virsh pool-info default >/dev/null 2>&1; then
  sudo virsh pool-define-as default dir --target /var/lib/libvirt/images
  sudo virsh pool-build default
fi
sudo virsh pool-autostart default >/dev/null
sudo virsh pool-info default | grep -q 'State: *running' || sudo virsh pool-start default

say "Done"
echo "Sign out and back in (or run: newgrp libvirt) so the libvirt group applies, then check:"
echo "  virsh -c qemu:///system list --all      # an empty table, no permission error"
