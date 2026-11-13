"""
Lab: install, create and manage the containers and VMs an Emulate run records on, without
leaving Shikari (Build → Emulate → Lab).

Shikari drives what's on the machine it runs on: Docker (or OrbStack) for Linux containers,
Tart for macOS and Linux VMs on Apple Silicon, UTM for QEMU VMs on a Mac, Hyper-V on a Windows
host and KVM (libvirt) on a Linux one. It is OS- and architecture-aware: a template
is only offered when the host can run it (a Windows x64 VM shows only where Shikari runs on an
x64 host), and a template's image is chosen for the host's architecture. Hypervisors aren't
installed for you — the host card shows the exact command when one is missing (step: detect
and guide).

The pieces:
  hosts       what this machine is and which engines it has (shikari.lab.hosts)
  templates   the machines you can create here, filtered to the host (shikari.lab.templates)
  machines    create, start, stop, snapshot, revert, delete, status, logs (shikari.lab.machines)
  provision   turn logging on and install Atomic Red Team in a machine (shikari.lab.provision)

Running Atomic Red Team and importing the recording (the rest of the loop) is shikari.lab.record.
Everything goes through shikari.lab.runner.run, one place that shells out, so the logic above
it is tested without a hypervisor.
"""

from shikari.lab.runner import LabError, run  # noqa: F401
