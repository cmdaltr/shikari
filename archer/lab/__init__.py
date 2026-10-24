"""
Lab: install, create and manage the containers and VMs an Emulate run records on, without
leaving Archer (Build → Emulate → Lab).

Archer drives what's on the machine it runs on: Docker (or OrbStack) for Linux containers,
Tart for macOS and Linux VMs on Apple Silicon. It is OS- and architecture-aware: a template
is only offered when the host can run it (a Windows x64 VM shows only where Archer runs on an
x64 host), and a template's image is chosen for the host's architecture. Hypervisors aren't
installed for you — the host card shows the exact command when one is missing (step: detect
and guide).

The pieces:
  hosts       what this machine is and which engines it has (archer.lab.hosts)
  templates   the machines you can create here, filtered to the host (archer.lab.templates)
  machines    create, start, stop, snapshot, revert, delete, status, logs (archer.lab.machines)
  provision   turn logging on and install Atomic Red Team in a machine (archer.lab.provision)

Running Atomic Red Team and importing the recording (the rest of the loop) is archer.lab.record.
Everything goes through archer.lab.runner.run, one place that shells out, so the logic above
it is tested without a hypervisor.
"""

from archer.lab.runner import LabError, run  # noqa: F401
