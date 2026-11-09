"""Built-in tools ATT&CK attributes a technique to join every group's evidence for it (#41: T1016)."""

import pytest

from shikari.mitre.retrieve import _BundleIndex, builtin_tools


class _Bundle:
    def __init__(self, objects):
        self.objects = objects


def _tool(tid, name, platforms=None):
    obj = {"type": "tool", "id": tid, "name": name}
    if platforms is not None:
        obj["x_mitre_platforms"] = platforms
    return obj


def _uses(src, dst):
    return {"type": "relationship", "relationship_type": "uses", "source_ref": src, "target_ref": dst, "id": f"r-{src}"}


@pytest.mark.unit
def test_built_in_tools_become_process_names_and_frameworks_and_shells_do_not():
    t1016 = "attack-pattern--t1016"
    objects = [
        {"type": "attack-pattern", "id": t1016},
        _tool("tool--nbtstat", "nbtstat"),                       # ATT&CK gives nbtstat no platforms
        _tool("tool--ipconfig", "ipconfig", ["Windows"]),
        _tool("tool--ifconfig", "ifconfig", ["Linux", "macOS"]),  # not a Windows built-in on the list
        _tool("tool--empire", "Empire", ["Windows"]),             # a framework: its name isn't a process
        _tool("tool--cmd", "cmd", ["Windows"]),                   # runs anything: says nothing about T1016
        {**_tool("tool--route", "route"), "revoked": True},
        {"type": "malware", "id": "malware--x", "name": "arp"},  # only tools count
    ]
    objects += [_uses(o["id"], t1016) for o in objects if o["type"] in ("tool", "malware")]
    assert builtin_tools(_BundleIndex(_Bundle(objects)), t1016) == ["ipconfig.exe", "nbtstat.exe"]


@pytest.mark.unit
def test_a_technique_with_no_built_in_tool_gets_nothing():
    objects = [{"type": "attack-pattern", "id": "attack-pattern--a"}, _tool("tool--empire", "Empire"),
               _uses("tool--empire", "attack-pattern--a")]
    assert builtin_tools(_BundleIndex(_Bundle(objects)), "attack-pattern--a") == []
