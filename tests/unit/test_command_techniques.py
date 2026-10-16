"""Techniques for commands, from the citations in ATT&CK's procedures."""

from collections import Counter

from archer.parsers import command_techniques as ct


def test_pair_then_binary_then_dll():
    index = {
        "net group": Counter({"T1069.002": 5, "T1087.002": 2}),
        "whoami /priv": Counter({"T1190": 2}),           # too few citations
        "whoami": Counter({"T1033": 40}),
        "dll:comsvcs": Counter({"T1003.001": 9}),
        "rundll32": Counter({"T1218.011": 50}),
    }
    assert ct.technique_for_command("net group /domain", index) == "T1069.002"
    assert ct.technique_for_command("whoami /priv", index) == "T1033"
    assert ct.technique_for_command(r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 1 x full", index) == "T1003.001"


def test_general_binaries_alone_say_nothing():
    index = {"powershell": Counter({"T1059.001": 100}), "cmd": Counter({"T1059.003": 100})}
    assert ct.technique_for_command("powershell -enc AAAA", index) is None
    assert ct.technique_for_command("cmd /c dir", index) is None


def test_no_clear_lead():
    index = {"foo": Counter({"T1": 3, "T2": 3, "T3": 3, "T4": 3, "T5": 3})}
    assert ct.technique_for_command("foo", index) is None


def test_keys():
    assert ct._keys(r"C:\Windows\System32\NET.EXE group /domain") == ["net", "net group"]
