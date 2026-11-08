"""Indicators too common to mean anything alone are dropped before any query is built.

Against a Sysmon recording of four discovery commands, generated rules fired on background activity:
T1055.004 on every svchost.exe (476 events), T1574.001 on "exe", T1003.007 on "and".
"""

import pytest

from shikari.build.indicator_hygiene import clean_identifier_map, clean_indicator, too_generic


@pytest.mark.parametrize("value", ["svchost.exe", "SVCHOST.EXE", "explorer.exe", "services", "powershell.exe",
                                   "cmd.exe", ".exe", "exe", ".JPG", "dll", "and", "*svchost.exe*",
                                   "C:\\Windows\\System32\\svchost.exe"])
def test_too_generic(value):
    assert too_generic(value) and clean_indicator(value) is None


@pytest.mark.parametrize("value", ["svchost.exe -k netsvcs", "invoice.pdf.exe", "nbtstat -n", ".wll", "lsass.exe",
                                   "rundll32.exe", "powershell -enc", "C:\\Users\\Public\\svchost.exe", "22"])
def test_kept(value):
    assert not too_generic(value) and clean_indicator(value) == value


def test_map_drops_a_kind_left_empty():
    assert clean_identifier_map({"sw": ["svchost.exe", "explorer.exe"], "cmd": ["nbtstat -n", "and"]}) == \
        {"cmd": ["nbtstat -n"]}
