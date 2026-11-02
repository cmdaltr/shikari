"""Commands from report text: prose that starts with a binary's name isn't a command."""

import pytest

from shikari.parsers.file_intelligence import FileIntelligenceParser, command_or_none


@pytest.mark.parametrize("text,expected", [
    ("aws remain unpatched", None),
    ("net group occurring near suspicious binary execution", "net group"),
    ("rundll32.exe against a dll in the user's", None),
    ("net command", None),
    ("net group", "net group"),
    ("whoami /priv was spawned from an m365copilot process (m365copilot.exe", "whoami /priv"),
    ("whoami /priv, cmdkey /list, and net group.despite", "whoami /priv"),
    ('net group "domain admins" /domain to list the admins', 'net group "domain admins" /domain'),
    ("cmd /c whoami", "cmd /c whoami"),
    ("rundll32.exe c:\\windows\\system32\\comsvcs.dll, minidump 624 c:\\temp\\l.dmp full",
     "rundll32.exe c:\\windows\\system32\\comsvcs.dll, minidump 624 c:\\temp\\l.dmp full"),
])
def test_command_or_none(text, expected):
    assert command_or_none(text) == expected


def test_binary_names_inside_words_are_not_commands():
    cmds = FileIntelligenceParser()._extract_iocs("The other two flaws remain unpatched.\nA dataset needs care.")["cmd"]
    assert cmds == []
