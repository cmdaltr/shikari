"""Every PowerShell script is plain ASCII.

Windows PowerShell 5.1 reads a script saved as UTF-8 without a byte-order mark in the ANSI code page,
so a typographic character turns into several, and an em dash's last byte (0x94 in cp1252) is a
closing smart quote, which PowerShell treats as a quote: record-custom.ps1 stopped parsing on the
VM it was meant for.
"""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = subprocess.run(["git", "-C", str(ROOT), "ls-files", "*.ps1"], capture_output=True, text=True,
                         check=True).stdout.split()


@pytest.mark.parametrize("path", SCRIPTS)
def test_ascii(path):
    text = (ROOT / path).read_bytes()
    bad = [(n, line.decode("utf-8", "replace").strip()[:60]) for n, line in enumerate(text.splitlines(), 1)
           if any(b > 0x7F for b in line)]
    assert not bad, f"non-ASCII in {path} (Windows PowerShell 5.1 misreads it): {bad[:3]}"
