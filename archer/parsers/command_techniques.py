"""
ATT&CK techniques for commands a report shows, without AI.

A report that never writes "T1069.002" still shows `net group`. ATT&CK's procedures
(data/mitre_procedures.csv) cite the same commands under the techniques they were used
for, so a command maps to the technique most of its citations sit under: first by its
binary and first argument ("net group", "whoami /priv"), then by binary alone when too
few procedures cite that pair.
"""

import csv
import json
import os
import re
from collections import Counter
from functools import lru_cache
from typing import Dict, List, Optional

MIN_CITATIONS = 3   # fewer citations than this are noise (whoami /priv: 2, under T1190)
MIN_SHARE = 0.25    # the leading technique's share of all citations
# Binaries that do anything: their technique comes from what they run, never the binary
_TOO_GENERAL = {"cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "bash", "sh",
                "python", "python3", "rundll32", "rundll32.exe", "wmic", "wmic.exe"}


def _csv_path() -> str:
    from archer.config import DATA_DIR
    return os.path.join(DATA_DIR, "mitre_procedures.csv")


@lru_cache(maxsize=1)
def _citations(path: str, mtime: float) -> Dict[str, Counter]:
    """Command keys (binary, binary + argument, DLL) → technique counts."""
    index: Dict[str, Counter] = {}
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                tid = row.get("technique_id") or ""
                keys = set()
                try:
                    cmds = (json.loads(row.get("evidence") or "{}") or {}).get("cmd") or []
                except (ValueError, AttributeError):
                    cmds = []
                for cmd in cmds:
                    keys.update(_keys(cmd))
                for m in _IN_PROSE.finditer((row.get("procedure_example") or "").lower()):
                    keys.update(_keys(m.group(0)))
                for key in keys:
                    index.setdefault(key, Counter())[tid] += 1
    except OSError:
        return {}
    return index


# A binary and its first argument in a procedure's prose: "used `net group /domain` to"
_IN_PROSE = re.compile(r"(?<![\w.\\/-])[a-z][a-z0-9_\-]*(?:\.exe)?\s+[/\-]?[a-z][a-z0-9_\-]*")
_DLL = re.compile(r"([a-z0-9_\-]+)\.dll\b")


def _keys(command: str) -> List[str]:
    """binary, "binary argument" and "dll:name" for each DLL the command names."""
    parts = command.lower().replace("\\", "/").split()
    if not parts:
        return []
    binary = re.sub(r"\.exe$", "", parts[0].rsplit("/", 1)[-1])
    keys = [binary]
    if len(parts) > 1:
        keys.append(f"{binary} {parts[1]}")
    keys += [f"dll:{d}" for d in _DLL.findall(command.lower())]
    return keys


def _lead(counts: Optional[Counter]) -> Optional[str]:
    if not counts:
        return None
    tid, n = counts.most_common(1)[0]
    total = sum(counts.values())
    return tid if n >= MIN_CITATIONS and n / total >= MIN_SHARE else None


def technique_for_command(command: str, index: Optional[Dict[str, Counter]] = None) -> Optional[str]:
    if index is None:
        path = _csv_path()
        index = _citations(path, os.path.getmtime(path)) if os.path.exists(path) else {}
    keys = _keys(command)
    if not keys:
        return None
    binary, rest = keys[0], keys[1:]
    pair = [k for k in rest if not k.startswith("dll:")]
    # Most specific first: the DLL a general binary loads, the binary with its argument, the binary
    for key in [k for k in rest if k.startswith("dll:")] + pair + ([] if binary in _TOO_GENERAL else [binary]):
        found = _lead(index.get(key))
        if found:
            return found
    return None


def techniques_for_commands(commands: List[str]) -> List[str]:
    path = _csv_path()
    if not os.path.exists(path):
        return []
    index = _citations(path, os.path.getmtime(path))
    return sorted({t for c in commands for t in [technique_for_command(c, index)] if t})
