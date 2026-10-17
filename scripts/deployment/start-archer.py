#!/usr/bin/env python3
"""
start-archer.py: Start Archer: -b/--background runs it under the crash-restarting supervisor (archer-cli start);
otherwise it supervises in the foreground (archer-cli run).
Kept for older instructions; the implementation is archer/service.py, which `archer` runs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "archer"))
import service  # noqa: E402

args = sys.argv[1:]
background = any(a in ("-b", "--background") for a in args)
args = [{"-p": "--port"}.get(a, a) for a in args if a not in ("-b", "--background")]
sys.exit(service.main(["start" if background else "run"] + args))
