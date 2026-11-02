#!/usr/bin/env python3
"""
start-shikari.py: Start Shikari: -b/--background runs it under the crash-restarting supervisor (shikari-cli start);
otherwise it supervises in the foreground (shikari-cli run).
Kept for older instructions; the implementation is shikari/service.py, which `shikari` runs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "shikari"))
import service  # noqa: E402

args = sys.argv[1:]
background = any(a in ("-b", "--background") for a in args)
args = [{"-p": "--port"}.get(a, a) for a in args if a not in ("-b", "--background")]
sys.exit(service.main(["start" if background else "run"] + args))
