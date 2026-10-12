#!/usr/bin/env python3
"""
restart-archer.py: Restart Archer in the background (archer restart).
Kept for older instructions; the implementation is archer/service.py, which `archer` runs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "archer"))
import service  # noqa: E402

args = [{"-p": "--port"}.get(a, a) for a in sys.argv[1:] if a not in ("-b", "--background")]
sys.exit(service.main(["restart"] + args))
