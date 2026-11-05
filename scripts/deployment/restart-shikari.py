#!/usr/bin/env python3
"""
restart-shikari.py: Restart Shikari in the background (shikari restart).
Kept for older instructions; the implementation is shikari/service.py, which `shikari` runs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "shikari"))
import service  # noqa: E402

args = [{"-p": "--port"}.get(a, a) for a in sys.argv[1:] if a not in ("-b", "--background")]
sys.exit(service.main(["restart"] + args))
