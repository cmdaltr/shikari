#!/usr/bin/env python3
"""
stop-archer.py: Stop Archer (archer stop --force).
Kept for older instructions; the implementation is archer/service.py, which `archer` runs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "archer"))
import service  # noqa: E402

sys.exit(service.main(["stop", "--force"]))
