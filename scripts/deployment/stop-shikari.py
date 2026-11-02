#!/usr/bin/env python3
"""
stop-shikari.py: Stop Shikari (shikari-cli stop --force).
Kept for older instructions; the implementation is shikari/service.py, which `shikari` runs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "shikari"))
import service  # noqa: E402

sys.exit(service.main(["stop", "--force"]))
