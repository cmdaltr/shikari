#!/usr/bin/env python3
"""
Regenerate hunted ATT&CK groups one at a time, exactly as the Results page's Regenerate button does
(POST /generate with regenerate=true), so a change to how detections are built reaches them.

Usage:
    SHIKARI_TOKEN=shik_... python scripts/admin/regenerate.py APT29 "Scattered Spider" FIN7
    SHIKARI_URL=https://<your-shikari-host> SHIKARI_TOKEN=shik_... python scripts/admin/regenerate.py

The token is from Profile → Security → API tokens on the server named by SHIKARI_URL
(default http://127.0.0.1:32453). Regenerate rewrites every detection, including ones edited by hand.
"""

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT))

# Run as ./regenerate.py, env's python3 is whichever is first on PATH: use the repo's venv, Shikari's own Python
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
if VENV_PYTHON.exists() and Path(sys.prefix).resolve() != (ROOT / ".venv").resolve():
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), __file__, *sys.argv[1:]])

from shikari.client import ShikariClient, ShikariError  # noqa: E402


def main() -> None:
    groups = sys.argv[1:]
    if not groups:
        sys.exit(__doc__)
    client = ShikariClient()
    failed = 0
    for g in groups:
        start = time.time()
        try:
            run = client._run_name(client._json("POST", "/generate", data={"group_name": g, "regenerate": "true"}))
            p = client.wait(run, poll=10)
            print(f"{g}: {p.get('status')}, {p.get('created_yaml')} detections, {time.time() - start:.0f}s", flush=True)
        except ShikariError as e:
            failed += 1
            print(f"{g}: FAILED {e}", flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
