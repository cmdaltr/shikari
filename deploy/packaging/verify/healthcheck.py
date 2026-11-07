#!/usr/bin/env python3
"""Poll a Shikari server's /health until it identifies itself, or time out (#29 on-target verify).

Shared by verify-linux.sh and verify-windows.ps1 so "is it actually up?" is decided the same way on
every platform: a 200 from /health whose body says {"app": "shikari"} (the same check the desktop smoke
test uses). Stdlib only — it runs under the bundled interpreter with nothing installed.

    python3 healthcheck.py [--url http://127.0.0.1:32453/health] [--timeout 120]

Exit 0 once healthy; exit 1 on timeout (last error printed).
"""
import argparse
import json
import sys
import time
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:32453/health")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--interval", type=float, default=3.0)
    args = ap.parse_args()

    deadline = time.monotonic() + args.timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(args.url, timeout=5) as r:
                body = json.loads(r.read().decode("utf-8"))
            if body.get("app") == "shikari":
                print(f"healthy: {body}")
                return 0
            last = f"answered, but not Shikari: {body}"
        except Exception as exc:  # noqa: BLE001 — any failure just means "not up yet"
            last = f"{type(exc).__name__}: {exc}"
        time.sleep(args.interval)

    print(f"timed out after {args.timeout:.0f}s waiting on {args.url} — last: {last}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
