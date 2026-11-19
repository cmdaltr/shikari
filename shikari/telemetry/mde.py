"""
Defender XDR's own telemetry for a lab run (shikari.telemetry.lab): each test's window of the
Device* tables, from Advanced Hunting through Microsoft Graph (runHuntingQuery; the older MDE
and XDR hunting APIs are being retired). Run it once Defender has caught up, usually within
an hour of the tests:

    python -m shikari.telemetry --mde-export data/telemetry/lab/<run>

An app registration in your tenant with the ThreatHunting.Read.All application permission
(admin consented), given as environment variables:

    SHIKARI_MDE_TENANT_ID, SHIKARI_MDE_CLIENT_ID, SHIKARI_MDE_CLIENT_SECRET
"""

import json
import os
from datetime import datetime, timedelta

from samarkand import siem

TABLES = ("DeviceProcessEvents", "DeviceFileEvents", "DeviceRegistryEvents", "DeviceNetworkEvents",
          "DeviceImageLoadEvents", "DeviceLogonEvents", "DeviceEvents")
PAD = timedelta(minutes=1)


def client() -> siem.Defender:
    """The app registration from SHIKARI_MDE_*, as samarkand's Advanced Hunting client."""
    env = {k: os.environ.get(f"SHIKARI_MDE_{k}") for k in ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET")}
    missing = [f"SHIKARI_MDE_{k}" for k, v in env.items() if not v]
    if missing:
        raise RuntimeError(f"Set {', '.join(missing)} (an app registration with ThreatHunting.Read.All)")
    return siem.Defender(env["TENANT_ID"], env["CLIENT_ID"], env["CLIENT_SECRET"])


def _when(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def export(run_dir: str, log=print) -> int:
    """Write each test's Device* rows to <test>/mde.json; returns the rows written."""
    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    host = str(manifest.get("host") or "").lower().replace('"', "")
    if not host:
        raise RuntimeError("The manifest names no host")
    defender, total = client(), 0
    for test in manifest.get("tests") or []:
        start, end = _when(test["start"]) - PAD, _when(test["end"]) + PAD
        rows = []
        for table in TABLES:
            query = (f'{table} | where Timestamp between (datetime({start:%Y-%m-%dT%H:%M:%SZ}) .. datetime({end:%Y-%m-%dT%H:%M:%SZ}))'
                     f' | where DeviceName startswith "{host}" | take 5000')
            rows += [{"Table": table, **row} for row in defender.query(query, max_rows=0).rows]
        folder = os.path.join(run_dir, test.get("folder") or f"{test['technique']}-{test.get('test', 1)}")
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "mde.json"), "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, default=str) + "\n")
        log(f"  {test['technique']}-{test.get('test', 1)}: {len(rows)} rows")
        total += len(rows)
    log(f"Defender XDR: {total} rows for {len(manifest.get('tests') or [])} tests on {host}")
    return total
