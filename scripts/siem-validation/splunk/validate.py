"""Validate a generated SPL detection against a local Splunk and report its hit count (#16).

End to end: push sample events into Splunk over the HTTP Event Collector, then run the detection's SPL
through the existing shikari.query.splunk.SplunkClient and report how many events it matched. This is
the harness that turns the (previously untested) Splunk client into something exercised against real
indexed data, and the shape the Defender XDR path (shikari.query.mde.MDEClient) mirrors.

    # bring Splunk up (see docker-compose.yml in this directory), then from the repo root:
    export SPLUNK_HOST=localhost SPLUNK_USERNAME=admin SPLUNK_PASSWORD=Shikari!23
    export SPLUNK_HEC_TOKEN=shikari-hec-token-0000
    .venv/bin/python scripts/siem-validation/splunk/validate.py \
        --events scripts/siem-validation/splunk/sample_events.jsonl \
        --spl    scripts/siem-validation/splunk/sample_rule.spl

A detection YAML may be given instead of raw SPL with --detection (its `query` field is used). The
events file is JSON-lines; each line is one event's raw fields.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import requests
import urllib3

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
from shikari.query.splunk import SplunkClient  # noqa: E402

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def ingest(events, host, hec_token, index, sourcetype, port=8088):
    """POST each event to the HTTP Event Collector. Returns the count accepted."""
    url = f"https://{host}:{port}/services/collector/event"
    headers = {"Authorization": f"Splunk {hec_token}"}
    sent = 0
    for evt in events:
        body = {"event": evt, "sourcetype": sourcetype, "index": index}
        r = requests.post(url, headers=headers, json=body, verify=False, timeout=30)
        if r.status_code >= 400:
            raise SystemExit(f"HEC rejected an event ({r.status_code}): {r.text[:200]}")
        sent += 1
    return sent


def load_spl(args) -> str:
    if args.spl:
        return Path(args.spl).read_text(encoding="utf-8").strip()
    import yaml
    doc = yaml.safe_load(Path(args.detection).read_text(encoding="utf-8"))
    query = doc.get("query") or doc.get("detection", {}).get("query")
    if not query:
        raise SystemExit(f"No `query` field in {args.detection}")
    return query.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--events", required=True, help="JSON-lines file of sample events to ingest")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--spl", help="file containing the SPL to run")
    src.add_argument("--detection", help="detection YAML whose `query` field is run")
    ap.add_argument("--index", default="main")
    ap.add_argument("--sourcetype", default="shikari:test")
    ap.add_argument("--hec-token", default=os.getenv("SPLUNK_HEC_TOKEN", "shikari-hec-token-0000"))
    ap.add_argument("--wait", type=int, default=8, help="seconds to let Splunk index before searching")
    ap.add_argument("--earliest", default="-24h")
    args = ap.parse_args()

    host = os.getenv("SPLUNK_HOST", "localhost")
    events = [json.loads(l) for l in Path(args.events).read_text(encoding="utf-8").splitlines() if l.strip()]
    spl = load_spl(args)

    print(f">> Ingesting {len(events)} events into index={args.index} sourcetype={args.sourcetype} ...")
    ingest(events, host, args.hec_token, args.index, args.sourcetype)
    print(f">> Waiting {args.wait}s for indexing ...")
    time.sleep(args.wait)

    print(f">> Running detection:\n   {spl}\n")
    client = SplunkClient()
    result = client.execute_query(spl, earliest_time=args.earliest)
    if result["status"] != "success":
        print(f"FAIL: {result.get('error')}", file=sys.stderr)
        return 1

    stats = result["stats"]
    hits = stats["row_count"]
    print(f"HIT COUNT: {hits}  (scanned {stats['scan_count']} events, {stats['event_count']} matched the base search)")
    print("Verdict:", "fires on the sample (expected for a positive-control event set)" if hits else
          "no hits — tune the query, the sourcetype/field mapping, or the sample events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
