"""The results page's save/export payload: held server-side, fetched on demand (/api/results-data)."""

import json

import shikari.app as app


def test_payload_drops_osint_and_the_stash_keeps_the_most_recent():
    vendors = [{"name": "mde", "detections": [{"file": "a.yaml", "osint_data": {"big": 1}}]}]
    corr = [{"name": "mde", "correlations": [{"name": "c", "osint_data": {"big": 1}}]}]
    key = app.stash_results_data(vendors, corr)
    payload = json.loads(app._RESULTS_DATA[key])
    assert payload["detections"][0]["detections"] == [{"file": "a.yaml"}]
    assert payload["correlations"][0]["correlations"] == [{"name": "c"}]
    for _ in range(app._RESULTS_DATA_MAX):
        app.stash_results_data([], [])
    assert key not in app._RESULTS_DATA and len(app._RESULTS_DATA) == app._RESULTS_DATA_MAX
