import json
from fastapi.testclient import TestClient

import gorgon.app as app_module


client = TestClient(app_module.app)


def test_manual_submit_monkeypatch_process(monkeypatch, tmp_path):
    called = {}

    def fake_process_group(group_name, hypothesis, manual_data=None):
        called["group_name"] = group_name
        called["hypothesis"] = hypothesis
        called["manual_data"] = manual_data

    monkeypatch.setattr(app_module, "process_group", fake_process_group)

    technique_entries = [
        {
            "technique": "Test Technique",
            "tactics": ["Discovery", "Lateral Movement"],
            "procedures": "Do something\nDo something else",
        }
    ]

    data = {
        "group_name": "UnitTestGroup",
        "group_desc": "A test group",
        "technique_entries": json.dumps(technique_entries),
    }

    resp = client.post("/manual_submit", data=data, allow_redirects=False)
    # Expect redirect to progress
    assert resp.status_code in (303, 307, 302)
    assert "Location" in resp.headers

    # Check that our fake was called with transformed manual_data
    assert called.get("group_name") == "UnitTestGroup"
    assert called.get("hypothesis") == "A test group"
    manual_data = called.get("manual_data")
    assert isinstance(manual_data, list)
    # tactic grouping should have both tactics as separate tactic entries
    tactics = {entry["tactic"] for entry in manual_data}
    assert "Discovery" in tactics
    assert "Lateral Movement" in tactics
    # techniques under each tactic
    for entry in manual_data:
        assert isinstance(entry.get("techniques"), list)
        assert entry["techniques"][0]["technique"] == "Test Technique"
