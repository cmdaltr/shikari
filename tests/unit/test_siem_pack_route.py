"""The SIEM export pack download (#41): GET /api/detections/code/siem-pack."""

import io
import json
import zipfile

import pytest
import yaml
from fastapi.testclient import TestClient

import shikari.app as app_module


class _Db:
    def close(self):
        pass


@pytest.fixture
def client(tmp_path, monkeypatch):
    gdir = tmp_path / "groups"
    gdir.mkdir()
    with open(gdir / "a.yaml", "w") as fh:
        yaml.safe_dump({"id": "a1", "name": "Find Domain", "technique_id": "T1016", "tags": ["Sandworm Team (Group)"],
                        "query": "FROM logs-endpoint.events.process-*", "severity": "high",
                        "requiredDataConnectors": [{"connectorId": "Elastic"}],
                        "indicators": {"cmd": ["nbtstat -n"]}}, fh)
    monkeypatch.setattr(app_module, "GENERATE_DIR", str(gdir))
    monkeypatch.setattr(app_module, "require_auth", lambda request, session: (object(), _Db()))
    monkeypatch.setattr("shikari.cli.export.lab_runs", lambda: {})
    monkeypatch.setattr("shikari.paths.DATA", tmp_path)  # the Wazuh rule-ID map
    return TestClient(app_module.app)


def test_download(client):
    r = client.get("/api/detections/code/siem-pack", params={"siem": "elastic", "group": "Sandworm_Team"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert 'filename="shikari-elastic-sandworm-team.zip"' in r.headers["content-disposition"]
    assert json.loads(r.headers["x-shikari-pack"])["detections"] == 1
    assert "rules.ndjson" in zipfile.ZipFile(io.BytesIO(r.content)).namelist()


def test_wazuh_all(client):
    r = client.get("/api/detections/code/siem-pack", params={"siem": "wazuh"})
    assert r.status_code == 200 and json.loads(r.headers["x-shikari-pack"])["rules"] >= 1


@pytest.mark.parametrize("params,status", [
    ({"siem": "qradar"}, 400),
    ({"siem": "elastic", "group": "Nobody"}, 404),
    ({"siem": "elastic", "telemetry": "../../etc"}, 404),
])
def test_refusals(client, params, status):
    r = client.get("/api/detections/code/siem-pack", params=params)
    assert r.status_code == status and r.json()["success"] is False


def test_master_kql(client):
    # The fixture's one detection is Elastic: nothing for Defender XDR to combine
    r = client.get("/api/detections/code/master-kql", params={"group": "Sandworm_Team"})
    assert r.status_code == 404 and "No Defender XDR detections" in r.json()["error"]


@pytest.mark.parametrize("params", [{"techniques": "T1016; drop"}, {"lookback": "1w"}, {"tlp": "SECRET"}])
def test_master_kql_refusals(client, params):
    r = client.get("/api/detections/code/master-kql", params=params)
    assert r.status_code == 400 and r.json()["success"] is False
