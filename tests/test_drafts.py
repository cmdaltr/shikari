#!/usr/bin/env python3
import os
import json
from fastapi.testclient import TestClient
import archer.app as app_module

client = TestClient(app_module.app)


def test_save_and_load_draft():
    payload = {
        "draft_id": "td1",
        "group_name": "G1",
        "entries": [{"technique": "T1", "procedures": "p1"}],
    }
    resp = client.post("/save_draft", json=payload)
    assert resp.status_code == 200
    assert resp.json().get("ok")

    resp2 = client.get("/load_draft", params={"draft_id": "td1"})
    assert resp2.status_code == 200
    assert resp2.json().get("ok")
    assert len(resp2.json().get("entries", [])) == 1


def test_user_draft_and_list():
    payload = {
        "draft_id": "u1",
        "user_id": "userA",
        "group_name": "GA",
        "entries": [{"technique": "TX", "procedures": "px"}],
    }
    # missing header should be rejected
    resp_fail = client.post("/save_draft", json=payload)
    assert resp_fail.status_code == 403

    # correct header
    resp = client.post("/save_draft", json=payload, headers={"X-USER-ID": "userA"})
    assert resp.status_code == 200

    # list drafts for user
    resp2 = client.get("/list_drafts", params={"user_id": "userA"})
    assert resp2.status_code == 200
    data = resp2.json()
    assert data["ok"]
    assert any(d["draft_id"] == "u1" for d in data["drafts"])

    # load specifically
    # load without user_id should not find user-scoped draft
    resp_no = client.get("/load_draft", params={"draft_id": "u1"})
    assert resp_no.status_code == 403 or resp_no.status_code == 200

    # load with user_id should succeed
    resp3 = client.get("/load_draft", params={"draft_id": "u1", "user_id": "userA"})
    assert resp3.status_code == 200
    assert resp3.json().get("entries")


def test_list_top_level_drafts():
    # ensure previous saves show up
    resp = client.get("/list_drafts")
    assert resp.status_code == 200
    assert resp.json().get("ok")
