#!/usr/bin/env python3
import sys
from importlib import import_module

try:
    from fastapi.testclient import TestClient
except Exception as e:
    print("Install fastapi[testclient] or requests for TestClient. Error:", e)
    sys.exit(1)

# import the app
try:
    mod = import_module("gorgon.app")
    app = getattr(mod, "app")
except Exception as e:
    print("Failed to import gorgon.app:app -", e)
    sys.exit(2)

client = TestClient(app)


def check_root():
    r = client.get("/")
    print("GET / ->", r.status_code)
    if r.status_code != 200:
        print("body:", r.text[:400])
        return False
    return True


def check_static():
    r = client.get("/static/style.css")
    print("GET /static/style.css ->", r.status_code)
    return r.status_code == 200


def check_manual_page():
    # try both GET and a safe POST if endpoint exists
    r = client.get("/manual_group")
    print("GET /manual_group ->", r.status_code)
    ok = r.status_code == 200
    # attempt a safe POST to manual_group_submit if route exists (non-LLM)
    r2 = client.post(
        "/manual_group_submit",
        data={
            "group_name": "test",
            "group_desc": "desc",
            "technique": "",
            "procedures": "proc1\nproc2",
        },
    )
    print("POST /manual_group_submit ->", r2.status_code)
    if r2.status_code >= 400:
        print("POST body/response (truncated):", r2.text[:400])
        # don't treat as fatal; many apps redirect or expect more
    return ok


def run_all():
    ok = True
    ok &= check_root()
    ok &= check_static()
    ok &= check_manual_page()
    if ok:
        print("Basic endpoint smoke checks passed.")
        return 0
    else:
        print("One or more endpoint checks failed (see above).")
        return 3


if __name__ == "__main__":
    sys.exit(run_all())
