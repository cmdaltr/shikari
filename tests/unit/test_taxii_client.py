"""TAXII 2.1 client (#19), over samarkand.taxii, against a throwaway local server."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from shikari.parsers import taxii_client

PAGES = {
    None: {"more": True, "next": "p2", "objects": [
        {"type": "attack-pattern", "id": "attack-pattern--1",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1003.001"}]}]},
    "p2": {"more": False, "objects": [
        {"type": "indicator", "id": "indicator--1", "pattern_type": "stix", "pattern": "[ipv4-addr:value = '10.0.0.5']"}]},
}


@pytest.fixture
def server():
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            url = urlparse(self.path)
            seen.append({"path": url.path, "query": parse_qs(url.query), "agent": self.headers["User-Agent"],
                         "auth": self.headers.get("Authorization")})
            if url.path.endswith("/moved/objects/"):
                self.send_response(302)
                self.send_header("Location", "/elsewhere/")
                self.end_headers()
                return
            body = json.dumps(PAGES[(parse_qs(url.query).get("next") or [None])[0]]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/taxii+json;version=2.1")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}", seen
    httpd.shutdown()
    httpd.server_close()


def test_a_collection_is_fetched_page_by_page_and_imported(server):
    base, seen = server
    result = taxii_client.import_collection(f"{base}/api/collections/c1", username="u", password="p")
    assert result["success"] and result["source"] == "taxii" and result["object_count"] == 2
    assert result["techniques"] == ["T1003.001"] and result["iocs"]["ip"] == ["10.0.0.5"]
    assert [s["path"] for s in seen] == ["/api/collections/c1/objects/"] * 2
    assert seen[1]["query"]["next"] == ["p2"]
    assert seen[0]["agent"] == "Shikari (TAXII 2.1 client)" and seen[0]["auth"].startswith("Basic ")


def test_a_redirect_is_not_followed(server):
    base, seen = server
    with pytest.raises(taxii_client.TaxiiProblem, match="HTTP 302"):
        taxii_client.fetch_objects(f"{base}/moved/", username="u", password="p")
    assert len(seen) == 1
