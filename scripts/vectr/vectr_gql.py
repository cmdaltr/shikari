"""Minimal GraphQL client for VECTR community edition (#26).

VECTR's API is GraphQL, not REST, so the archived `_archive/vectr/client.py` (which assumed a
`/api/v1/...` REST surface) is the wrong shape. This client speaks the real thing:

- endpoint ``https://<host>:8081/sra-purpletools-rest/graphql``
- auth header ``Authorization: VEC1 <keyId>:<secret>`` (key version 1.0, prefix ``VEC1``), with the
  key created in VECTR's Administration area and shown only once
- queries as HTTP POST with a JSON ``{"query": ..., "variables": ...}`` body
- community edition serves an untrusted self-signed certificate, so TLS verification is off by default

Used by probe_schema.py to introspect a running instance before any Phase 1 connector is written; it
is deliberately kept in scripts/ (not shikari/) until the schema is confirmed against a live VECTR.
"""
from __future__ import annotations

import json
import os
import urllib3
from typing import Any, Dict, Optional

import requests

# The CE cert is self-signed; silence the per-request warning rather than spam the probe output.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_URL = os.getenv("VECTR_GQL_URL", "https://localhost:8081/sra-purpletools-rest/graphql")


class VectrGraphQLError(RuntimeError):
    """A GraphQL-level error (HTTP 200 with an ``errors`` array), carrying the messages."""


class VectrGQL:
    def __init__(self, url: Optional[str] = None, api_key: Optional[str] = None,
                 verify: bool = False, timeout: int = 30):
        self.url = (url or DEFAULT_URL).rstrip("/")
        key = api_key or os.getenv("VECTR_API_KEY", "")
        if not key:
            raise ValueError("No VECTR API key: pass api_key or set VECTR_API_KEY (form 'keyId:secret').")
        # Accept either a bare 'keyId:secret' or an already-prefixed 'VEC1 keyId:secret'.
        self.auth = key if key.upper().startswith("VEC1 ") else f"VEC1 {key}"
        self.verify = verify
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Authorization": self.auth, "Content-Type": "application/json"})

    def execute(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """POST a GraphQL document and return its ``data``, raising on transport or GraphQL errors."""
        body = {"query": query, "variables": variables or {}}
        resp = self.session.post(self.url, data=json.dumps(body), verify=self.verify, timeout=self.timeout)
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("errors"):
            msgs = "; ".join(e.get("message", str(e)) for e in payload["errors"])
            raise VectrGraphQLError(msgs)
        return payload.get("data", {})

    def ping(self) -> str:
        """A trivial query to prove the endpoint and the API key work. Returns the root type name."""
        return self.execute("{ __typename }").get("__typename", "")

    def introspect(self) -> Dict[str, Any]:
        """Run the standard GraphQL introspection query and return the raw ``__schema`` object."""
        return self.execute(_INTROSPECTION)["__schema"]


# Standard introspection: enough to enumerate queries, mutations and their argument/return types.
_INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name description
        args { name description type { ...TypeRef } }
        type { ...TypeRef }
      }
      inputFields { name description type { ...TypeRef } }
    }
  }
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
}
"""
