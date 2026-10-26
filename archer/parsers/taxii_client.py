"""
Poll a TAXII 2.1 collection (#19).

A minimal TAXII 2.1 client over requests — no taxii2-client dependency. Fetches a collection's
objects (following pagination) and hands them to the STIX importer, so a TAXII collection can be
used as an Analyse input or a feed source. No AI.
"""

from typing import Dict, Optional
from urllib.parse import urljoin

import requests

from archer.parsers.stix_import import parse_stix_bundle

TAXII_ACCEPT = "application/taxii+json;version=2.1"
_HEADERS = {"Accept": TAXII_ACCEPT, "User-Agent": "Archer (TAXII 2.1 client)"}


def fetch_objects(collection_url: str, *, username: str = "", password: str = "",
                  added_after: str = "", limit: int = 5000, timeout: int = 60) -> list:
    """Every STIX object in a TAXII 2.1 collection, following the `more`/`next` pagination.

    collection_url is the collection's base (…/collections/<id>/); /objects/ is appended. added_after
    is an optional ISO timestamp to fetch only what changed since."""
    base = collection_url if collection_url.endswith("/") else collection_url + "/"
    url = urljoin(base, "objects/")
    auth = (username, password) if username else None
    params: Dict[str, object] = {"limit": min(limit, 1000)}
    if added_after:
        params["added_after"] = added_after
    objects: list = []
    seen_next = set()
    while url and len(objects) < limit:
        r = requests.get(url, headers=_HEADERS, params=params, auth=auth, timeout=timeout)
        r.raise_for_status()
        envelope = r.json()
        objects.extend(envelope.get("objects") or [])
        nxt = envelope.get("next")
        if not envelope.get("more") or not nxt or nxt in seen_next:
            break
        seen_next.add(nxt)
        params["next"] = nxt
    return objects[:limit]


def collection_info(collection_url: str, *, username: str = "", password: str = "", timeout: int = 30) -> dict:
    """The collection's metadata (title, description, id)."""
    base = collection_url.rstrip("/")
    auth = (username, password) if username else None
    r = requests.get(base, headers=_HEADERS, auth=auth, timeout=timeout)
    r.raise_for_status()
    return r.json()


def import_collection(collection_url: str, *, username: str = "", password: str = "",
                      added_after: str = "", limit: int = 5000) -> dict:
    """Fetch a TAXII 2.1 collection and parse it as a STIX bundle into the extraction shape."""
    objects = fetch_objects(collection_url, username=username, password=password,
                            added_after=added_after, limit=limit)
    result = parse_stix_bundle({"type": "bundle", "objects": objects})
    result["source"] = "taxii"
    result["taxii_collection"] = collection_url
    result["object_count"] = len(objects)
    return result
