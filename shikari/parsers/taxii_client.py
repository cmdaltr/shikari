"""
Poll a TAXII 2.1 collection (#19).

The client is `samarkand.taxii`, the suite's shared one (standard library, no taxii2-client): it
fetches a collection's objects, following pagination, with optional Basic auth, and doesn't follow
redirects, so credentials only ever go to the URL given. This module hands the objects to the STIX
importer, so a TAXII collection can be used as an Analyse input or a feed source. A server that
refuses or can't be reached raises `TaxiiProblem`, with a reason an admin can act on. No AI.
"""

from samarkand import taxii
from samarkand.taxii import TaxiiProblem  # noqa: F401 (what a fetch raises, for callers)

from shikari.parsers.stix_import import parse_stix_bundle

TAXII_ACCEPT = taxii.ACCEPT
USER_AGENT = "Shikari (TAXII 2.1 client)"


def fetch_objects(collection_url: str, *, username: str = "", password: str = "",
                  added_after: str = "", limit: int = 5000, timeout: int = 60) -> list:
    """Every STIX object in a TAXII 2.1 collection, following the `more`/`next` pagination.

    collection_url is the collection's base (…/collections/<id>/); /objects/ is appended. added_after
    is an optional ISO timestamp to fetch only what changed since."""
    return taxii.fetch_objects(collection_url, username=username, password=password,
                               added_after=added_after, limit=limit, timeout=timeout, user_agent=USER_AGENT)


def collection_info(collection_url: str, *, username: str = "", password: str = "", timeout: int = 30) -> dict:
    """The collection's metadata (title, description, id)."""
    return taxii.collection_info(collection_url, username=username, password=password, timeout=timeout,
                                 user_agent=USER_AGENT)


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
