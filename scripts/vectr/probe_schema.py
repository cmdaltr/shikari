"""Probe a running VECTR's GraphQL schema before writing the Phase 1 connector (#26).

The issue is explicit: VECTR's GraphQL schema shifts between releases, so the exact mutations and
queries for creating an assessment and loading test cases must be confirmed against a live instance
before any connector code is written. This script does that confirmation and prints the surface in a
form you can paste back so Phase 1 is written against reality, not a guess.

Usage (run against the instance stood up by up.sh):

    export VECTR_API_KEY='keyId:secret'           # created in VECTR Administration, shown once
    export VECTR_GQL_URL='https://localhost:8081/sra-purpletools-rest/graphql'   # or pass --url
    .venv/bin/python scripts/vectr/probe_schema.py                # relevant mutations + queries
    .venv/bin/python scripts/vectr/probe_schema.py --all          # the whole schema
    .venv/bin/python scripts/vectr/probe_schema.py --json > schema.json   # raw, to share back

Only reads. It never creates or changes anything in VECTR.
"""
from __future__ import annotations

import argparse
import json
import sys

from vectr_gql import VectrGQL, DEFAULT_URL, VectrGraphQLError

# The parts of the schema Phase 1 touches: creating assessments/campaigns and loading test cases, plus
# the containers they live in. Field/mutation names matching any of these are surfaced by default.
RELEVANT = ("assessment", "campaign", "testcase", "test_case", "template", "import",
            "organization", "org", "environment", "db", "database", "defect", "outcome", "result")


def _unwrap(t: dict) -> str:
    """Render a possibly-wrapped type ref (NON_NULL/LIST of ...) as a readable signature."""
    if not t:
        return "?"
    kind, name, of = t.get("kind"), t.get("name"), t.get("ofType")
    if kind == "NON_NULL":
        return _unwrap(of) + "!"
    if kind == "LIST":
        return "[" + _unwrap(of) + "]"
    return name or "?"


def _sig(field: dict) -> str:
    args = ", ".join(f"{a['name']}: {_unwrap(a['type'])}" for a in field.get("args") or [])
    return f"{field['name']}({args}): {_unwrap(field['type'])}" if args else \
           f"{field['name']}: {_unwrap(field['type'])}"


def _print_op_type(schema: dict, type_name: str, label: str, show_all: bool) -> None:
    types = {t["name"]: t for t in schema["types"]}
    root = types.get(type_name)
    if not root:
        print(f"  (no {label} type)")
        return
    fields = root.get("fields") or []
    shown = 0
    for f in sorted(fields, key=lambda x: x["name"]):
        if show_all or any(term in f["name"].lower() for term in RELEVANT):
            print(f"  {_sig(f)}")
            if f.get("description"):
                print(f"      — {f['description'].strip().splitlines()[0]}")
            shown += 1
    print(f"  [{shown} of {len(fields)} {label} shown]\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default=DEFAULT_URL, help=f"GraphQL endpoint (default {DEFAULT_URL})")
    ap.add_argument("--key", default=None, help="API key 'keyId:secret' (default: $VECTR_API_KEY)")
    ap.add_argument("--all", action="store_true", help="show every query/mutation, not just the relevant ones")
    ap.add_argument("--json", action="store_true", help="dump the raw introspection JSON and exit")
    args = ap.parse_args()

    try:
        client = VectrGQL(url=args.url, api_key=args.key)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    try:
        root = client.ping()
    except VectrGraphQLError as e:
        print(f"Connected, but the API rejected the request: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Could not reach VECTR at {args.url}: {e}", file=sys.stderr)
        print("Is it up (scripts/vectr/up.sh), is the URL/port right, and is the key valid?", file=sys.stderr)
        return 1
    print(f"OK — authenticated against {args.url} (root query type: {root})\n")

    schema = client.introspect()
    if args.json:
        json.dump(schema, sys.stdout, indent=2)
        return 0

    print("=== MUTATIONS ===")
    _print_op_type(schema, (schema.get("mutationType") or {}).get("name", "Mutation"), "mutations", args.all)
    print("=== QUERIES ===")
    _print_op_type(schema, (schema.get("queryType") or {}).get("name", "Query"), "queries", args.all)
    if not args.all:
        print("Filtered to assessment/campaign/test-case terms. Re-run with --all for everything,")
        print("or --json > schema.json to share the full surface back for the Phase 1 connector.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
