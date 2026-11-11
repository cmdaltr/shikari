"""`shikari licence show|install FILE --accept-terms "Name <email>"|remove` — the installation's
commercial licence.

The licence itself is issued by the licensor (scripts/admin/sign_licence.py); this only installs,
shows or removes the one line on this host. See docs/LICENSING_MODEL.md.
"""

from __future__ import annotations

import argparse
import json
import sys

from shikari import licensing


def _show() -> int:
    s = licensing.status()
    if not s["present"]:
        print("No licence installed — Free edition.")
        return 0
    seats = "unlimited" if s["seats"] is None else s["seats"]
    print(f"Edition:  {s['edition']}")
    print(f"State:    {s['state']} ({s['reason']})")
    if s["licensee"]:
        print(f"Licensee: {s['licensee']}")
    print(f"Seats:    {seats}")
    print(f"Expires:  {s['expires']}")
    if s["grace_ends"]:
        print(f"Grace to: {s['grace_ends']}")
    if s["features"]:
        print(f"Features: {', '.join(s['features'])}")
    if s["accepted"]:
        a = s["accepted"]
        print(f"Terms:    commercial licence v{a['terms_version']} accepted by {a['accepted_by_name']} "
              f"on {(a['accepted_at'] or '')[:10]}")
    return 0 if s["valid"] else 1


def _audit(event: str, details: dict) -> None:
    """Record a CLI install or removal in the same audit log the admin page writes to. A server with
    no database yet still gets its licence; the warning says the entry is missing."""
    try:
        from shikari.database.audit import log_audit_event
        from shikari.database.db import SessionLocal
        db = SessionLocal()
        try:
            log_audit_event(db, event, details=json.dumps({**details, "via": "cli"}))
        finally:
            db.close()
    except Exception as exc:  # noqa: BLE001 - the licence change has happened; say what wasn't logged
        print(f"Warning: not recorded in the audit log ({exc}).", file=sys.stderr)


def _install(path: str, accepted_by: str) -> int:
    """From the server, for when no admin can sign in to do it. Recorded like an admin's install, with
    the name given for whoever accepted the terms."""
    if not (accepted_by or "").strip():
        version = licensing.terms()[0]
        print(f"Installing a licence accepts the Shikari Commercial Licence, version {version}, on the "
              "licensee's behalf. Read COMMERCIAL-LICENSE.md, then run this again with "
              '--accept-terms "Your Name <you@example.org>".', file=sys.stderr)
        return 1
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as exc:
        print(f"Could not read {path}: {exc}", file=sys.stderr)
        return 2
    ok, message = licensing.install(text, accepted_by_name=accepted_by)
    print(message, file=sys.stdout if ok else sys.stderr)
    if ok:
        from shikari.database.audit import EVENT_LICENCE_INSTALLED
        s = licensing.status()
        _audit(EVENT_LICENCE_INSTALLED, {
            "edition": s["edition"], "licensee": s["licensee"], "seats": s["seats"],
            "licence_id": s["licence_id"], "expires": s["expires"],
            "terms_version": s["accepted"]["terms_version"], "accepted_by": accepted_by.strip(),
        })
    return 0 if ok else 1


def _remove() -> int:
    from shikari.database.audit import EVENT_LICENCE_REMOVED
    had = licensing.status()
    licensing.remove()
    if had["present"]:
        _audit(EVENT_LICENCE_REMOVED, {"was": had["edition"], "licensee": had["licensee"]})
    print("Licence removed — Free edition. Nobody has been deactivated.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="shikari licence", description="This installation's licence.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("show", help="the installed licence and what it grants")
    inst = sub.add_parser("install", help="install a licence line from a file")
    inst.add_argument("file", help="the .licence file the licensor sent")
    inst.add_argument("--accept-terms", metavar='"NAME <EMAIL>"', default="",
                      help="accept the Shikari Commercial Licence on the licensee's behalf (required)")
    sub.add_parser("remove", help="remove the installed licence (back to Free)")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if args.command == "show":
        return _show()
    if args.command == "install":
        return _install(args.file, args.accept_terms)
    return _remove()


if __name__ == "__main__":
    sys.exit(main())
