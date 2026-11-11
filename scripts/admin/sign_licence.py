#!/usr/bin/env python3
"""
Sign a Shikari commercial licence (licensor tooling — not for customers).

A licence is a short JSON payload signed with the licensor's Ed25519 private key. The matching
public key is embedded in ``shikari/licensing.py`` and ships with the product, so a licence
verifies offline but can't be forged or altered. The private key stays with the licensor and is
never committed to the repository.

Keep the signing key safe:
    python scripts/admin/sign_licence.py keygen
      -> prints a new keypair; put PUBLIC_KEY_HEX in shikari/licensing.py, store the private key
         (PEM) somewhere safe and point SHIKARI_LICENCE_KEY at it.

Issue a licence:
    export SHIKARI_LICENCE_KEY=/path/to/signing-key.pem
    python scripts/admin/sign_licence.py sign \
        --licensee "Acme Security Ltd" --email ops@acme.example \
        --features report-branding --expires 2027-12-31 \
        -o acme-licence.json

The customer drops the file in at Report branding → Licence, or saves it as data/licence.json.
Omit --expires for a perpetual licence; pass --features pro to unlock every reserved feature.
"""

import argparse
import base64
import datetime
import json
import os
import sys
import uuid


def _load_private_key(path):
    from cryptography.hazmat.primitives import serialization

    if not path:
        sys.exit("Set SHIKARI_LICENCE_KEY (or pass --key) to the signing key file.")
    data = open(path, "rb").read()
    text = data.decode("utf-8", "replace").strip()
    # Accept a PEM private key or a bare 64-char hex seed.
    if "PRIVATE KEY" in text:
        return serialization.load_pem_private_key(data, password=None)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(text))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def cmd_keygen(_args):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()
    print("PUBLIC_KEY_HEX =", pub_raw.hex())
    print("\n# Store this private key safely; never commit it. Point SHIKARI_LICENCE_KEY at it.\n")
    print(pem)


def cmd_sign(args):
    priv = _load_private_key(args.key or os.getenv("SHIKARI_LICENCE_KEY"))
    features = []
    for f in args.features:
        features += [part.strip() for part in f.split(",") if part.strip()]
    payload = {
        "licence_id": args.licence_id or uuid.uuid4().hex[:12],
        "licensee": args.licensee,
        "email": args.email or "",
        "features": features or ["report-branding"],
        "issued": datetime.date.today().isoformat(),
    }
    if args.not_before:
        payload["not_before"] = args.not_before
    if args.expires:
        payload["expires"] = args.expires
    sig = priv.sign(_canonical(payload))
    licence = {"payload": payload, "sig": _b64url(sig)}
    out = json.dumps(licence, indent=2)
    token = _b64url(_canonical(payload)) + "." + _b64url(sig)
    if args.output:
        open(args.output, "w").write(out + "\n")
        print(f"Wrote {args.output}")
    else:
        print(out)
    print("\nCompact token (same bytes, for pasting):\n" + token)


def main():
    ap = argparse.ArgumentParser(description="Sign Shikari commercial licences (licensor only).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen", help="generate a new signing keypair")
    s = sub.add_parser("sign", help="sign a licence")
    s.add_argument("--licensee", required=True, help="who the licence is for")
    s.add_argument("--email", default="", help="licensee contact")
    s.add_argument("--features", nargs="+", default=["report-branding"],
                   help="feature ids (space- or comma-separated); 'pro' unlocks all")
    s.add_argument("--expires", default="", help="YYYY-MM-DD; omit for perpetual")
    s.add_argument("--not-before", default="", help="YYYY-MM-DD; optional start date")
    s.add_argument("--licence-id", default="", help="override the generated id")
    s.add_argument("--key", default="", help="signing key file (else SHIKARI_LICENCE_KEY)")
    s.add_argument("-o", "--output", default="", help="write the licence JSON here")
    args = ap.parse_args()
    {"keygen": cmd_keygen, "sign": cmd_sign}[args.cmd](args)


if __name__ == "__main__":
    main()
