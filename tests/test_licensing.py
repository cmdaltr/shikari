"""The Shikari licence: signing, checking, the editions, grace, and the seat rule — no server.

Mirrors ostraka's licence unit tests (docs/LICENSING_MODEL.md, the shared spec). Everything signs
with a throwaway key patched into PUBLIC_KEYS, so the real signing key is never needed.
"""

import base64
import json
import os
import sys
from datetime import date, datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shikari import licensing as L

TODAY = date(2026, 11, 11)


@pytest.fixture
def signing_key(monkeypatch):
    """A throwaway keypair whose public half replaces the shipped PUBLIC_KEYS for the test."""
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
    )
    monkeypatch.setattr(L, "PUBLIC_KEYS", (pub.hex(),))
    return key


def lic(edition="pro", seats=10, expires=date(2027, 11, 30), **extra) -> L.Licence:
    return L.Licence("lic_test", "Northwind Ltd", L.Edition(edition), seats, TODAY, expires, **extra)


ADMIN = "Ada Admin <ada@example.org>"


def _isolated(tmp_path, monkeypatch):
    """Point the installed-licence file at tmp_path, with a cold cache."""
    monkeypatch.setattr(L, "INSTALL_PATH", tmp_path / "licence.json")
    monkeypatch.setattr(L, "_cache", {"path": None, "mtime": None, "licence": None, "error": None, "accepted": None})
    monkeypatch.delenv("SHIKARI_LICENCE", raising=False)
    monkeypatch.setattr(L.paths, "HOME", tmp_path)


def at(day: date) -> datetime:
    return datetime(day.year, day.month, day.day, 12, tzinfo=timezone.utc)


# ── signing and checking ──

def test_a_signed_licence_reads_back_exactly(signing_key):
    original = lic("services", seats=None, expires=None, email="ops@northwind.example",
                   features=("*",), not_before=date(2026, 12, 1))
    assert L.parse(L.sign(signing_key, original)) == original


def test_the_payload_is_canonical_json_with_the_product(signing_key):
    _, payload, _ = L.sign(signing_key, lic()).split(".")
    text = base64.urlsafe_b64decode(payload + "==").decode()
    assert text == json.dumps(json.loads(text), sort_keys=True, separators=(",", ":"))
    assert json.loads(text)["product"] == "shikari"


def test_a_licence_for_another_product_is_refused(signing_key):
    with pytest.raises(L.LicenceProblem, match="licence for ostraka"):
        L.parse(L.sign(signing_key, lic(product="ostraka")))


def test_an_edited_licence_is_refused(signing_key):
    head, payload, signature = L.sign(signing_key, lic(seats=10)).split(".")
    more = json.loads(base64.urlsafe_b64decode(payload + "=="))
    more["seats"] = 500
    forged = base64.urlsafe_b64encode(json.dumps(more).encode()).rstrip(b"=").decode()
    with pytest.raises(L.LicenceProblem, match="altered"):
        L.parse(f"{head}.{forged}.{signature}")


def test_a_licence_signed_by_another_key_is_refused(signing_key):
    with pytest.raises(L.LicenceProblem, match="wasn't issued for Shikari"):
        L.parse(L.sign(Ed25519PrivateKey.generate(), lic()))


@pytest.mark.parametrize("text", ["", "hello", "shikari-licence-1.!!!.???", "shikari-licence-2.a.b"])
def test_text_that_isnt_a_licence_is_refused(signing_key, text):
    with pytest.raises(L.LicenceProblem):
        L.parse(text)


def test_a_free_licence_grants_nothing(signing_key):
    with pytest.raises(L.LicenceProblem, match="nothing beyond"):
        L.parse(L.sign(signing_key, lic("free")))


def test_the_shipped_key_is_a_real_ed25519_public_key():
    for key in L.PUBLIC_KEYS:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))


# ── what a licence gives, and when it runs out ──

def test_no_licence_is_the_free_edition():
    s = L.standing(None)
    assert (s.edition, s.seats, s.state) == (L.Edition.FREE, L.FREE_SEATS, "free")
    assert not s.has(L.FEATURE_REPORT_BRANDING)


def test_a_licence_runs_to_the_end_of_its_last_day_then_thirty_days_grace():
    l = lic("services", seats=25, expires=date(2027, 1, 31))
    active = L.standing(l, at(date(2027, 1, 31)))
    assert (active.state, active.seats) == ("active", 25)
    grace = L.standing(l, at(date(2027, 2, 1)))
    assert (grace.state, grace.edition, grace.seats) == ("grace", L.Edition.SERVICES, 25)
    assert L.standing(l, at(date(2027, 3, 2))).state == "grace"
    lapsed = L.standing(l, at(date(2027, 3, 3)))
    assert (lapsed.state, lapsed.edition, lapsed.seats, lapsed.organisation) == (
        "lapsed", L.Edition.FREE, L.FREE_SEATS, "")


def test_a_licence_waits_for_its_first_day_and_a_perpetual_one_never_ends():
    later = lic("pro", not_before=date(2026, 12, 1))
    assert L.standing(later, at(date(2026, 11, 30))).state == "pending"
    assert L.standing(later, at(date(2026, 11, 30))).seats == L.FREE_SEATS
    assert L.standing(later, at(date(2026, 12, 1))).state == "active"
    forever = lic("pro", expires=None)
    assert L.standing(forever, at(date(2099, 1, 1))).state == "active"
    assert L.grace_ends(forever) is None


def test_grace_ends_thirty_days_after_expiry():
    assert L.grace_ends(lic(expires=date(2027, 1, 31))) == date(2027, 1, 31) + timedelta(days=30)


def test_an_edition_grants_its_features_and_a_licence_can_add_more():
    # The split (docs/LICENSING_MODEL.md): Pro brands the installation and fires webhooks; Services
    # adds a brand per client and the managed-service right.
    pro = L.standing(lic("pro"), at(TODAY))
    assert pro.has(L.FEATURE_REPORT_BRANDING) and pro.has(L.FEATURE_AUTOMATION)
    assert not pro.has(L.FEATURE_BRAND_LIBRARY) and not pro.has(L.FEATURE_MANAGED_SERVICE)
    assert pro.custom_branding and not pro.brand_library
    services = L.standing(lic("services"), at(TODAY))
    assert services.has(L.FEATURE_BRAND_LIBRARY) and services.has(L.FEATURE_MANAGED_SERVICE)
    assert services.custom_branding and services.brand_library
    everything = L.standing(lic("pro", features=("*",)), at(TODAY))
    assert everything.has(L.FEATURE_MANAGED_SERVICE) and everything.has("anything-later")


# ── the seat rule ──

def test_free_edition_allows_two_accounts_then_refuses(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    assert L.FREE_SEATS == 2
    assert L.standing(None).seats == 2
    assert L.can_add_user(0) and L.can_add_user(1) and not L.can_add_user(2)


def test_seats_come_from_the_licence(signing_key, tmp_path, monkeypatch):
    monkeypatch.setattr(L, "INSTALL_PATH", tmp_path / "licence.json")
    monkeypatch.setattr(L, "_cache", {"path": None, "mtime": None, "licence": None, "error": None, "accepted": None})
    monkeypatch.delenv("SHIKARI_LICENCE", raising=False)
    monkeypatch.setattr(L.paths, "HOME", tmp_path)

    assert L.seats_allowed() == 2 and L.can_add_user(1) and not L.can_add_user(2)
    L.install(L.sign(signing_key, lic("pro", seats=5)), accepted_by_name=ADMIN)
    assert L.seats_allowed() == 5 and L.can_add_user(4) and not L.can_add_user(5)
    L.install(L.sign(signing_key, lic("services", seats=None)), accepted_by_name=ADMIN)
    assert L.seats_allowed() is None and L.can_add_user(10_000)


# ── install / status / remove ──

def test_install_show_and_remove(signing_key, tmp_path, monkeypatch):
    monkeypatch.setattr(L, "INSTALL_PATH", tmp_path / "licence.json")
    monkeypatch.setattr(L, "_cache", {"path": None, "mtime": None, "licence": None, "error": None, "accepted": None})
    monkeypatch.delenv("SHIKARI_LICENCE", raising=False)
    monkeypatch.setattr(L.paths, "HOME", tmp_path)

    assert not L.has_feature(L.FEATURE_REPORT_BRANDING)
    ok, msg = L.install(L.sign(signing_key, lic("pro", seats=5, expires=None)), accepted_by_name=ADMIN)
    assert ok and "Pro licence installed" in msg
    s = L.status()
    assert s["valid"] and s["edition"] == "pro" and s["licensee"] == "Northwind Ltd"
    assert s["seats"] == 5 and s["expires"] == "perpetual"
    assert L.has_feature(L.FEATURE_REPORT_BRANDING)
    L.remove()
    assert not L.has_feature(L.FEATURE_REPORT_BRANDING) and L.status()["present"] is False


def test_an_old_format_file_counts_as_no_licence(tmp_path, monkeypatch):
    # The shipped open-core format was {"payload":..,"sig":..}; it must read as no licence, not crash.
    f = tmp_path / "licence.json"
    f.write_text(json.dumps({"payload": {"features": ["report-branding"]}, "sig": "x"}))
    monkeypatch.setattr(L, "INSTALL_PATH", f)
    monkeypatch.setattr(L, "_cache", {"path": None, "mtime": None, "licence": None, "error": None, "accepted": None})
    monkeypatch.delenv("SHIKARI_LICENCE", raising=False)
    monkeypatch.setattr(L.paths, "HOME", tmp_path)
    assert not L.has_feature(L.FEATURE_REPORT_BRANDING)
    assert L.status()["valid"] is False


# ── the terms and accepting them ──

def test_the_terms_shikari_ships_are_the_terms_in_the_repo():
    # The server reads the packaged copy; an installed Shikari has no repo root to read.
    root = os.path.join(os.path.dirname(__file__), "..", "COMMERCIAL-LICENSE.md")
    assert L.TERMS.read_text("utf-8") == open(root, encoding="utf-8").read(), \
        "copy COMMERCIAL-LICENSE.md to shikari/legal/"
    version, text = L.terms()
    assert version == "1.1" and text.startswith("# Shikari Commercial Licence")


def test_installing_needs_the_current_terms_accepted(signing_key):
    licence = L.parse(L.sign(signing_key, lic()))
    version = L.terms()[0]
    assert L.acceptance_problem(licence, False, version)[0] == 422
    code, reason = L.acceptance_problem(licence, True, "0.9")
    assert code == 409 and f"version {version}" in reason
    assert L.acceptance_problem(licence, True, version) is None


def test_an_install_records_who_accepted_which_terms_and_when(signing_key, tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    ok, _ = L.install(L.sign(signing_key, lic()), accepted_by=7, accepted_by_name=ADMIN)
    assert ok
    stored = json.loads((tmp_path / "licence.json").read_text())
    assert stored["licence"].startswith("shikari-licence-1.")
    assert (stored["terms_version"], stored["accepted_by"], stored["accepted_by_name"]) == ("1.1", 7, ADMIN)
    assert stored["accepted_at"].startswith(str(datetime.now(timezone.utc).date()))
    assert L.status()["accepted"] == {k: stored[k] for k in
                                      ("terms_version", "accepted_by", "accepted_by_name", "accepted_at")}


def test_an_install_without_a_name_for_who_accepted_is_refused(signing_key, tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    ok, msg = L.install(L.sign(signing_key, lic()), accepted_by_name="  ")
    assert not ok and "accepted" in msg and not (tmp_path / "licence.json").exists()


def test_a_lapsed_licence_is_refused_at_install(signing_key, tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    ok, msg = L.install(L.sign(signing_key, lic(expires=date(2020, 1, 31))), accepted_by_name=ADMIN)
    assert not ok and "ran out" in msg


def test_a_bare_licence_line_from_an_earlier_build_still_reads(signing_key, tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    (tmp_path / "licence.json").write_text(L.sign(signing_key, lic()) + "\n")
    s = L.status()
    assert s["valid"] and s["licensee"] == "Northwind Ltd" and s["accepted"] is None


# ── the CLI ──

def test_the_cli_refuses_to_install_without_accept_terms(signing_key, tmp_path, monkeypatch, capsys):
    from shikari.cli import licence as cli
    _isolated(tmp_path, monkeypatch)
    f = tmp_path / "northwind.licence"
    f.write_text(L.sign(signing_key, lic()) + "\n")
    assert cli.main(["install", str(f)]) == 1
    assert "--accept-terms" in capsys.readouterr().err and not (tmp_path / "licence.json").exists()


def test_the_cli_installs_with_accept_terms_and_audits_it(signing_key, tmp_path, monkeypatch):
    from shikari.cli import licence as cli
    _isolated(tmp_path, monkeypatch)
    logged = []
    monkeypatch.setattr(cli, "_audit", lambda event, details: logged.append((event, details)))
    f = tmp_path / "northwind.licence"
    f.write_text(L.sign(signing_key, lic()) + "\n")
    assert cli.main(["install", str(f), "--accept-terms", ADMIN]) == 0
    assert L.status()["accepted"]["accepted_by_name"] == ADMIN
    assert logged[0][0] == "licence_installed"
    assert logged[0][1]["terms_version"] == "1.1" and logged[0][1]["accepted_by"] == ADMIN
    assert cli.main(["remove"]) == 0 and logged[1][0] == "licence_removed"


# ── the ledger ──

def test_signing_into_the_ledger_files_the_licence_and_a_row(signing_key, tmp_path):
    import csv
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "sign_licence", os.path.join(os.path.dirname(__file__), "..", "scripts", "admin", "sign_licence.py"))
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    ledger = tmp_path / "licensing"
    ledger.mkdir()
    with (ledger / "ledger.csv").open("w", newline="") as fh:
        csv.writer(fh).writerow(tool.LEDGER_FIELDS)
    licence = lic("services", seats=None)
    line = L.sign(signing_key, licence)
    out = tool._record(ledger, licence, line)
    assert out == ledger / "issued" / "shikari" / "lic_test.licence"
    assert out.read_text() == line + "\n"
    rows = list(csv.DictReader((ledger / "ledger.csv").open()))
    assert rows == [{**dict.fromkeys(tool.LEDGER_FIELDS, ""), "licence_id": "lic_test", "product": "shikari",
                     "licensee": "Northwind Ltd", "edition": "services", "seats": "unlimited",
                     "issued": "2026-11-11", "expires": "2027-11-30", "terms_version": "1.1",
                     "file": "issued/shikari/lic_test.licence"}]
