"""Role hierarchy, temporary elevation, and lab machine ownership."""

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from shikari.database.models import UserRole, at_least, effective_role, role_rank
from shikari.lab import machines


def _user(role, temp_role=None, temp_expires=None):
    return SimpleNamespace(id=1, role=role, temp_role=temp_role, temp_role_expires=temp_expires)


# --- ranked roles ---

def test_rank_order():
    assert role_rank(UserRole.STANDARD) < role_rank(UserRole.OPERATOR) < role_rank(UserRole.ADMIN)


def test_rank_accepts_stored_name_and_value():
    assert role_rank("ADMIN") == role_rank(UserRole.ADMIN)  # stored enum NAME
    assert role_rank("operator") == role_rank(UserRole.OPERATOR)  # value


def test_at_least_is_inheriting():
    op = _user(UserRole.OPERATOR)
    assert at_least(op, UserRole.OPERATOR) and at_least(op, UserRole.STANDARD)
    assert not at_least(op, UserRole.ADMIN)
    assert not at_least(None, UserRole.STANDARD)


# --- temporary elevation ---

def test_active_grant_elevates():
    u = _user(UserRole.STANDARD, UserRole.OPERATOR, datetime.utcnow() + timedelta(hours=1))
    assert effective_role(u) == UserRole.OPERATOR
    assert at_least(u, UserRole.OPERATOR)


def test_expired_grant_is_ignored():
    u = _user(UserRole.STANDARD, UserRole.ADMIN, datetime.utcnow() - timedelta(minutes=1))
    assert effective_role(u) == UserRole.STANDARD
    assert not at_least(u, UserRole.OPERATOR)


def test_a_grant_never_demotes():
    u = _user(UserRole.ADMIN, UserRole.STANDARD, datetime.utcnow() + timedelta(hours=1))
    assert effective_role(u) == UserRole.ADMIN


# --- machine ownership ---

def test_admin_manages_any_machine():
    assert machines._manageable("docker", owner=2, user_id=1, is_admin=True)


def test_owner_manages_their_own():
    assert machines._manageable("tart", owner=1, user_id=1, is_admin=False)
    assert not machines._manageable("tart", owner=2, user_id=1, is_admin=False)


def test_operator_may_claim_an_unclaimed_utm_vm():
    assert machines._manageable("utm", owner=None, user_id=1, is_admin=False)
    # but not an unowned docker/tart machine
    assert not machines._manageable("docker", owner=None, user_id=1, is_admin=False)


def test_listing_filters_to_what_the_user_may_manage(monkeypatch, tmp_path):
    monkeypatch.setattr("shikari.lab.registry._PATH", str(tmp_path / "m.json"))
    monkeypatch.setattr(machines.ENGINES["docker"].__class__, "list", lambda self: [
        {"engine": "docker", "name": "mine", "uuid": "", "kind": "container", "image": "",
         "os": "", "state": "running", "detail": ""},
        {"engine": "docker", "name": "theirs", "uuid": "", "kind": "container", "image": "",
         "os": "", "state": "running", "detail": ""}])
    monkeypatch.setattr(machines.ENGINES["tart"].__class__, "list", lambda self: [])
    monkeypatch.setattr(machines.ENGINES["utm"].__class__, "list", lambda self: [])
    import shikari.lab.registry as reg
    reg.record("docker", "mine", "ubuntu-container", "linux", "ubuntu:24.04", owner=1)
    reg.record("docker", "theirs", "ubuntu-container", "linux", "ubuntu:24.04", owner=2)

    mine = machines.listing(["docker", "tart", "utm"], user_id=1, is_admin=False)
    assert [m["name"] for m in mine] == ["mine"]
    allm = machines.listing(["docker", "tart", "utm"], user_id=99, is_admin=True)
    assert {m["name"] for m in allm} == {"mine", "theirs"}


def test_clone_and_create_record_the_owner(monkeypatch, tmp_path):
    monkeypatch.setattr("shikari.lab.registry._PATH", str(tmp_path / "m.json"))
    monkeypatch.setattr(machines.ENGINES["utm"].__class__, "clone", lambda self, name, new: None)
    import shikari.lab.registry as reg
    reg.record("utm", "src", "utm-vm", "windows", "", owner=7)
    machines.clone("utm", "src", "src-2", owner=7)
    assert reg.get("utm", "src-2")["owner"] == 7
