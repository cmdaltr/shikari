"""The just-in-time elevation workflow: request → peer approval → delayed start → revoke."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from shikari import elevation
from shikari.database.models import Base, RoleRequest, User, UserRole, at_least, effective_role


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/t.db")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _mk(db, role, name):
    u = User(email=f"{name}@x.io", full_name=name, password_hash="x", role=role)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def test_request_must_be_an_elevation(db):
    op = _mk(db, UserRole.OPERATOR, "op")
    with pytest.raises(elevation.ElevationError):
        elevation.create_request(db, op, "operator", 4)  # already operator
    with pytest.raises(elevation.ElevationError):
        elevation.create_request(db, op, "standard", 4)  # not requestable


def test_request_validates_duration(db):
    a = _mk(db, UserRole.STANDARD, "a")
    with pytest.raises(elevation.ElevationError):
        elevation.create_request(db, a, "operator", 3)


def test_one_open_request_at_a_time(db):
    a = _mk(db, UserRole.STANDARD, "a")
    elevation.create_request(db, a, "operator", 4)
    with pytest.raises(elevation.ElevationError):
        elevation.create_request(db, a, "admin", 1)


def test_approval_needs_a_peer_at_or_above_and_not_self(db):
    a = _mk(db, UserRole.STANDARD, "a")
    other_std = _mk(db, UserRole.STANDARD, "b")
    op = _mk(db, UserRole.OPERATOR, "op")
    req = elevation.create_request(db, a, "operator", 4)
    with pytest.raises(elevation.ElevationError):  # a standard can't approve an operator request
        elevation.decide(db, other_std, req.id, True)
    op_req = elevation.create_request(db, op, "admin", 1)  # op requests admin
    with pytest.raises(elevation.ElevationError):  # can't self-approve
        elevation.decide(db, op, op_req.id, True)


def test_approve_materialises_a_delayed_grant(db):
    a = _mk(db, UserRole.STANDARD, "a")
    op = _mk(db, UserRole.OPERATOR, "op")
    req = elevation.create_request(db, a, "operator", 4)
    out = elevation.decide(db, op, req.id, True)
    assert out.status == "approved" and out.approver_id == op.id
    # starts ~1 min out, expires 4h after that
    assert timedelta(seconds=50) < (out.starts_at - out.decided_at) < timedelta(seconds=70)
    assert out.expires_at - out.starts_at == timedelta(hours=4)
    # Grant is set on the user but NOT active yet (still inside the activation delay)
    assert a.temp_role == UserRole.OPERATOR
    assert effective_role(a) == UserRole.STANDARD and not at_least(a, UserRole.OPERATOR)
    # Once the start time passes, it is in force
    a.temp_role_starts = datetime.utcnow() - timedelta(seconds=1)
    assert effective_role(a) == UserRole.OPERATOR and at_least(a, UserRole.OPERATOR)


def test_deny_sets_status_and_grants_nothing(db):
    a = _mk(db, UserRole.STANDARD, "a")
    admin = _mk(db, UserRole.ADMIN, "adm")
    req = elevation.create_request(db, a, "admin", 1)
    out = elevation.decide(db, admin, req.id, False)
    assert out.status == "denied" and a.temp_role is None


def test_revoke_clears_the_grant(db):
    a = _mk(db, UserRole.STANDARD, "a")
    op = _mk(db, UserRole.OPERATOR, "op")
    req = elevation.create_request(db, a, "operator", 8)
    elevation.decide(db, op, req.id, True)
    a.temp_role_starts = datetime.utcnow() - timedelta(seconds=1)  # make it active
    assert at_least(a, UserRole.OPERATOR)
    out = elevation.revoke(db, a, req.id)  # requester revokes their own
    assert out.status == "revoked" and a.temp_role is None
    assert effective_role(a) == UserRole.STANDARD


def test_revoke_only_by_requester_approver_or_admin(db):
    a = _mk(db, UserRole.STANDARD, "a")
    op = _mk(db, UserRole.OPERATOR, "op")
    bystander = _mk(db, UserRole.OPERATOR, "by")
    req = elevation.create_request(db, a, "operator", 8)
    elevation.decide(db, op, req.id, True)
    with pytest.raises(elevation.ElevationError):
        elevation.revoke(db, bystander, req.id)


def test_active_grants_visible_to_approver_and_admin_not_bystander(db):
    a = _mk(db, UserRole.STANDARD, "a")
    op = _mk(db, UserRole.OPERATOR, "op")
    bystander = _mk(db, UserRole.OPERATOR, "by")
    admin = _mk(db, UserRole.ADMIN, "adm")
    req = elevation.create_request(db, a, "operator", 4)
    elevation.decide(db, op, req.id, True)
    assert [r.id for r in elevation.active_grants_for(db, op)] == [req.id]       # the approver
    assert [r.id for r in elevation.active_grants_for(db, admin)] == [req.id]    # any admin
    assert elevation.active_grants_for(db, bystander) == []                      # uninvolved operator
    assert elevation.active_grants_for(db, a) == []                             # not your own


def test_pending_for_filters_by_approver_level(db):
    a = _mk(db, UserRole.STANDARD, "a")
    b = _mk(db, UserRole.STANDARD, "b")
    op = _mk(db, UserRole.OPERATOR, "op")
    admin = _mk(db, UserRole.ADMIN, "adm")
    elevation.create_request(db, a, "operator", 4)
    elevation.create_request(db, b, "admin", 1)
    op_sees = {r.requested_role for r in elevation.pending_for(db, op)}
    assert op_sees == {UserRole.OPERATOR}          # operator can't approve admin requests
    admin_sees = {r.requested_role for r in elevation.pending_for(db, admin)}
    assert admin_sees == {UserRole.OPERATOR, UserRole.ADMIN}
