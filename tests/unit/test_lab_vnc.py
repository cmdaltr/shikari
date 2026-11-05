"""Tests for the graphical (VNC) console: endpoint validation + per-machine endpoint storage (#28).

Pure/isolated — the WS↔TCP bridge needs a real VNC target and is exercised manually (see
docs/implementation-plans/28-vm-consoles.md).
"""
import pytest

from shikari.lab import vnc


@pytest.mark.parametrize("host,port", [
    ("127.0.0.1", 5900),
    ("localhost", 5901),
    ("192.168.64.3", 5900),   # private
    ("10.0.0.5", 5900),       # private
    ("169.254.1.2", 5900),    # link-local
    ("::1", 5900),            # loopback v6
    ("127.0.0.1", "5900"),    # string port coerces
])
def test_valid_endpoints_accepted(host, port):
    assert vnc.valid_endpoint(host, port)


@pytest.mark.parametrize("host,port", [
    ("8.8.8.8", 5900),        # public — refused even though well-formed
    ("example.com", 5900),    # hostname (not localhost) — not resolved
    ("127.0.0.1", 0),         # port out of range
    ("127.0.0.1", 70000),     # port out of range
    ("127.0.0.1", "abc"),     # non-numeric port
    ("127.0.0.1", None),      # missing port
    ("", 5900),               # empty host
])
def test_invalid_endpoints_refused(host, port):
    assert not vnc.valid_endpoint(host, port)


def test_registry_vnc_round_trip(tmp_path, monkeypatch):
    from shikari.lab import registry

    monkeypatch.setattr(registry, "LAB_DIR", str(tmp_path))
    monkeypatch.setattr(registry, "_PATH", str(tmp_path / "machines.json"))

    assert registry.get_vnc("utm", "shi-win11") is None       # nothing configured yet
    registry.set_vnc("utm", "shi-win11", "127.0.0.1", 5900)
    assert registry.get_vnc("utm", "shi-win11") == ("127.0.0.1", 5900)

    # Upsert onto an existing Shikari-made record keeps the rest of the entry.
    registry.record("docker", "shi-x", "tmpl", "linux", "img", owner=3)
    registry.set_vnc("docker", "shi-x", "10.0.0.2", 5901)
    entry = registry.get("docker", "shi-x")
    assert entry["owner"] == 3 and entry["template"] == "tmpl"
    assert registry.get_vnc("docker", "shi-x") == ("10.0.0.2", 5901)

    registry.clear_vnc("docker", "shi-x")
    assert registry.get_vnc("docker", "shi-x") is None
    assert registry.get("docker", "shi-x")["owner"] == 3       # only the vnc field went
