"""Threat Feed watchlists (#18): saved searches that flag new matching posts."""
from unittest.mock import patch

import pytest

from shikari.intelligence import watchlists as wl


def post(n, title="Scattered Spider returns"):
    return {"title": f"{title} {n}", "url": f"https://example.org/{n}", "source": "Example",
            "published": f"2026-10-{n:02d}", "via": "Example"}


def test_what_matches_on_saving_is_seen_and_later_posts_are_new():
    with patch.object(wl, "matches", return_value=[post(1), post(2)]):
        w = wl.add(7, "analyst@example.org", "  Scattered   Spider ")
    assert w["query"] == "Scattered Spider" and w["new_count"] == 0

    sent = []
    with patch.object(wl, "matches", return_value=[post(1), post(2), post(3)]):
        assert wl.check_user(7, send=lambda to, found: sent.append(found)) == 1
    [only] = wl.list_for(7)
    assert [m["url"] for m in only["new"]] == ["https://example.org/3"]
    assert wl.new_count(7) == 1 and sent == []  # email is off for this one
    assert wl.watched(7) == {"https://example.org/3": ["Scattered Spider"]}

    assert wl.mark_seen(7, only["id"]) == 1
    assert wl.new_count(7) == 0
    with patch.object(wl, "matches", return_value=[post(1), post(2), post(3)]):
        assert wl.check_user(7) == 0  # nothing new the second time


def test_email_once_per_new_post():
    with patch.object(wl, "matches", return_value=[]):
        wl.add(8, "analyst@example.org", "RedSun", want_email=True)
    sent = []
    send = lambda to, found: sent.append((to, [(q, [m["url"] for m in items]) for q, items in found]))
    with patch.object(wl, "matches", return_value=[post(4, "RedSun")]):
        wl.check_user(8, send=send)
        wl.check_user(8, send=send)  # still unseen, but already emailed
    assert sent == [("analyst@example.org", [("RedSun", ["https://example.org/4"])])]


def test_limits_and_removal():
    with patch.object(wl, "matches", return_value=[]):
        with pytest.raises(ValueError):
            wl.add(9, None, "ab")
        w = wl.add(9, None, "CVE-2025-53770", web=True)
        with pytest.raises(ValueError):
            wl.add(9, None, "cve-2025-53770")  # same query, any case
    assert wl.update(9, w["id"], web=False)["web"] is False
    assert wl.remove(9, w["id"]) and wl.list_for(9) == []


def test_check_all_reads_every_user():
    with patch.object(wl, "matches", return_value=[]):
        wl.add(1, None, "Volt Typhoon")
        wl.add(2, None, "Salt Typhoon")
    with patch.object(wl, "matches", side_effect=lambda q, web, b=None: [post(5, q)]):
        assert wl.check_all() == 2
