"""
Playwright UI tests for the results page's attack flow drag and drop (#4): moving a
technique to another tactic, reordering tactics, drawing links, the keyboard, and the
edits reaching the STIX export. Needs a running Shikari with UNC3944's results.

Saving layouts and exporting are intercepted, so nothing reaches the Library.
"""
import json

import pytest

pytestmark = pytest.mark.ui
GROUP = "UNC3944"


@pytest.fixture
def flow(authenticated_page, base_url):
    page = authenticated_page
    sent = {"layout": [], "export": []}
    page.route("**/api/flow-layout", lambda r: (sent["layout"].append(json.loads(r.request.post_data)),
                                                 r.fulfill(status=200, body='{"saved": true}')))
    page.route("**/api/attack-flow/export", lambda r: (sent["export"].append(json.loads(r.request.post_data)),
                                                        r.fulfill(status=200, body="{}")))
    page.goto(f"{base_url}/results?group_name={GROUP}")
    page.wait_for_selector("#attack-flow .af-node")
    page.evaluate("document.getElementById('attack-flow').scrollIntoView()")
    page.sent = sent
    return page


def lanes(page):
    """[(tactic, [technique ids])] in the order shown."""
    return page.evaluate("""() => [...document.querySelectorAll('#attack-flow .af-lane:not([hidden])')]
        .sort((a, b) => (+a.style.order || 0) - (+b.style.order || 0))
        .map(l => [l.dataset.tactic, [...l.querySelectorAll('.af-node:not([hidden])')].map(n => n.dataset.id)])""")


def centre(page, selector, fy=0.5):
    box = page.locator(selector).first.bounding_box()
    return box["x"] + box["width"] / 2, box["y"] + box["height"] * fy


def drag(page, start, end, alt=False):
    page.mouse.move(*start)
    page.mouse.down()
    if alt:
        page.keyboard.down("Alt")
    for i in range(1, 9):
        page.mouse.move(start[0] + (end[0] - start[0]) * i / 8, start[1] + (end[1] - start[1]) * i / 8)
    page.mouse.up()
    if alt:
        page.keyboard.up("Alt")


def test_card_moves_to_another_tactic(flow):
    before = lanes(flow)
    (src, ids), (dst, dst_ids) = before[0], before[1]
    card = f'.af-node[data-id="{ids[0]}"]'
    drag(flow, centre(flow, card), centre(flow, f'.af-lane[data-tactic="{dst}"] .af-node[data-id="{dst_ids[0]}"]', 0.25))
    after = dict(lanes(flow))
    assert ids[0] in after[dst] and after[dst].index(ids[0]) == 0
    assert ids[0] not in after.get(src, [])
    assert "is-retagged" in flow.get_attribute(card, "class") or dst in flow.get_attribute(card, "title")
    flow.click("#af-undo")
    assert dict(lanes(flow))[dst] == dst_ids


def test_alt_drag_places_freely(flow):
    (src, ids) = lanes(flow)[0]
    card = f'.af-node[data-id="{ids[0]}"]'
    x, y = centre(flow, card)
    drag(flow, (x, y), (x + 40, y + 300), alt=True)
    assert dict(lanes(flow))[src][0] == ids[0]
    assert "translate" in flow.get_attribute(card, "style")


def test_tactics_reorder_by_their_heads(flow):
    order = [t for t, _ in lanes(flow)]
    first, second = order[0], order[1]
    sx, sy = centre(flow, f'.af-lane[data-tactic="{first}"] .af-lane-head')
    box = flow.locator(f'.af-lane[data-tactic="{second}"]').bounding_box()
    drag(flow, (sx, sy), (box["x"] + box["width"] * 0.8, sy))
    new = [t for t, _ in lanes(flow)]
    assert new[:2] == [second, first]


def test_draw_a_link_and_remove_it(flow):
    (_, a), (_, b) = lanes(flow)[0], lanes(flow)[2]
    count = int(flow.inner_text("#af-stat-edges"))
    flow.hover(f'.af-node[data-id="{a[0]}"]')
    drag(flow, centre(flow, f'.af-node[data-id="{a[0]}"] .af-link-handle'), centre(flow, f'.af-node[data-id="{b[0]}"]'))
    assert int(flow.inner_text("#af-stat-edges")) == count + 1
    assert flow.locator(f'path.af-edge.is-manual[data-from="{a[0]}"][data-to="{b[0]}"]').count() == 1
    flow.click(f'.af-node[data-id="{a[0]}"]')
    assert "drawn" in flow.inner_text("#af-detail-body").lower()
    flow.locator(f'.af-unlink[data-key="{a[0]}>{b[0]}"]').click()
    assert int(flow.inner_text("#af-stat-edges")) == count


def test_keyboard_moves_a_card(flow):
    (src, ids), (dst, _) = lanes(flow)[0], lanes(flow)[1]
    flow.focus(f'.af-node[data-id="{ids[0]}"]')
    flow.keyboard.press("Alt+ArrowRight")
    assert ids[0] in dict(lanes(flow))[dst]


def test_edits_reach_the_export(flow):
    (src, ids), (dst, _) = lanes(flow)[0], lanes(flow)[1]
    flow.focus(f'.af-node[data-id="{ids[0]}"]')
    flow.keyboard.press("Alt+ArrowRight")
    flow.click("#af-stix")
    flow.wait_for_timeout(300)
    state = flow.sent["export"][-1]["state"]
    assert ids[0] in state["arrangement"][dst]


def test_lifecycle_tabs_regroup_the_same_cards(flow):
    ids = sorted(i for _, tids in lanes(flow) for i in tids)
    flow.click('.af-tab[data-framework="ckc"]')
    phases = flow.evaluate("""() => [...document.querySelectorAll('#attack-flow .af-lane:not([hidden])')]
        .map(l => [l.dataset.phase, [...l.querySelectorAll('.af-node:not([hidden])')].map(n => n.dataset.id)])""")
    names = [p for p, _ in phases]
    assert names[:7] == ["Reconnaissance", "Weaponization", "Delivery", "Exploitation", "Installation",
                         "Command & Control", "Actions on Objectives"]
    assert sorted(i for _, tids in phases for i in tids) == ids
    assert flow.locator('.af-about[data-framework="ckc"]').is_visible()
    # Read-only here: a drag doesn't move the card or record an edit
    first = next(tids[0] for _, tids in phases if tids)
    x, y = centre(flow, f'.af-node[data-id="{first}"]')
    drag(flow, (x, y), (x + 400, y))
    assert flow.is_disabled("#af-undo")
    flow.click('.af-tab[data-framework="tal"]')
    assert "Maintain Presence" in flow.evaluate(
        "() => [...document.querySelectorAll('#attack-flow .af-lane:not([hidden])')].map(l => l.dataset.phase)")
    flow.click('.af-tab[data-framework="attack"]')
    assert sorted(i for _, tids in lanes(flow) for i in tids) == ids
    assert all(t for t, _ in lanes(flow))
