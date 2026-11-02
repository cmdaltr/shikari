from pathlib import Path

from shikari.intelligence import cyber_powers, feed

SVG = (Path(__file__).resolve().parents[2] / "static" / "images" / "world_equal_earth.svg").read_text()


def test_every_state_is_on_the_map():
    for group in cyber_powers.powers()["groups"]:
        for state in group["states"]:
            assert f'data-name="{state["map"]}"' in SVG, state


def test_iiss_tiers_cover_both_volumes_once_each():
    states = [s for t in cyber_powers.TIERS for s in t["states"]]
    assert len(states) == len(set(states)) == 25
    assert cyber_powers.VOLUME_2 <= set(states)


def test_the_feed_tags_every_state_the_page_shows():
    for group in cyber_powers.powers()["groups"]:
        for state in group["states"]:
            assert state["name"] in feed.NATIONS
