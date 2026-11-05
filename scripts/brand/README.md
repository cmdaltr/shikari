# Brand asset generator

Regenerates the SHIKARI brand set — two-tone-K wordmark (Rajdhani SemiBold, gold stem+arm / red
leg), hexagon icon (bateleur profile head on a white interior inside a rounded gold ring), the
three lockup cards, the per-pose hero cards, nav banners, the video master and favicons.

## Run

```bash
python -m venv .venv && . .venv/bin/activate
pip install pillow numpy shapely
python scripts/brand/build_assets.py            # overwrite static/images/shikari/
python scripts/brand/build_assets.py --out /tmp/preview   # preview without touching the repo
```

## Layout

- `wordmark.py` — two-tone-K wordmark. `k_split` cuts the K along the arm's lower edge (one
  halfplane): stem + arm gold, leg red, no gold sliver on the leg.
- `make_icons.py` — hexagon + favicon/apple-touch sizes. Pointy-top rounded hexagon via shapely
  morphological opening; head framing `F` is zoom 0.72 / fx 0.58 / fy 0.45.
- `lockup.py` — the lockup card in three themes (`lightcard`, `darkcard`, `dark`), parametrised by
  bird pose (`branch`, `profile`, `screech`). Bird always on the left.
- `build_assets.py` — drives all three to write the full asset set: six hero/lockup cards
  `shikari-lockup-{perched,profile,screech}-{light,dark}` (light = lightcard, dark = darkcard;
  perched is the home/auth hero), the perched-eagle nav banner `shikari-wordmark-{light,dark}`, the
  video master `shikari-lockup.png`, the hexagon and the favicon/apple-touch set.

Source cutouts come from `static/images/shikari/shikari-bird.png` (perched eagle) and
`static/images/bateleur/_src/bateleur-{profile,screech}.png`. The video pipeline consumes
`shikari-lockup.png` (horizontal master, no tagline — `make_video.py` adds the tagline itself).

Fonts under `fonts/` are Rajdhani (SIL OFL, see `fonts/OFL.txt`).
