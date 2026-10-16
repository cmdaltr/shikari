#!/usr/bin/env python3
"""
Build static/images/world_equal_earth.svg: every country (Natural Earth 1:110m, via the
world-atlas package) on the Equal Earth projection, one <path> per country carrying its
name, for pages to colour with CSS. Run once; the SVG is committed, so Archer needs no map
library or network at runtime (air-gapped installs included).

Usage:
    python3 scripts/data/build_world_map.py

Standard library only. Natural Earth is public domain; world-atlas is ISC-licensed.
"""

import json
import math
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "static" / "images" / "world_equal_earth.svg"
SOURCE = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json"
# ISO 3166-1 alpha-2 by numeric code (i18n-iso-countries, MIT), for each country's flag
CODES = "https://cdn.jsdelivr.net/npm/i18n-iso-countries@7/codes.json"
# No numeric code in Natural Earth: Kosovo's is the user-assigned XK; N. Cyprus and Somaliland have none
ISO_BY_NAME = {"Kosovo": "XK"}
WIDTH = 1000
DROP = {"Antarctica"}
# Too small for 1:110m: drawn as a dot at (lon, lat)
POINTS = {"Singapore": (103.82, 1.35, "SG")}

# Equal Earth (Šavrič, Patterson and Jenny, 2018)
A1, A2, A3, A4 = 1.340264, -0.081106, 0.000893, 0.003796
M = math.sqrt(3) / 2


def equal_earth(lon: float, lat: float):
    lam, phi = math.radians(lon), math.radians(lat)
    t = math.asin(M * math.sin(phi))
    t2 = t * t
    t6 = t2 * t2 * t2
    x = lam * math.cos(t) / (M * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2)))
    y = t * (A1 + A2 * t2 + t6 * (A3 + A4 * t2))
    return x, y


X_MAX = equal_earth(180, 0)[0]
Y_MAX = equal_earth(0, 90)[1]
SCALE = WIDTH / (2 * X_MAX)
HEIGHT = round(2 * Y_MAX * SCALE)


def to_svg(lon: float, lat: float):
    # Beyond ±180° (shifted copies) x keeps going linearly, so the clip cuts it at the edge
    x, y = equal_earth(lon, lat)
    return (x + X_MAX) * SCALE, (Y_MAX - y) * SCALE


def decode_arcs(topo):
    """Absolute [lon, lat] points per arc, from the quantised, delta-encoded TopoJSON arcs."""
    (sx, sy), (tx, ty) = topo["transform"]["scale"], topo["transform"]["translate"]
    arcs = []
    for arc in topo["arcs"]:
        x = y = 0
        points = []
        for dx, dy in arc:
            x += dx
            y += dy
            points.append((x * sx + tx, y * sy + ty))
        arcs.append(points)
    return arcs


def ring(indices, arcs):
    points = []
    for i in indices:
        arc = arcs[i] if i >= 0 else arcs[~i][::-1]
        points.extend(arc if not points else arc[1:])  # arcs share their end points
    return points


def unwrap(points):
    """Longitudes made continuous, so a ring crossing 180° (Russia's Chukotka, Fiji) runs past
    it instead of jumping back across the whole map."""
    out = []
    for lon, lat in points:
        if out:
            while lon - out[-1][0] > 180:
                lon -= 360
            while lon - out[-1][0] < -180:
                lon += 360
        out.append((lon, lat))
    return out


def path_d(geometry, arcs) -> str:
    """Each ring, plus a copy shifted 360° for the part past the edge; the page clips both to
    the sphere."""
    polygons = geometry["arcs"] if geometry["type"] == "MultiPolygon" else [geometry["arcs"]]
    parts = []
    for polygon in polygons:
        for r in polygon:
            points = unwrap(ring(r, arcs))
            lons = [lon for lon, _ in points]
            shifts = [0] + ([-360] if max(lons) > 180 else []) + ([360] if min(lons) < -180 else [])
            for shift in shifts:
                pts = [to_svg(lon + shift, lat) for lon, lat in points]
                parts.append("M" + "L".join(f"{x:.1f},{y:.1f}" for x, y in pts) + "Z")
    return "".join(parts)


def main() -> int:
    with urllib.request.urlopen(SOURCE, timeout=60) as res:
        topo = json.load(res)
    with urllib.request.urlopen(CODES, timeout=60) as res:
        iso2 = {numeric: alpha2 for alpha2, _, numeric, *_ in json.load(res)}
    arcs = decode_arcs(topo)
    paths = []
    for g in sorted(topo["objects"]["countries"]["geometries"], key=lambda g: g["properties"]["name"]):
        name = g["properties"]["name"]
        if name in DROP or g.get("type") not in ("Polygon", "MultiPolygon"):
            continue
        iso = ISO_BY_NAME.get(name) or iso2.get(str(g.get("id") or ""), "")
        paths.append(f'<path class="country" data-name="{name}" data-iso="{iso}" d="{path_d(g, arcs)}"><title>{name}</title></path>')
    for name, (lon, lat, iso) in POINTS.items():
        x, y = to_svg(lon, lat)
        paths.append(f'<circle class="country is-point" data-name="{name}" data-iso="{iso}" cx="{x:.1f}" cy="{y:.1f}" r="4">'
                     f'<title>{name}</title></circle>')
    outline = [to_svg(180, lat) for lat in range(-90, 91, 2)] + [to_svg(-180, lat) for lat in range(90, -91, -2)]
    sphere = "M" + "L".join(f"{x:.1f},{y:.1f}" for x, y in outline) + "Z"
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" class="world-map" role="img" '
           f'aria-label="World map, Equal Earth projection">\n'
           f'<defs><clipPath id="wm-sphere"><path d="{sphere}"/></clipPath></defs>\n'
           f'<path class="sphere" d="{sphere}"/>\n<g clip-path="url(#wm-sphere)">\n'
           + "\n".join(paths) + "\n</g>\n</svg>\n")
    OUT.write_text(svg, encoding="utf-8")
    print(f"{OUT.relative_to(ROOT)}: {len(paths)} countries, {len(svg) // 1024} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
