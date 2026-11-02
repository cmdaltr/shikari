"""
Where Shikari's files are.

ROOT is what ships with the code: templates, static, shikari/'s own reference data. HOME is
what Shikari writes and what each install supplies: data/ (the database, generated
detections, caches), bespoke/ (organisation mappings) and shikari/data/cache (the ATT&CK
bundle). In a checkout they're the same directory, so nothing moves. The desktop app
(shikari/desktop_app.py) sets SHIKARI_HOME to a per-user folder, because an installed app's
own directory is read-only, and makes it the working directory, which is what the relative
paths in shikari/config.py and elsewhere ("data/...", "bespoke/...") resolve against.
"""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOME = Path(os.environ.get("SHIKARI_HOME") or ROOT).expanduser().resolve()

DATA = HOME / "data"
BESPOKE = HOME / "bespoke"
# shikari/data/cache, not data/cache: where a checkout has always kept the ATT&CK bundle
CACHE = HOME / "shikari" / "data" / "cache"
TEMPLATES = ROOT / "templates"
STATIC = ROOT / "static"

# The mappings an install starts with: everything bespoke/mappings needs, with generic
# CEF-aligned Splunk indexes and sourcetypes (shikari/mappings/defaults/README.md)
DEFAULT_MAPPINGS = ROOT / "shikari" / "mappings" / "defaults"


# These name Splunk indexes, so they only make sense together: seeded into an empty folder,
# never mixed with an organisation's own index names
SPLUNK_SET = {"indicatorMapping.json", "schemas/schemaSplunk.json", "sources/platforms.json",
              "sources/logSourceCategories.json", "sources/dataSources.json", "sources/display_names.json"}


def seed_bespoke():
    """Copy the default mappings bespoke/mappings is missing. Never overwrites. The Splunk set
    goes in only when the folder has no mappings at all; the vendor schemas (MDE, Elastic,
    SecOps) and the technique matrix fill gaps one by one. Returns what was copied."""
    import shutil

    target = BESPOKE / "mappings"
    fresh = not any(target.rglob("*.json"))
    copied = []
    for src in sorted(DEFAULT_MAPPINGS.rglob("*.json")):
        rel = src.relative_to(DEFAULT_MAPPINGS).as_posix()
        dest = target / rel
        if dest.exists() or (rel in SPLUNK_SET and not fresh):
            continue
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
            copied.append(f"bespoke/mappings/{rel}")
        except OSError:
            pass
    return copied
