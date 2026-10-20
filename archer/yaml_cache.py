"""
Detection YAML parsed once per file version. The results page reads each of a group's
files several times (detections, OSINT details, the attack flow); with PyYAML's pure-Python
parser that took Scattered Spider's page to 40 s. libyaml's parser, plus a cache keyed on
path, mtime and size, makes the repeats free. Callers get their own copy, so they can change it.
"""

import copy
import os
from functools import lru_cache

import yaml

Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


@lru_cache(maxsize=8192)
def _parse(path: str, mtime: float, size: int, text: str):
    return yaml.load(text, Loader=Loader)


def loads(text: str):
    """safe_load with libyaml when it's installed."""
    return yaml.load(text, Loader=Loader)


def load(path: str, text: str = None):
    """A file's YAML, parsed at most once per version; raises like yaml.safe_load."""
    st = os.stat(path)
    if text is None:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    return copy.deepcopy(_parse(os.path.abspath(path), st.st_mtime, st.st_size, text))
