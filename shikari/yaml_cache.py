"""
Detection YAML parsed once per file version. The results page reads each of a group's
files several times (detections, OSINT details, the attack flow); with PyYAML's pure-Python
parser that took Scattered Spider's page to 40 s. libyaml's parser, plus a cache keyed on
path, mtime and size, makes the repeats free. Callers get their own copy, so they can change it.
"""

import os
import pickle
import threading
from collections import OrderedDict

import yaml

Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

# (path, mtime, size) -> the parse, pickled: unpickling a fresh copy for each caller is several
# times faster than deepcopy. Least recently used out first.
_CACHE: "OrderedDict[tuple, bytes]" = OrderedDict()
_MAX = 8192
_LOCK = threading.Lock()


def loads(text: str):
    """safe_load with libyaml when it's installed."""
    return yaml.load(text, Loader=Loader)


def load(path: str, text: str = None):
    """A file's YAML, parsed at most once per version; raises like yaml.safe_load.

    text is the file's contents when the caller has already read them; only a miss needs it.
    """
    st = os.stat(path)
    key = (os.path.abspath(path), st.st_mtime, st.st_size)
    with _LOCK:
        blob = _CACHE.get(key)
        if blob is not None:
            _CACHE.move_to_end(key)
    if blob is None:
        if text is None:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        blob = pickle.dumps(loads(text), protocol=pickle.HIGHEST_PROTOCOL)
        with _LOCK:
            _CACHE[key] = blob
            if len(_CACHE) > _MAX:
                _CACHE.popitem(last=False)
    return pickle.loads(blob)
