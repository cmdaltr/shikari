"""GitHub downloads for the telemetry sources: the repository tree, raw files and Git LFS objects."""

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, List
from urllib.parse import quote

import requests

HEADERS = {"User-Agent": "Archer (telemetry datasets)"}
WORKERS = 8


def tree(repo: str, branch: str = "master") -> List[dict]:
    r = requests.get(f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1", headers=HEADERS, timeout=60)
    r.raise_for_status()
    return r.json()["tree"]


def raw(repo: str, path: str, branch: str = "master", timeout: int = 60) -> bytes:
    r = requests.get(f"https://raw.githubusercontent.com/{repo}/{branch}/{quote(path.lstrip('/'))}", headers=HEADERS,
                     timeout=timeout)
    r.raise_for_status()
    return r.content


def lfs(repo: str, path: str, cap: int, branch: str = "master", timeout: int = 120) -> bytes:
    """A Git LFS file's first `cap` bytes (a Range request; GitHub's media host serves LFS without a client)."""
    r = requests.get(f"https://media.githubusercontent.com/media/{repo}/{branch}/{path.lstrip('/')}",
                     headers={**HEADERS, "Range": f"bytes=0-{cap - 1}"}, timeout=timeout, stream=True)
    r.raise_for_status()
    out = bytearray()
    for chunk in r.iter_content(65536):
        out += chunk
        if len(out) >= cap:
            break
    r.close()
    return bytes(out[:cap])


def pool(fn: Callable, items: Iterable, log=print) -> Iterable:
    """fn over items, WORKERS at a time; an item that fails is logged and skipped."""
    def safe(item):
        try:
            return fn(item)
        except Exception as e:
            log(f"  {item}: {e}")
            return None

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for result in ex.map(safe, items):
            if result is not None:
                yield result
