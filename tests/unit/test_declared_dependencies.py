"""
Every third-party module Shikari imports comes from a package pyproject.toml declares.

The desktop app and `pip install -e .` install from pyproject.toml alone. anthropic, openai, reportlab,
python-docx and toml were only in requirements.txt, so the installed app's Claude and OpenAI providers,
Generate Report and the Elastic importer failed with "No module named ...". A module that's genuinely
optional (one platform, the local-AI extra's heavier tooling, a standalone simulator) is listed below.
"""
import ast
import re
import sys
import tomllib
from importlib.metadata import packages_distributions
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

OPTIONAL = {
    # One platform: Windows service (pywin32), the ARM64 window (pythonnet), macOS (PyObjC, which
    # pywebview brings), Linux's GTK window (the distro's python3-gi)
    "servicemanager", "win32event", "win32service", "win32serviceutil", "pythonnet", "clr",
    "AppKit", "CoreFoundation", "Foundation", "PyObjCTools", "gi",
    # Local AI and model training: the local-ai extra and beyond, each import guarded
    "llama_cpp", "peft", "datasets", "torch", "transformers",
    # Gemini, behind a try
    "google",
    # The standalone SIEM simulators (python shikari/siem/<siem>/simulator.py), and the parsers
    # they import from beside themselves
    "flask", "kql_parser", "yaral_parser",
}


def _name(requirement):
    return re.sub(r"[-_.]+", "-", re.split(r"[=<>~! ;\[]", requirement.strip(), maxsplit=1)[0]).lower()


def _imports():
    for path in (ROOT / "shikari").rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                yield name.split(".")[0], path.relative_to(ROOT)


def test_every_third_party_import_is_declared():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    declared = {_name(d) for d in project["dependencies"]}
    declared |= {_name(d) for extra in project.get("optional-dependencies", {}).values() for d in extra}
    providers = packages_distributions()
    skip = set(sys.stdlib_module_names) | {"shikari", "MITRESaw", "__future__"} | OPTIONAL

    undeclared = {}
    for top, path in _imports():
        if top in skip:
            continue
        dists = providers.get(top) or []
        if not any(_name(d) in declared for d in dists):
            undeclared.setdefault(f"{top} ({', '.join(dists) or 'not installed'})", str(path))
    assert not undeclared, "imported but not in pyproject.toml: " + "; ".join(
        f"{k} e.g. {v}" for k, v in sorted(undeclared.items()))
