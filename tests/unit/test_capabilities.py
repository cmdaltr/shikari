"""The Help page's dependency matrix: installed / missing / N/A per optional component."""

import os
from unittest.mock import patch

from shikari import capabilities


def _host(engines, label="Test Host"):
    return {"label": label, "os": "linux", "arch": "amd64", "ready": [], "engines": engines}


def _engine(key, name, supported=True, installed=False, running=False, version=""):
    return {"key": key, "name": name, "runs": "", "blurb": "", "supported": supported,
            "installed": installed, "running": running, "version": version, "note": "", "install": ""}


def _matrix(engines, *, ollama=False, env_keys=False, webview=False):
    env = {k: "" for k in capabilities._AI_ENV_KEYS}
    if env_keys:
        env["ANTHROPIC_API_KEY"] = "sk-test"
    with patch.object(capabilities.hosts, "capabilities", return_value=_host(engines)), \
         patch.object(capabilities, "which", return_value="/usr/bin/ollama" if ollama else None), \
         patch("importlib.util.find_spec", return_value=object() if webview else None), \
         patch.dict(os.environ, env, clear=False):
        for k in capabilities._AI_ENV_KEYS:
            if not (env_keys and k == "ANTHROPIC_API_KEY"):
                os.environ.pop(k, None)
        return {r["name"]: r for r in capabilities.dependency_matrix()["rows"]}


def test_unsupported_engine_is_na_not_missing():
    # Tart/UTM on a host that can't run them read N/A, never a red cross
    rows = _matrix([_engine("docker", "Docker"),
                    _engine("tart", "Tart", supported=False),
                    _engine("utm", "UTM", supported=False)])
    assert rows["Tart"]["status"] == "na"
    assert rows["UTM"]["status"] == "na"
    assert rows["Docker / OrbStack"]["status"] == "missing"


def test_installed_engine_reports_version():
    rows = _matrix([_engine("docker", "Docker", installed=True, running=True, version="27.0"),
                    _engine("tart", "Tart", supported=False),
                    _engine("utm", "UTM", supported=False)])
    assert rows["Docker / OrbStack"]["status"] == "installed"
    assert "27.0" in rows["Docker / OrbStack"]["detail"]


def test_ai_available_from_a_local_runtime_or_a_server_key():
    engines = [_engine("docker", "Docker"), _engine("tart", "Tart", supported=False),
               _engine("utm", "UTM", supported=False)]
    assert _matrix(engines, ollama=True)["AI provider"]["status"] == "installed"
    assert _matrix(engines, env_keys=True)["AI provider"]["status"] == "installed"
    assert _matrix(engines)["AI provider"]["status"] == "missing"


def test_desktop_window_follows_pywebview():
    engines = [_engine("docker", "Docker"), _engine("tart", "Tart", supported=False),
               _engine("utm", "UTM", supported=False)]
    assert _matrix(engines, webview=True)["Desktop app window"]["status"] == "installed"
    assert _matrix(engines)["Desktop app window"]["status"] == "missing"
