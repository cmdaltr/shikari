"""The Linux service runs from its data home: Shikari writes data/shikari.db and the rest relative to the
working directory, and the hardened unit lets it write nowhere else."""

import re
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[2] / "deploy" / "linux"


def setting(text: str, key: str) -> str:
    return re.search(rf"^{key}=(.*)$", text, re.MULTILINE).group(1)


def test_the_unit_runs_where_it_may_write():
    unit = (DEPLOY / "shikari.service").read_text()
    assert setting(unit, "WorkingDirectory") == setting(unit, "ReadWritePaths") == "/var/lib/shikari"
    assert "ProtectSystem=strict" in unit


def test_install_sh_points_both_at_its_data_dir():
    script = (DEPLOY / "install.sh").read_text()
    assert 's#^WorkingDirectory=.*#WorkingDirectory=$DATA_DIR#' in script
    assert 's#^ReadWritePaths=.*#ReadWritePaths=$DATA_DIR#' in script
    # The first-admin link is made as the service would make it, against the same database
    assert 'out=$(cd "$DATA_DIR" &&' in script
    assert 'cd "$CODE_DIR"' not in script


def test_cli_commands_run_from_shikari_home(monkeypatch, tmp_path):
    """`shikari first-admin` and the rest must open the database the server uses, not the checkout's."""
    from shikari import service

    seen = {}
    monkeypatch.setenv("SHIKARI_HOME", str(tmp_path))
    monkeypatch.setattr(service.os, "chdir", lambda path: seen.setdefault("cwd", Path(path)))

    def execv(*_):
        raise SystemExit(0)  # where the real one replaces the process

    monkeypatch.setattr(service.os, "execv", execv)
    with pytest.raises(SystemExit):
        service.main(["first-admin", "you@example.org"])
    assert seen["cwd"] == tmp_path

    monkeypatch.delenv("SHIKARI_HOME")
    seen.clear()
    with pytest.raises(SystemExit):
        service.main(["first-admin", "you@example.org"])
    assert seen["cwd"] == service.ROOT
