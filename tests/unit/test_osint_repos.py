"""Without git (Windows, a Mac without the developer tools) the OSINT repos come as tarballs."""
import io
import tarfile

import pytest

from shikari.build import osint_repos


def _tarball(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, body in files.items():
            info = tarfile.TarInfo(f"repo-abc123/{name}")
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
        link = tarfile.TarInfo("repo-abc123/Detections/escape")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        tar.addfile(link)
    return buf.getvalue()


class FakeResponse:
    def __init__(self, body=b"", data=None):
        self.raw, self._data = io.BytesIO(body), data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass


@pytest.fixture
def no_git(tmp_path, monkeypatch):
    monkeypatch.setattr(osint_repos, "_GIT", False)
    monkeypatch.setattr(osint_repos, "REPOS_BASE_DIR", tmp_path)
    monkeypatch.setitem(osint_repos.REPOS, "azure_sentinel",
                        {**osint_repos.REPOS["azure_sentinel"], "path": str(tmp_path / "azure_sentinel")})
    calls = []
    head = {"sha": "abc123", "commit": {"committer": {"date": "2026-10-27T09:00:00Z"}}}
    body = _tarball({
        "Detections/rule.yaml": b"T1078",
        "Solutions/Okta/Analytic Rules/okta.yaml": b"T1110.003",
        "Solutions/Okta/Workbooks/okta.json": b"{}",
        "Solutions/Okta/Nested/Analytic Rules/no.yaml": b"T1078",
        "Workbooks/big.json": b"{}",
    })

    def get(url, **kw):
        calls.append(url)
        return FakeResponse(data=head) if "api.github.com" in url else FakeResponse(body)

    monkeypatch.setattr(osint_repos.requests, "get", get)
    return tmp_path / "azure_sentinel", calls


def test_only_the_rule_folders_are_kept(no_git):
    repo, _ = no_git
    assert osint_repos.clone_or_update_repo("azure_sentinel", force=True)
    kept = sorted(str(p.relative_to(repo)).replace("\\", "/") for p in repo.rglob("*") if p.is_file())
    assert kept == [".commit", ".last_update", "Detections/rule.yaml", "Solutions/Okta/Analytic Rules/okta.yaml"]
    assert osint_repos.commit_date("azure_sentinel") == "2026-10-27"


def test_an_unchanged_branch_isnt_downloaded_again(no_git):
    repo, calls = no_git
    osint_repos.clone_or_update_repo("azure_sentinel", force=True)
    calls.clear()
    assert osint_repos.clone_or_update_repo("azure_sentinel", force=True)
    assert not any("codeload" in c for c in calls)


def test_a_huge_tarball_is_refreshed_weekly_not_hourly(no_git):
    repo, _ = no_git
    osint_repos.clone_or_update_repo("azure_sentinel", force=True)
    for days, due in ((3, False), (8, True)):
        then = osint_repos.datetime.now() - osint_repos.timedelta(days=days)
        (repo / ".last_update").write_text(then.isoformat())
        assert osint_repos.needs_update("azure_sentinel") is due


def test_search_works_without_grep(no_git, monkeypatch):
    repo, _ = no_git
    osint_repos.clone_or_update_repo("azure_sentinel", force=True)
    monkeypatch.setattr(osint_repos.shutil, "which", lambda name: None)
    found = osint_repos.search_repo_for_technique("azure_sentinel", "T1110")
    assert len(found) == 1 and found[0].endswith("okta.yaml")
