"""GitHub PR agent tests (FR-12) — config guard without network."""

from __future__ import annotations

import pytest

from iac_threatgen import github_pr


def test_open_pr_requires_token_and_repo(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    with pytest.raises(github_pr.GitHubConfigError):
        github_pr.open_pull_request(
            [{"path": "remediation.tf", "content": "x"}],
            title="t",
            body="b",
            branch="threatgen/test",
        )


def test_headers_include_bearer_and_api_version():
    h = github_pr._headers("tok")
    assert h["Authorization"] == "Bearer tok"
    assert h["X-GitHub-Api-Version"] == "2022-11-28"


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError(f"unexpected error status {self.status_code}")


class _FakeClient:
    """Minimal httpx.Client stand-in routing by path."""

    def __init__(self, *a, **k):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, path, **k):
        self.calls.append(("GET", path))
        if path.endswith("/repos/o/r"):
            return _Resp(payload={"default_branch": "main"})
        if "git/ref/heads/main" in path:
            return _Resp(payload={"object": {"sha": "basesha"}})
        if "contents/" in path:
            return _Resp(status=404)  # file does not exist yet
        return _Resp()

    def post(self, path, **k):
        self.calls.append(("POST", path))
        if path.endswith("/pulls"):
            return _Resp(payload={"html_url": "https://github.com/o/r/pull/1"})
        return _Resp()

    def put(self, path, **k):
        self.calls.append(("PUT", path))
        return _Resp(payload={})


def test_open_pull_request_full_flow(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setattr("iac_threatgen.github_pr.httpx.Client", _FakeClient)

    result = github_pr.open_pull_request(
        [{"path": "remediation.tf", "content": "# secure"}],
        title="threatgen: fix",
        body="body",
        branch="threatgen/x",
    )
    assert result["url"] == "https://github.com/o/r/pull/1"
    assert result["files_changed"] == ["remediation.tf"]
    assert result["branch"] == "threatgen/x"
