"""GitHub PR agent (FR-12). Opens a branch + pull request — never auto-merges, never force-pushes.

Uses httpx (already in the dependency tree via openai, ADR-5) against the GitHub REST API. Needs a
fine-grained PAT with only contents:write + pull_requests:write on the target repo (least
privilege, R-06). Token + repo come from the environment, never from model output.
"""

from __future__ import annotations

import base64
import os

import httpx

_API = "https://api.github.com"


class GitHubConfigError(RuntimeError):
    pass


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def open_pull_request(
    files: list[dict],
    *,
    title: str,
    body: str,
    branch: str,
) -> dict:
    """Create branch, commit files, open a PR. Returns PR metadata.

    Raises GitHubConfigError if token/repo are missing.
    """
    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPOSITORY")
    if not token or not repo:
        raise GitHubConfigError("GITHUB_TOKEN and GITHUB_REPOSITORY must be set to open a PR.")

    with httpx.Client(base_url=_API, headers=_headers(token), timeout=30.0) as client:
        # 1. default branch + base sha
        repo_info = client.get(f"/repos/{repo}")
        repo_info.raise_for_status()
        base = repo_info.json()["default_branch"]

        ref = client.get(f"/repos/{repo}/git/ref/heads/{base}")
        ref.raise_for_status()
        base_sha = ref.json()["object"]["sha"]

        # 2. create the feature branch (never the default branch)
        client.post(
            f"/repos/{repo}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": base_sha},
        ).raise_for_status()

        # 3. write each file on the new branch (Contents API)
        changed: list[str] = []
        for f in files:
            path = f["path"]
            payload = {
                "message": f"threatgen: harden {path}",
                "content": base64.b64encode(f.get("content", "").encode()).decode(),
                "branch": branch,
            }
            existing = client.get(f"/repos/{repo}/contents/{path}", params={"ref": branch})
            if existing.status_code == 200:
                payload["sha"] = existing.json()["sha"]
            put = client.put(f"/repos/{repo}/contents/{path}", json=payload)
            put.raise_for_status()
            changed.append(path)

        # 4. open the PR (proposes only — no merge call)
        pr = client.post(
            f"/repos/{repo}/pulls",
            json={"title": title, "head": branch, "base": base, "body": body},
        )
        pr.raise_for_status()
        pr_json = pr.json()

    return {
        "branch": branch,
        "title": title,
        "body": body,
        "files_changed": changed,
        "url": pr_json.get("html_url", ""),
    }
