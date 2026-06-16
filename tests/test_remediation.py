"""Remediation + terraform-validate tests (FR-10, FR-11)."""

from __future__ import annotations

from iac_threatgen import remediation


def test_terraform_validate_graceful_when_binary_absent(monkeypatch):
    monkeypatch.setattr("iac_threatgen.remediation.shutil.which", lambda _: None)
    assert remediation.terraform_available() is False
    passed, msg = remediation.terraform_validate([{"path": "main.tf", "content": "x"}])
    assert passed is None
    assert "terraform binary not found" in msg


def test_generate_remediation_parses_model_output(monkeypatch):
    canned = {"summary": "hardened", "files": [{"path": "remediation.tf", "content": "# secure"}]}
    monkeypatch.setattr("iac_threatgen.llm.chat_json", lambda s, u, **k: (canned, {"input_tokens": 1, "output_tokens": 1}))
    rem, usage = remediation.generate_remediation({"resources": [], "edges": []}, [])
    assert rem["files"][0]["path"] == "remediation.tf"
    assert usage["input_tokens"] == 1


def test_generate_remediation_rejects_bad_shape(monkeypatch):
    monkeypatch.setattr("iac_threatgen.llm.chat_json", lambda s, u, **k: ({"nope": 1}, {}))
    import pytest

    with pytest.raises(ValueError):
        remediation.generate_remediation({"resources": []}, [])


import types  # noqa: E402


def _completed(returncode, out=""):
    return types.SimpleNamespace(returncode=returncode, stdout=out, stderr="")


def test_terraform_validate_success(monkeypatch):
    monkeypatch.setattr("iac_threatgen.remediation.shutil.which", lambda _: "terraform")

    def fake_run(args, **kwargs):
        return _completed(0, "Success!\n")

    monkeypatch.setattr("iac_threatgen.remediation.subprocess.run", fake_run)
    passed, output = remediation.terraform_validate([{"path": "remediation.tf", "content": "x"}])
    assert passed is True
    assert "Success" in output


def test_terraform_validate_init_failure(monkeypatch):
    monkeypatch.setattr("iac_threatgen.remediation.shutil.which", lambda _: "terraform")

    def fake_run(args, **kwargs):
        # fail on init (first call)
        return _completed(1, "init boom") if "init" in args else _completed(0)

    monkeypatch.setattr("iac_threatgen.remediation.subprocess.run", fake_run)
    passed, output = remediation.terraform_validate([{"path": "remediation.tf", "content": "x"}])
    assert passed is False
    assert "terraform init failed" in output
