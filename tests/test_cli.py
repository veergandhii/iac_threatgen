"""CLI tests (G7, NFR-8) — rendering, summary, and the scan command via a mocked pipeline."""

from __future__ import annotations

import json

from iac_threatgen import cli

_REPORT = {
    "schema_version": "1.0",
    "generated_at": "2026-06-16T00:00:00+00:00",
    "model": "meta/llama-3.3-70b-instruct",
    "input_summary": {"resource_count": 2, "files": ["main.tf"], "skipped_count": 0},
    "dfd_mermaid": "flowchart LR\n    n0[\"x\"]",
    "threats": [
        {
            "id": "TH-001",
            "stride": "InformationDisclosure",
            "title": "Public bucket",
            "description": "desc",
            "resource_id": "aws_s3_bucket.data",
            "severity": "high",
            "attack": [{"technique_id": "T1530", "technique_name": "Data from Cloud Storage", "url": "u"}],
            "mitigations": [{"csf_function": "PR", "csf_subcategory": "PR.DS-01", "recommendation": "fix"}],
        }
    ],
    "_warnings": ["heads up"],
    "_secret_findings": [{"resource_id": "r", "attribute": "password", "reason": "secret-like attribute name"}],
}


def test_render_markdown_contains_mermaid_and_table():
    md = cli._render_markdown(_REPORT)
    assert "```mermaid" in md
    assert "| TH-001 |" in md
    assert "Data from Cloud Storage" in md
    assert "## Secrets detected" in md
    assert "## Warnings" in md


def test_print_summary(capsys):
    cli._print_summary(_REPORT)
    out = capsys.readouterr().out
    assert "Threats: 1" in out
    assert "high=1" in out
    assert "heads up" in out


def test_cmd_scan_writes_files(monkeypatch, tmp_path):
    monkeypatch.setattr("iac_threatgen.pipeline.run_pipeline", lambda *a, **k: _REPORT)
    out = tmp_path / "r.json"
    md = tmp_path / "r.md"
    rc = cli.main(["scan", "somepath", "-o", str(out), "--markdown", str(md)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "_warnings" not in data  # meta stripped from JSON artifact
    assert data["threats"][0]["id"] == "TH-001"
    assert md.exists()


def test_main_returns_setup_code_on_config_error(monkeypatch, tmp_path):
    from iac_threatgen.llm import LLMConfigError

    def boom(*a, **k):
        raise LLMConfigError("no key")

    monkeypatch.setattr("iac_threatgen.pipeline.run_pipeline", boom)
    rc = cli.main(["scan", "x", "-o", str(tmp_path / "r.json")])
    assert rc == 2


def test_main_returns_fail_code_on_unexpected_error(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr("iac_threatgen.pipeline.run_pipeline", boom)
    rc = cli.main(["scan", "x", "-o", str(tmp_path / "r.json")])
    assert rc == 3
