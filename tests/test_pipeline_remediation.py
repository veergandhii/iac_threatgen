"""Pipeline remediation branch with mocked LLM + absent terraform binary (graceful)."""

from __future__ import annotations

from iac_threatgen.pipeline import run_pipeline

_THREATS = [
    {
        "id": "TH-001",
        "stride": "InformationDisclosure",
        "title": "Public S3",
        "description": "d",
        "resource_id": "aws_s3_bucket.data",
        "severity": "high",
        "attack": [{"technique_id": "T1530"}],
        "mitigations": [
            {"csf_function": "PR", "csf_subcategory": "PR.DS-01", "recommendation": "block public"}
        ],
    }
]
_REMEDIATION = {"summary": "hardened bucket", "files": [{"path": "remediation.tf", "content": "# secure"}]}


def test_remediation_branch_runs_and_degrades_without_terraform(monkeypatch, sample_stack):
    def fake_chat_json(system, user, **kwargs):
        # Branch by which prompt is being served (only the mapper says "threat modeling").
        if "threat modeling" in system:
            return list(_THREATS), {"input_tokens": 5, "output_tokens": 5}
        return dict(_REMEDIATION), {"input_tokens": 5, "output_tokens": 5}

    monkeypatch.setattr("iac_threatgen.llm.chat_json", fake_chat_json)
    # Force terraform to be "not installed" so the validate gate degrades gracefully.
    monkeypatch.setattr("iac_threatgen.remediation.shutil.which", lambda _: None)

    report = run_pipeline(sample_stack, enable_remediation=True, open_pr=False)

    assert report["remediation_pr"] is not None
    assert "remediation.tf" in report["remediation_pr"]["files_changed"]
    assert report["remediation_pr"]["terraform_validate_passed"] is False
    assert any("terraform binary not found" in w for w in report["_warnings"])
