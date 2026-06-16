"""End-to-end pipeline test with a mocked LLM (no API key, no network) — the CI-safe path.

Patches llm.chat_json so the LangGraph pipeline runs deterministically and the output is validated
against the frozen threat-report schema (FR-9).
"""

from __future__ import annotations

import json

from iac_threatgen import validation
from iac_threatgen.pipeline import run_pipeline

_CANNED = [
    {
        "id": "TH-001",
        "stride": "InformationDisclosure",
        "title": "Public S3 bucket",
        "description": "Bucket is world-readable.",
        "resource_id": "aws_s3_bucket.data",
        "severity": "high",
        "attack": [{"technique_id": "T1530"}],
        "mitigations": [
            {"csf_function": "PR", "csf_subcategory": "PR.DS-01", "recommendation": "Block public access."}
        ],
    },
    {
        "id": "TH-002",
        "stride": "ElevationOfPrivilege",
        "title": "Open security group",
        "description": "SG allows 0.0.0.0/0.",
        "resource_id": "aws_security_group.web",
        "severity": "critical",
        "attack": [{"technique_id": "T1190"}],
        "mitigations": [
            {"csf_function": "PR", "csf_subcategory": "PR.AA-01", "recommendation": "Restrict CIDRs."}
        ],
    },
]


def test_pipeline_runs_and_output_is_schema_valid(monkeypatch, sample_stack):
    def fake_chat_json(system, user, **kwargs):
        return list(_CANNED), {"input_tokens": 10, "output_tokens": 20}

    monkeypatch.setattr("iac_threatgen.llm.chat_json", fake_chat_json)

    report = run_pipeline(sample_stack, enable_remediation=False, open_pr=False)

    # Public report (without _meta) must validate against the schema.
    public = {k: v for k, v in report.items() if not k.startswith("_")}
    validation.validate_report(public)
    json.dumps(public)  # must be JSON-serializable

    assert len(report["threats"]) == 2
    assert report["input_summary"]["resource_count"] == 6
    # secret in the fixture's RDS password must have been redacted before the (mock) LLM
    assert any(f["attribute"] == "password" for f in report["_secret_findings"])
    # ATT&CK names were enriched from the corpus
    names = {a.get("technique_name") for t in report["threats"] for a in t["attack"]}
    assert "Data from Cloud Storage" in names


def test_pipeline_drops_ungrounded_threats(monkeypatch, sample_stack):
    def fake_chat_json(system, user, **kwargs):
        bad = [
            {
                "id": "TH-001",
                "stride": "Tampering",
                "title": "Hallucinated",
                "description": "fake technique",
                "resource_id": "aws_s3_bucket.data",
                "severity": "low",
                "attack": [{"technique_id": "T9999"}],  # not in corpus
                "mitigations": [
                    {"csf_function": "PR", "csf_subcategory": "PR.DS-01", "recommendation": "x"}
                ],
            }
        ]
        return bad, {}

    monkeypatch.setattr("iac_threatgen.llm.chat_json", fake_chat_json)
    report = run_pipeline(sample_stack, enable_remediation=False, open_pr=False)
    # ungrounded threat dropped after retries; report still schema-valid with a warning
    assert report["threats"] == []
    assert any("ungrounded" in w for w in report["_warnings"])
