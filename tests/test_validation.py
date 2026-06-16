"""Groundedness + schema validation tests (FR-9, FR-17, R-03)."""

from __future__ import annotations

import pytest

from iac_threatgen.rag import AttackIndex
from iac_threatgen.validation import check_groundedness, validate_report

GRAPH = {"resources": [{"id": "aws_s3_bucket.data", "type": "aws_s3_bucket", "name": "data"}]}


def _threat(**over):
    base = {
        "id": "TH-001",
        "stride": "InformationDisclosure",
        "title": "t",
        "description": "d",
        "resource_id": "aws_s3_bucket.data",
        "severity": "high",
        "attack": [{"technique_id": "T1530"}],
        "mitigations": [{"csf_function": "PR", "csf_subcategory": "PR.DS-01", "recommendation": "r"}],
    }
    base.update(over)
    return base


@pytest.fixture(scope="module")
def index():
    return AttackIndex()


def test_grounded_threat_passes(index):
    assert check_groundedness([_threat()], GRAPH, index) == []


def test_rejects_hallucinated_attack_id(index):
    errs = check_groundedness([_threat(attack=[{"technique_id": "T9999"}])], GRAPH, index)
    assert any("T9999" in e for e in errs)


def test_rejects_unknown_resource(index):
    errs = check_groundedness([_threat(resource_id="aws_s3_bucket.ghost")], GRAPH, index)
    assert any("ghost" in e for e in errs)


def test_rejects_bad_stride_and_csf(index):
    errs = check_groundedness([_threat(stride="Bogus")], GRAPH, index)
    assert any("STRIDE" in e for e in errs)
    bad_csf = _threat(mitigations=[{"csf_function": "ZZ", "csf_subcategory": "ZZ.ZZ-99", "recommendation": "r"}])
    errs2 = check_groundedness([bad_csf], GRAPH, index)
    assert any("CSF" in e for e in errs2)


def test_report_schema_validation_roundtrip():
    report = {
        "schema_version": "1.0",
        "generated_at": "2026-06-16T00:00:00+00:00",
        "model": "meta/llama-3.3-70b-instruct",
        "input_summary": {"resource_count": 1, "files": ["main.tf"]},
        "dfd_mermaid": "flowchart LR\n  a",
        "threats": [_threat(attack=[{"technique_id": "T1530", "technique_name": "Data from Cloud Storage"}])],
    }
    validate_report(report)  # should not raise
