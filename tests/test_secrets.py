"""Secret redaction tests (FR-15, R-05)."""

from __future__ import annotations

from iac_threatgen.secrets_scan import REDACTED, redact_graph


def _graph(attrs):
    return {"resources": [{"id": "r.x", "type": "t", "name": "x", "attributes": attrs}]}


def test_redacts_by_attribute_name():
    g = _graph({"password": "hunter2", "bucket": "public-name"})
    red, findings = redact_graph(g)
    assert red["resources"][0]["attributes"]["password"] == REDACTED
    assert red["resources"][0]["attributes"]["bucket"] == "public-name"
    assert findings[0]["attribute"] == "password"


def test_redacts_aws_key_pattern_even_under_innocent_name():
    g = _graph({"note": "key is AKIAIOSFODNN7EXAMPLE here"})
    red, findings = redact_graph(g)
    assert red["resources"][0]["attributes"]["note"] == REDACTED
    assert findings and findings[0]["reason"].startswith("secret-like value")


def test_findings_never_contain_the_secret():
    secret = "SuperSecretP@ssw0rd"
    g = _graph({"db_password": secret})
    _, findings = redact_graph(g)
    blob = str(findings)
    assert secret not in blob


def test_nested_and_list_redaction():
    g = _graph({"block": {"client_secret": "abc"}, "items": [{"token": "t"}]})
    red, _ = redact_graph(g)
    assert red["resources"][0]["attributes"]["block"]["client_secret"] == REDACTED
    assert red["resources"][0]["attributes"]["items"][0]["token"] == REDACTED
