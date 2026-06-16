"""Secret detection + redaction for the resource graph (FR-15, R-05).

Runs BEFORE any model call. Secret-looking attribute values are replaced with a placeholder so
they never reach the LLM, the report, or a PR. Findings record *where* a secret was (resource +
attribute) but never the secret value itself.
"""

from __future__ import annotations

import re

REDACTED = "***REDACTED***"

# Attribute names whose values are treated as secrets regardless of content.
_SECRET_NAME = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|"
    r"private[_-]?key|client[_-]?secret|credential)",
    re.IGNORECASE,
)

# Value patterns that look like secrets even under an innocuous key name.
_VALUE_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),  # PEM private key
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]


def _looks_secret_value(value: str) -> bool:
    return any(p.search(value) for p in _VALUE_PATTERNS)


def _redact_attrs(attrs: dict, resource_id: str, findings: list[dict]) -> dict:
    out: dict = {}
    for key, value in attrs.items():
        if isinstance(value, dict):
            out[key] = _redact_attrs(value, resource_id, findings)
        elif isinstance(value, list):
            out[key] = [
                _redact_attrs(v, resource_id, findings)
                if isinstance(v, dict)
                else _redact_scalar(key, v, resource_id, findings)
                for v in value
            ]
        else:
            out[key] = _redact_scalar(key, value, resource_id, findings)
    return out


def _redact_scalar(key: str, value, resource_id: str, findings: list[dict]):
    if not isinstance(value, str):
        return value
    by_name = bool(_SECRET_NAME.search(key))
    by_value = _looks_secret_value(value)
    if by_name or by_value:
        findings.append(
            {
                "resource_id": resource_id,
                "attribute": key,
                "reason": "secret-like attribute name" if by_name else "secret-like value pattern",
            }
        )
        return REDACTED
    return value


def redact_graph(graph: dict) -> tuple[dict, list[dict]]:
    """Return (redacted_graph, findings). The input graph is not mutated."""
    findings: list[dict] = []
    redacted = dict(graph)
    redacted["resources"] = []
    for res in graph.get("resources", []):
        r = dict(res)
        r["attributes"] = _redact_attrs(res.get("attributes", {}) or {}, res["id"], findings)
        redacted["resources"].append(r)
    return redacted, findings
