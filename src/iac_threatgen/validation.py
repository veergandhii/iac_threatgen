"""Groundedness + schema validation.

Groundedness (FR-17): reject threats that reference non-existent resources, invalid STRIDE
categories, hallucinated ATT&CK IDs, or CSF subcategories outside the controlled list. Returns a
list of human-readable errors used as retry feedback for the threat mapper.

Schema validation (FR-9): validate the final report against schemas/threat_report.schema.json.
"""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

import jsonschema

from .rag import AttackIndex, data_dir

_SCHEMA_DIR = Path(str(files("iac_threatgen") / "schemas"))
_STRIDE = {
    "Spoofing",
    "Tampering",
    "Repudiation",
    "InformationDisclosure",
    "DenialOfService",
    "ElevationOfPrivilege",
}


def load_csf() -> tuple[set[str], set[str]]:
    data = json.loads((data_dir() / "nist_csf_subcategories.json").read_text(encoding="utf-8"))
    return set(data["functions"].keys()), set(data["subcategories"])


def check_groundedness(threats: list[dict], graph: dict, index: AttackIndex) -> list[str]:
    """Return a list of groundedness errors. Empty list == passed."""
    errors: list[str] = []
    resource_ids = {r["id"] for r in graph.get("resources", [])}
    csf_functions, csf_subs = load_csf()

    if not threats:
        return ["No threats were produced."]

    for th in threats:
        tid = th.get("id", "<no-id>")
        if th.get("resource_id") not in resource_ids:
            errors.append(f"{tid}: resource_id '{th.get('resource_id')}' is not in the graph.")
        if th.get("stride") not in _STRIDE:
            errors.append(f"{tid}: invalid STRIDE category '{th.get('stride')}'.")
        attack = th.get("attack") or []
        if not attack:
            errors.append(f"{tid}: must cite at least one ATT&CK technique.")
        for tech in attack:
            if tech.get("technique_id") not in index.valid_ids:
                errors.append(
                    f"{tid}: ATT&CK id '{tech.get('technique_id')}' is not in the corpus."
                )
        mitigations = th.get("mitigations") or []
        if not mitigations:
            errors.append(f"{tid}: must include at least one mitigation.")
        for m in mitigations:
            if m.get("csf_function") not in csf_functions:
                errors.append(f"{tid}: invalid CSF function '{m.get('csf_function')}'.")
            sub = m.get("csf_subcategory")
            if sub is not None and sub not in csf_subs:
                errors.append(f"{tid}: CSF subcategory '{sub}' is not in the controlled list.")
    return errors


def _load_schema(name: str) -> dict:
    return json.loads((_SCHEMA_DIR / name).read_text(encoding="utf-8"))


def validate_graph(graph: dict) -> None:
    jsonschema.validate(graph, _load_schema("resource_graph.schema.json"))


def validate_report(report: dict) -> None:
    jsonschema.validate(report, _load_schema("threat_report.schema.json"))
