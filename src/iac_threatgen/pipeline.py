"""LangGraph pipeline wiring + run_pipeline() — the shared core for CLI and GitHub Action.

Deterministic nodes do parsing, redaction, retrieval, DFD, validation, terraform-validate, and PR
creation; two LLM nodes do threat mapping and remediation. Two bounded retry loops (groundedness,
terraform-validate) keep output valid without infinite cycles (ADR-7).
"""

from __future__ import annotations

import datetime as _dt

from langgraph.graph import END, START, StateGraph

from . import constants, dfd, github_pr, remediation, secrets_scan, threats, validation
from .parsers import parse_iac
from .rag import AttackIndex, retrieve_for_graph
from .state import PipelineState

_index: AttackIndex | None = None


def _get_index() -> AttackIndex:
    global _index
    if _index is None:
        _index = AttackIndex()
    return _index


def _merge_usage(a: dict, b: dict) -> dict:
    return {
        "input_tokens": a.get("input_tokens", 0) + b.get("input_tokens", 0),
        "output_tokens": a.get("output_tokens", 0) + b.get("output_tokens", 0),
    }


# --------------------------------------------------------------------------- nodes


def n_parse(state: PipelineState) -> dict:
    graph = parse_iac(state.input_path)
    warnings = [f"skipped {s['path']}: {s['reason']}" for s in graph["source"].get("skipped", [])]
    return {"resource_graph": graph, "warnings": state.warnings + warnings}


def n_redact(state: PipelineState) -> dict:
    redacted, findings = secrets_scan.redact_graph(state.resource_graph)
    return {"resource_graph": redacted, "secret_findings": findings}


def n_retrieve(state: PipelineState) -> dict:
    candidates = retrieve_for_graph(_get_index(), state.resource_graph)
    return {"attack_candidates": candidates}


def n_map(state: PipelineState) -> dict:
    _, csf_subs = validation.load_csf()
    feedback = "\n".join(state.ground_feedback) if state.ground_feedback else None
    result, usage = threats.map_threats(
        state.resource_graph,
        state.attack_candidates,
        sorted(csf_subs),
        _get_index(),
        feedback=feedback,
    )
    return {"threats": result, "usage": _merge_usage(state.usage, usage)}


def n_validate_ground(state: PipelineState) -> dict:
    idx = _get_index()
    errors = validation.check_groundedness(state.threats, state.resource_graph, idx)
    if errors and state.ground_retries < state.max_ground_retries:
        return {"ground_feedback": errors, "ground_retries": state.ground_retries + 1}
    if errors:
        # Out of retries: drop only the ungrounded threats so the report stays valid + honest.
        valid = [
            th
            for th in state.threats
            if not validation.check_groundedness([th], state.resource_graph, idx)
        ]
        dropped = len(state.threats) - len(valid)
        warn = state.warnings + [f"dropped {dropped} ungrounded threat(s) after retries"]
        return {"threats": valid, "ground_feedback": [], "warnings": warn}
    return {"ground_feedback": []}


def n_build_dfd(state: PipelineState) -> dict:
    return {"dfd_mermaid": dfd.build_dfd(state.resource_graph)}


def n_remediate(state: PipelineState) -> dict:
    rem, usage = remediation.generate_remediation(state.resource_graph, state.threats)
    if state.tf_feedback:
        rem["_retry_note"] = "regenerated after terraform validate failure"
    return {"remediation": rem, "usage": _merge_usage(state.usage, usage), "tf_feedback": None}


def n_tf_validate(state: PipelineState) -> dict:
    files = (state.remediation or {}).get("files", [])
    passed, output = remediation.terraform_validate(files)
    rem = dict(state.remediation or {})
    if passed is False and state.tf_retries < state.max_tf_retries:
        return {"tf_retries": state.tf_retries + 1, "tf_feedback": output}
    rem["terraform_validate_passed"] = bool(passed)
    warnings = list(state.warnings)
    if passed is None:
        warnings.append("terraform binary not found — validation skipped (FR-11 gate deferred)")
    elif passed is False:
        warnings.append("terraform validate failed after retries; PR not opened")
    return {"remediation": rem, "tf_feedback": None, "warnings": warnings}


def n_open_pr(state: PipelineState) -> dict:
    rem = dict(state.remediation or {})
    files = rem.get("files", [])
    if not state.open_pr or not files or rem.get("terraform_validate_passed") is False:
        return {}
    title = "threatgen: secure-by-default remediations"
    body = rem.get("summary", "Automated security remediations proposed by IaC ThreatGen.")
    branch = "threatgen/remediation-" + _dt.datetime.now(_dt.UTC).strftime("%Y%m%d%H%M%S")
    try:
        pr = github_pr.open_pull_request(files, title=title, body=body, branch=branch)
        rem["pr"] = pr
        return {"remediation": rem}
    except Exception as exc:  # noqa: BLE001 — PR failures must not crash the run
        return {"warnings": state.warnings + [f"PR not opened: {type(exc).__name__}: {exc}"]}


# --------------------------------------------------------------------------- routers


def _route_ground(state: PipelineState) -> str:
    return "retry" if state.ground_feedback else "ok"


def _route_remediation(state: PipelineState) -> str:
    return "remediate" if state.enable_remediation else "skip"


def _route_tf(state: PipelineState) -> str:
    return "retry" if state.tf_feedback else "open_pr"


# --------------------------------------------------------------------------- graph


def build_graph():
    g = StateGraph(PipelineState)
    g.add_node("parse", n_parse)
    g.add_node("redact", n_redact)
    g.add_node("retrieve", n_retrieve)
    g.add_node("map", n_map)
    g.add_node("validate_ground", n_validate_ground)
    g.add_node("build_dfd", n_build_dfd)
    g.add_node("remediate", n_remediate)
    g.add_node("tf_validate", n_tf_validate)
    g.add_node("open_pr", n_open_pr)

    g.add_edge(START, "parse")
    g.add_edge("parse", "redact")
    g.add_edge("redact", "retrieve")
    g.add_edge("retrieve", "map")
    g.add_edge("map", "validate_ground")
    g.add_conditional_edges("validate_ground", _route_ground, {"retry": "map", "ok": "build_dfd"})
    g.add_conditional_edges(
        "build_dfd", _route_remediation, {"remediate": "remediate", "skip": END}
    )
    g.add_edge("remediate", "tf_validate")
    g.add_conditional_edges("tf_validate", _route_tf, {"retry": "remediate", "open_pr": "open_pr"})
    g.add_edge("open_pr", END)
    return g.compile()


def _build_report(final: dict) -> dict:
    graph = final.get("resource_graph") or {}
    rem = final.get("remediation")
    remediation_pr = None
    if rem:
        remediation_pr = {
            "branch": (rem.get("pr") or {}).get("branch", ""),
            "title": (rem.get("pr") or {}).get("title", ""),
            "body": rem.get("summary", ""),
            "files_changed": [f["path"] for f in rem.get("files", [])],
            "terraform_validate_passed": bool(rem.get("terraform_validate_passed")),
        }
    return {
        "schema_version": "1.0",
        "generated_at": _dt.datetime.now(_dt.UTC).isoformat(),
        "model": constants.MODEL,
        "input_summary": {
            "resource_count": len(graph.get("resources", [])),
            "files": graph.get("source", {}).get("files", []),
            "skipped_count": len(graph.get("source", {}).get("skipped", [])),
        },
        "dfd_mermaid": final.get("dfd_mermaid") or "flowchart LR\n    empty([no resources])",
        "threats": final.get("threats", []),
        "remediation_pr": remediation_pr,
        "usage": final.get("usage") or None,
        "_warnings": final.get("warnings", []),
        "_secret_findings": final.get("secret_findings", []),
    }


def run_pipeline(
    input_path: str,
    *,
    enable_remediation: bool = False,
    open_pr: bool = False,
) -> dict:
    """Run the full pipeline and return a schema-valid threat report (plus _warnings meta)."""
    app = build_graph()
    final = app.invoke(
        PipelineState(
            input_path=input_path,
            enable_remediation=enable_remediation,
            open_pr=open_pr,
        )
    )
    if not isinstance(final, dict):  # langgraph returns the channel dict; be defensive
        final = dict(final)
    report = _build_report(final)
    # Validate the public part of the report against the frozen schema (FR-9).
    public = {k: v for k, v in report.items() if not k.startswith("_")}
    validation.validate_report(public)
    return report
