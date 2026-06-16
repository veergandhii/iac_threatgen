"""Shared LangGraph pipeline state (typed with pydantic)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PipelineState(BaseModel):
    """State passed between LangGraph nodes. Nodes return partial dicts that get merged in."""

    # --- inputs / config ---
    input_path: str
    enable_remediation: bool = False
    open_pr: bool = False
    max_ground_retries: int = 2
    max_tf_retries: int = 2

    # --- working data ---
    resource_graph: dict | None = None  # conforms to schemas/resource_graph.schema.json
    secret_findings: list[dict] = Field(default_factory=list)
    attack_candidates: dict = Field(default_factory=dict)  # query_key -> [techniques]
    threats: list[dict] = Field(default_factory=list)
    dfd_mermaid: str | None = None
    remediation: dict | None = None

    # --- control / observability ---
    warnings: list[str] = Field(default_factory=list)
    ground_retries: int = 0
    tf_retries: int = 0
    ground_feedback: list[str] = Field(default_factory=list)  # retry hints for map_threats
    tf_feedback: str | None = None  # retry hint for remediate
    usage: dict = Field(default_factory=dict)  # {input_tokens, output_tokens}
