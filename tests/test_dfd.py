"""DFD builder tests (G5/FR-8)."""

from __future__ import annotations

from iac_threatgen.dfd import build_dfd


def test_dfd_structure_and_public_highlight():
    graph = {
        "resources": [
            {"id": "a", "type": "aws_s3_bucket", "name": "a", "exposure": "public"},
            {"id": "b", "type": "aws_instance", "name": "b", "exposure": "unknown"},
        ],
        "edges": [{"from": "b", "to": "a", "relation": "references"}],
    }
    dfd = build_dfd(graph)
    assert dfd.startswith("flowchart LR")
    assert "internet([Internet])" in dfd
    assert "internet --> n0" in dfd  # public node linked from Internet
    assert "-->|references|" in dfd
    assert "class n0 public;" in dfd  # public node highlighted


def test_dfd_handles_empty_graph():
    dfd = build_dfd({"resources": [], "edges": []})
    assert dfd.startswith("flowchart LR")
