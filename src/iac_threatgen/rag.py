"""Lexical RAG over the ATT&CK cloud corpus using BM25 (ADR-2, resolves R-02).

Deterministic, no network, no torch. The retrieved technique candidates form the *allowlist* the
threat mapper must choose from, and the groundedness validator checks membership against the same
corpus (FR-6, FR-17).
"""

from __future__ import annotations

import json
import os
import re
from importlib.resources import files
from pathlib import Path

from rank_bm25 import BM25Okapi


def data_dir() -> Path:
    """Package-bundled data dir (overridable via IAC_THREATGEN_DATA_DIR)."""
    override = os.getenv("IAC_THREATGEN_DATA_DIR")
    if override:
        return Path(override)
    return Path(str(files("iac_threatgen") / "data"))


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


class AttackIndex:
    """BM25 index over the ATT&CK corpus."""

    def __init__(self, corpus_path: Path | None = None):
        path = corpus_path or (data_dir() / "attack_cloud_corpus.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        self.techniques: list[dict] = data["techniques"]
        self.attack_version: str = data["metadata"]["attack_version"]
        self.valid_ids: set[str] = {t["technique_id"] for t in self.techniques}
        self._by_id = {t["technique_id"]: t for t in self.techniques}
        corpus_tokens = [
            _tokenize(
                f"{t['name']} {t['description']} "
                f"{' '.join(t.get('tactics', []))} {' '.join(t.get('platforms', []))}"
            )
            for t in self.techniques
        ]
        self._bm25 = BM25Okapi(corpus_tokens)

    def get(self, technique_id: str) -> dict | None:
        return self._by_id.get(technique_id)

    def retrieve(self, query: str, k: int = 5) -> list[dict]:
        scores = self._bm25.get_scores(_tokenize(query))
        ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        return [self.techniques[i] for i in ranked[:k] if scores[i] > 0]


def _resource_query(resource: dict) -> str:
    attrs = resource.get("attributes", {}) or {}
    signal_words = []
    for k, v in attrs.items():
        signal_words.append(str(k))
        if isinstance(v, bool) and v:
            signal_words.append(str(k))  # weight enabled boolean flags
    return " ".join(
        [
            resource.get("type", ""),
            resource.get("kind") or "",
            f"{resource.get('exposure', 'unknown')} exposure",
            *signal_words,
        ]
    )


def retrieve_for_graph(index: AttackIndex, graph: dict, k: int = 5) -> dict:
    """Return {resource_id: [technique, ...]} of candidate techniques per resource."""
    candidates: dict[str, list[dict]] = {}
    for res in graph.get("resources", []):
        candidates[res["id"]] = index.retrieve(_resource_query(res), k=k)
    return candidates
