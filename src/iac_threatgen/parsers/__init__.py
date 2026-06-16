"""IaC parsing entry point: walk a path, parse Terraform + Kubernetes, build the resource graph.

Produces a dict conforming to schemas/resource_graph.schema.json. Unparseable or unknown files
degrade gracefully — they are skipped and recorded, never crashing the run (FR-4).
"""

from __future__ import annotations

from pathlib import Path

from . import kubernetes, terraform

TF_SUFFIXES = {".tf"}
K8S_SUFFIXES = {".yaml", ".yml"}
MAX_FILE_BYTES = 1 * 1024 * 1024  # 1 MiB soft cap (input contract)


def _classify(path: Path) -> str | None:
    name = path.name.lower()
    if name.endswith(".tf"):
        return "terraform"
    if path.suffix.lower() in K8S_SUFFIXES:
        return "kubernetes"
    return None


def _iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_file():
            yield p


def parse_iac(input_path: str) -> dict:
    """Parse all IaC under ``input_path`` (file or directory) into the resource graph."""
    root = Path(input_path)
    if not root.exists():
        raise FileNotFoundError(f"Input path does not exist: {input_path}")

    resources: list[dict] = []
    edges: list[dict] = []
    parsed_files: list[str] = []
    skipped: list[dict] = []
    kinds: set[str] = set()

    for path in _iter_files(root):
        kind = _classify(path)
        if kind is None:
            continue  # not IaC; silently ignore non-IaC files
        rel = str(path)
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped.append({"path": rel, "reason": "exceeds 1 MiB soft cap"})
                continue
            if kind == "terraform":
                res, edg = terraform.parse_file(path)
            else:
                res, edg = kubernetes.parse_file(path)
            if not res:
                # Parsed fine but nothing recognized (e.g. a non-K8s yaml). Skip quietly.
                if kind == "kubernetes":
                    continue
            resources.extend(res)
            edges.extend(edg)
            if res:
                parsed_files.append(rel)
                kinds.add(kind)
        except Exception as exc:  # noqa: BLE001 — graceful degradation is the requirement
            skipped.append({"path": rel, "reason": f"{type(exc).__name__}: {exc}"})

    source_type = "mixed" if len(kinds) > 1 else (next(iter(kinds), "terraform"))
    return {
        "schema_version": "1.0",
        "source": {"type": source_type, "files": parsed_files, "skipped": skipped},
        "resources": resources,
        "edges": edges,
    }
