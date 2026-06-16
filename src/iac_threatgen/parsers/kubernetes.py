"""Kubernetes (YAML) parser → resource-graph fragments.

Handles multi-document YAML. Extracts security-relevant essentials (exposure, privileged
containers, host namespaces, hostPath mounts) and infers Service→workload edges via selectors.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_PUBLIC_SERVICE_TYPES = {"LoadBalancer", "NodePort"}


def _workload_pod_spec(doc: dict) -> dict | None:
    """Return the pod spec for workload kinds, else None."""
    kind = doc.get("kind")
    spec = doc.get("spec", {}) or {}
    if kind == "Pod":
        return spec
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}:
        return (spec.get("template", {}) or {}).get("spec", {}) or {}
    if kind == "CronJob":
        job = (spec.get("jobTemplate", {}) or {}).get("spec", {}) or {}
        return (job.get("template", {}) or {}).get("spec", {}) or {}
    return None


def _summarize_pod(pod_spec: dict) -> dict:
    containers = (pod_spec.get("containers", []) or []) + (
        pod_spec.get("initContainers", []) or []
    )
    privileged = False
    allow_priv_esc = False
    run_as_root = False
    images: list[str] = []
    for c in containers:
        if c.get("image"):
            images.append(c["image"])
        sc = c.get("securityContext", {}) or {}
        privileged = privileged or bool(sc.get("privileged"))
        allow_priv_esc = allow_priv_esc or bool(sc.get("allowPrivilegeEscalation"))
        if sc.get("runAsNonRoot") is False:
            run_as_root = True
    host_paths = [
        (v.get("hostPath") or {}).get("path")
        for v in (pod_spec.get("volumes", []) or [])
        if v.get("hostPath")
    ]
    return {
        "images": images,
        "privileged": privileged,
        "allowPrivilegeEscalation": allow_priv_esc,
        "hostNetwork": bool(pod_spec.get("hostNetwork")),
        "hostPID": bool(pod_spec.get("hostPID")),
        "hostIPC": bool(pod_spec.get("hostIPC")),
        "runAsRootPossible": run_as_root,
        "hostPaths": [p for p in host_paths if p],
    }


def _infer_exposure(doc: dict, summary: dict | None) -> str:
    if doc.get("kind") == "Service":
        if (doc.get("spec", {}) or {}).get("type") in _PUBLIC_SERVICE_TYPES:
            return "public"
        return "private"
    if doc.get("kind") == "Ingress":
        return "public"
    if summary and (summary["hostNetwork"] or summary["privileged"]):
        return "public"
    return "unknown"


def parse_text(text: str, source_file: str) -> tuple[list[dict], list[dict]]:
    """Parse one YAML file (possibly multi-doc). Returns (resources, edges)."""
    resources: list[dict] = []
    edges: list[dict] = []
    services: list[tuple[str, dict]] = []  # (id, selector)
    workloads: list[tuple[str, dict]] = []  # (id, labels)

    for doc in yaml.safe_load_all(text):
        if not isinstance(doc, dict) or "kind" not in doc:
            continue
        kind = doc["kind"]
        api = doc.get("apiVersion", "v1")
        meta = doc.get("metadata", {}) or {}
        name = meta.get("name", "<unnamed>")
        rid = f"{api}/{kind}/{name}"

        pod_spec = _workload_pod_spec(doc)
        summary = _summarize_pod(pod_spec) if pod_spec is not None else None
        attrs: dict = {"namespace": meta.get("namespace", "default")}
        if summary:
            attrs.update(summary)
        if kind == "Service":
            svc_spec = doc.get("spec", {}) or {}
            attrs["serviceType"] = svc_spec.get("type", "ClusterIP")
            attrs["ports"] = svc_spec.get("ports", [])
            services.append((rid, svc_spec.get("selector", {}) or {}))

        resources.append(
            {
                "id": rid,
                "type": f"{api}/{kind}",
                "provider": "kubernetes",
                "name": name,
                "kind": kind,
                "attributes": attrs,
                "exposure": _infer_exposure(doc, summary),
                "source_file": source_file,
            }
        )

        # collect workload labels for selector matching
        labels = (
            ((doc.get("spec", {}) or {}).get("template", {}) or {}).get("metadata", {}) or {}
        ).get("labels") or meta.get("labels") or {}
        if pod_spec is not None and labels:
            workloads.append((rid, labels))

    # Service -> workload edges via selector subset match.
    for svc_id, selector in services:
        if not selector:
            continue
        for wl_id, labels in workloads:
            if all(labels.get(k) == v for k, v in selector.items()):
                edges.append({"from": svc_id, "to": wl_id, "relation": "exposes"})

    return resources, edges


def parse_file(path: Path) -> tuple[list[dict], list[dict]]:
    text = path.read_text(encoding="utf-8")
    return parse_text(text, str(path))
