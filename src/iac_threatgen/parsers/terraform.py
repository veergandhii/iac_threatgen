"""Terraform (HCL) parser → resource-graph fragments.

Uses python-hcl2 to load HCL into a dict. Terraform interpolations (``${...}``) are kept as
opaque strings — we never resolve or execute them (untrusted input). Edges are inferred
heuristically from references between resources.
"""

from __future__ import annotations

import re
from pathlib import Path

import hcl2

# Substrings that signal public exposure when found in an attribute value.
_PUBLIC_SIGNALS = ("0.0.0.0/0", "::/0", "public-read", "public-read-write")
# Reference pattern: aws_s3_bucket.data  (type.name[.attr])
_REF = re.compile(r"\b([a-z][a-z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_-]*)")
# Resource address that is a real resource type (has a provider_resource form).
_RES_TYPE = re.compile(r"^[a-z][a-z0-9]*_[a-z0-9_]+$")


def _stringify(value) -> str:
    """Flatten any attribute value to a searchable string."""
    if isinstance(value, dict):
        return " ".join(_stringify(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_stringify(v) for v in value)
    return str(value)


def _infer_exposure(attrs: dict) -> str:
    blob = _stringify(attrs).lower()
    if any(sig in blob for sig in _PUBLIC_SIGNALS):
        return "public"
    if "publicly_accessible" in attrs and _stringify(attrs.get("publicly_accessible")).lower() in (
        "true",
        "1",
    ):
        return "public"
    if _stringify(attrs.get("associate_public_ip_address", "")).lower() == "true":
        return "public"
    return "unknown"


def _find_line(text: str, rtype: str, rname: str) -> list[int] | None:
    pat = re.compile(rf'resource\s+"{re.escape(rtype)}"\s+"{re.escape(rname)}"')
    for i, line in enumerate(text.splitlines(), start=1):
        if pat.search(line):
            return [i]
    return None


def _references(attrs: dict, own_id: str) -> list[str]:
    """Return resource ids referenced inside this resource's attributes."""
    blob = _stringify(attrs)
    refs: set[str] = set()
    for m in _REF.findall(blob):
        rtype = m.split(".")[0]
        if _RES_TYPE.match(rtype) and m != own_id:
            refs.add(m)
    return sorted(refs)


def parse_text(text: str, source_file: str) -> tuple[list[dict], list[dict]]:
    """Parse one HCL document. Returns (resources, edges). Raises on invalid HCL."""
    data = hcl2.loads(text)
    resources: list[dict] = []
    edges: list[dict] = []
    seen_ids: set[str] = set()

    for block in data.get("resource", []):
        # block = { "aws_s3_bucket": { "data": {<attrs>} } }
        # python-hcl2 v8 keeps surrounding quotes on block keys — strip them.
        for rtype_raw, named in block.items():
            rtype = rtype_raw.strip('"')
            for rname_raw, attrs in named.items():
                rname = rname_raw.strip('"')
                if not isinstance(attrs, dict):
                    attrs = {}
                rid = f"{rtype}.{rname}"
                seen_ids.add(rid)
                resources.append(
                    {
                        "id": rid,
                        "type": rtype,
                        "provider": "terraform",
                        "name": rname,
                        "kind": None,
                        "attributes": attrs,
                        "exposure": _infer_exposure(attrs),
                        "source_file": source_file,
                        **({"source_lines": ln} if (ln := _find_line(text, rtype, rname)) else {}),
                    }
                )

    # Build edges after all ids are known so we only link to real resources in this doc.
    for res in resources:
        for ref in _references(res["attributes"], res["id"]):
            # ref may include an attribute suffix (aws_x.y.attr) -> trim to type.name
            parts = ref.split(".")
            target = ".".join(parts[:2])
            if target in seen_ids and target != res["id"]:
                edges.append({"from": res["id"], "to": target, "relation": "references"})
        # explicit depends_on
        for dep in res["attributes"].get("depends_on", []) or []:
            parts = _stringify(dep).split(".")
            target = ".".join(parts[:2])
            if target in seen_ids and target != res["id"]:
                edges.append({"from": res["id"], "to": target, "relation": "depends_on"})

    return resources, edges


def parse_file(path: Path) -> tuple[list[dict], list[dict]]:
    text = path.read_text(encoding="utf-8")
    return parse_text(text, str(path))
