"""Command-line interface — the same core pipeline used by the GitHub Action (G7).

Usage:
    iac-threatgen scan <path> [--remediate] [--open-pr] [-o report.json] [--markdown report.md]

Exit codes: 0 ok · 2 setup (missing key/deps) · 3 failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .llm import LLMConfigError

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _render_markdown(report: dict) -> str:
    lines = ["# IaC ThreatGen Report", ""]
    lines.append(f"- **Generated:** {report['generated_at']}")
    lines.append(f"- **Model:** `{report['model']}`")
    s = report["input_summary"]
    lines.append(
        f"- **Resources:** {s['resource_count']} from {len(s['files'])} file(s); "
        f"{s.get('skipped_count', 0)} skipped"
    )
    lines += ["", "## Data-flow diagram", "", "```mermaid", report["dfd_mermaid"], "```", ""]

    lines += ["## STRIDE threats", "", "| ID | STRIDE | Severity | Resource | ATT&CK | Title |",
              "|----|--------|----------|----------|--------|-------|"]
    threats = sorted(report["threats"], key=lambda t: _SEV_ORDER.get(t.get("severity"), 9))
    for t in threats:
        attack = ", ".join(a["technique_id"] for a in t.get("attack", []))
        lines.append(
            f"| {t['id']} | {t['stride']} | {t['severity']} | `{t['resource_id']}` | "
            f"{attack} | {t['title']} |"
        )
    lines.append("")

    lines += ["## Details & mitigations", ""]
    for t in threats:
        lines.append(f"### {t['id']} — {t['title']} ({t['severity']})")
        lines.append(f"*{t['stride']} · resource `{t['resource_id']}`*")
        lines.append("")
        lines.append(t.get("description", ""))
        lines.append("")
        for a in t.get("attack", []):
            nm = a.get("technique_name", "")
            url = a.get("url", "")
            lines.append(f"- **ATT&CK [{a['technique_id']}]({url})** {nm}".rstrip())
        for m in t.get("mitigations", []):
            sub = m.get("csf_subcategory", "")
            lines.append(f"- **CSF {m['csf_function']} {sub}** — {m['recommendation']}")
        lines.append("")

    if report.get("_secret_findings"):
        lines += ["## Secrets detected (redacted before analysis)", ""]
        for f in report["_secret_findings"]:
            lines.append(f"- `{f['resource_id']}` attribute `{f['attribute']}` — {f['reason']}")
        lines.append("")
    if report.get("_warnings"):
        lines += ["## Warnings", ""] + [f"- {w}" for w in report["_warnings"]] + [""]
    return "\n".join(lines)


def _print_summary(report: dict) -> None:
    s = report["input_summary"]
    counts: dict[str, int] = {}
    for t in report["threats"]:
        counts[t["severity"]] = counts.get(t["severity"], 0) + 1
    order = ("critical", "high", "medium", "low")
    sev = ", ".join(f"{k}={counts[k]}" for k in order if k in counts)
    n = len(report["threats"])
    print(f"Resources analyzed: {s['resource_count']}  |  Threats: {n}  ({sev})")
    if report.get("_secret_findings"):
        print(f"Secrets redacted:   {len(report['_secret_findings'])}")
    for w in report.get("_warnings", []):
        print(f"  ! {w}")


def cmd_scan(args: argparse.Namespace) -> int:
    from .pipeline import run_pipeline

    report = run_pipeline(
        args.path,
        enable_remediation=args.remediate,
        open_pr=args.open_pr,
    )

    out = Path(args.output)
    public = {k: v for k, v in report.items() if not k.startswith("_")}
    out.write_text(json.dumps(public, indent=2), encoding="utf-8")
    print(f"Wrote report: {out}")

    if args.markdown:
        md = Path(args.markdown)
        md.write_text(_render_markdown(report), encoding="utf-8")
        print(f"Wrote markdown: {md}")

    _print_summary(report)
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ModuleNotFoundError:
        pass

    parser = argparse.ArgumentParser(prog="iac-threatgen", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan IaC and generate a threat report.")
    scan.add_argument("path", help="File or directory containing Terraform/Kubernetes IaC.")
    scan.add_argument(
        "--remediate", action="store_true", help="Generate secure-by-default Terraform."
    )
    scan.add_argument(
        "--open-pr", action="store_true", help="Open a GitHub PR with the remediation."
    )
    scan.add_argument("-o", "--output", default="threat_report.json", help="JSON output path.")
    scan.add_argument("--markdown", help="Also write a human-readable Markdown report here.")
    scan.set_defaults(func=cmd_scan)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except LLMConfigError as exc:
        print(f"SETUP: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"SETUP: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 — top-level CLI guard
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
