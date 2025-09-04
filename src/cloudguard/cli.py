"""
CloudGuard – compliance-as-code scanner (MVP).
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

from . import __version__


# --------------------------- helpers / io ---------------------------------- #

def load_inventory(input_path: str | Path) -> Dict[str, Any]:
    """Load inventory JSON (UTF-8)."""
    path = Path(input_path)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


# ------------------------------- checks ------------------------------------ #

def check_s3_public_buckets(inv: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flag S3 buckets that are publicly accessible (returns list of dicts)."""
    buckets = inv.get("buckets") or inv.get("Buckets") or []
    out: List[Dict[str, Any]] = []
    for b in buckets:
        name = str(b.get("name") or b.get("Name") or "unknown")
        public = bool(b.get("public") or b.get("Public") or b.get("isPublic"))
        if public:
            out.append({
                "rule_id": "S3-PUBLIC-001",
                "severity": "HIGH",
                "resource": name,
                "message": f"Public bucket detected: {name}",
            })
    return out


def _stmt_has_wildcard_action(stmt: Dict[str, Any]) -> bool:
    """True if an IAM statement contains Action == * (or list with *)."""
    action = stmt.get("Action")
    if action == "*":
        return True
    if isinstance(action, list) and any(a == "*" for a in action):
        return True
    return False


def check_iam_wildcards(inv: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Flag IAM policies that allow wildcard actions.

    Accepts either of these shapes:
      {"iam_policies": [{"name": "...", "statements": [...] }]}
      {"policies": [{"name": "...", "document": {"Statement": [...]}}]}
    """
    policies = inv.get("iam_policies") or inv.get("policies") or []
    out: List[Dict[str, Any]] = []
    for p in policies:
        name = str(p.get("name", "policy"))
        stmts: Iterable[Dict[str, Any]] = (
            p.get("statements")
            or (p.get("document") or {}).get("Statement")
            or []
        )
        if any(_stmt_has_wildcard_action(s) for s in stmts):
            out.append({
                "rule_id": "IAM-WILDCARD-001",
                "severity": "HIGH",
                "resource": name,
                "message": "Policy allows wildcard actions",
            })
    return out


# ------------------------------- reports ----------------------------------- #

def _get(d: Any, key: str) -> Any:
    """dict-or-object accessor."""
    if isinstance(d, dict):
        return d.get(key)
    return getattr(d, key, None)


def render_html(findings: List[Dict[str, Any]], out_path: str | Path) -> None:
    """Write a tiny self-contained HTML report."""
    out = Path(out_path)
    rows = []
    for f in findings:
        rule_id = _get(f, "rule_id") or ""
        severity = _get(f, "severity") or ""
        resource = _get(f, "resource") or ""
        message = (
            _get(f, "message") or _get(f, "title") or _get(f, "details") or ""
        )
        rows.append(
            "<tr>"
            f"<td>{rule_id}</td>"
            f"<td>{severity}</td>"
            f"<td>{resource}</td>"
            f"<td>{message}</td>"
            "</tr>"
        )
    rows_html = "\n".join(rows)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    styles = (
        "body{font-family:system-ui;margin:24px}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #e5e7eb;padding:8px;text-align:left}"
        "th{background:#f3f4f6}"
        ".badge{display:inline-block;padding:2px 8px;"
        "border-radius:999px;background:#eef}"
    )

    html = (
        "<!doctype html>\n"
        "<html><head><meta charset=\"utf-8\">\n"
        "<title>CloudGuard Report</title>\n"
        f"<style>{styles}</style></head>\n"
        "<body>\n"
        "<h1>CloudGuard Report "
        f"<span class=\"badge\">v{__version__}</span></h1>\n"
        f"<p>Generated: {now}</p>\n"
        "<table>\n"
        "<thead><tr><th>Rule</th><th>Severity</th>"
        "<th>Resource</th><th>Message</th></tr></thead>\n"
        "<tbody>\n"
        f"{rows_html}\n"
        "</tbody>\n"
        "</table>\n"
        "</body></html>\n"
    )
    out.write_text(html, encoding="utf-8")


# ------------------------------- pipeline ---------------------------------- #

def scan(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Load inventory and run enabled checks."""
    inv = load_inventory(args.input)
    findings: List[Dict[str, Any]] = []
    if args.provider.lower() == "aws":
        findings.extend(check_s3_public_buckets(inv))
        findings.extend(check_iam_wildcards(inv))
    return findings


# --------------------------------- cli ------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudguard",
        description="CloudGuard – compliance-as-code scanner (MVP)",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"CloudGuard v{__version__}",
    )
    parser.add_argument(
        "--provider",
        required=True,
        choices=["aws"],
        help="Cloud provider to scan (MVP: aws).",
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to inventory JSON (e.g. sample_data/aws/*.json).",
    )
    parser.add_argument(
        "--policies",
        default="policies",
        help="Policies directory (reserved for future checks).",
    )
    parser.add_argument(
        "--report",
        choices=["html"],
        help="If set, writes a report in the chosen format.",
    )
    parser.add_argument(
        "--out",
        default="cloudguard_report.html",
        help="Output path when --report is provided.",
    )
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    findings = scan(args)

    if args.report == "html":
        render_html(findings, args.out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
