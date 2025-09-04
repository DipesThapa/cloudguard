import argparse
import json
import sys
from pathlib import Path


def load_inventory(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def check_s3_public_buckets(inventory: dict) -> list[dict]:
    findings = []
    for bucket in inventory.get("buckets", []):
        name = bucket.get("name")
        is_public = bool(bucket.get("public"))
        if is_public:
            findings.append(
                {
                    "rule_id": "S3-PUBLIC-001",
                    "severity": "HIGH",
                    "message": f"Public bucket detected: {name}",
                    "resource": name,
                }
            )
    return findings


def check_iam_wildcards(inventory: dict) -> list[dict]:
    """Flag IAM policies that contain '*' in Action or Resource."""
    findings = []
    for pol in inventory.get("iam_policies", []):
        name = pol.get("name", "<unknown>")
        for stmt in pol.get("statements", []):
            actions = stmt.get("Action") or stmt.get("Actions") or []
            resources = stmt.get("Resource") or stmt.get("Resources") or []
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            wild_action = any(a == "*" or "*" in a for a in actions)
            wild_res = any(r == "*" or "*" in r for r in resources)
            if wild_action or wild_res:
                findings.append(
                    {
                        "rule_id": "IAM-WILDCARD-001",
                        "severity": "HIGH",
                        "message": f"IAM wildcard detected in policy: {name}",
                        "resource": name,
                    }
                )
                break
    return findings


def render_html(findings: list[dict], out_path: Path) -> None:
    """Write a very simple HTML report."""
    rows = "\n".join(
        f"<tr><td>{f['severity']}</td><td>{f['rule_id']}</td>"
        f"<td>{f['resource']}</td><td>{f['message']}</td></tr>"
        for f in findings
    )
    html = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>CloudGuard Report</title>
<style>
body{{font-family:system-ui;margin:24px}} table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:8px}} th{{background:#f5f5f5;text-align:left}}
.sev-HIGH{{color:#a00;font-weight:600}}
</style></head><body>
<h2>CloudGuard Report</h2>
<p>Findings: {len(findings)}</p>
<table>
<thead><tr><th>Severity</th><th>Rule</th><th>Resource</th><th>Message</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body></html>"""
    Path(out_path).write_text(html)


def scan(provider: str, input_path: Path, policies_dir: Path) -> int:
    if provider != "aws":
        print(
            f"[!] Provider '{provider}' not yet supported in MVP",
            file=sys.stderr,
        )
        return 2

    inventory = load_inventory(input_path)
    findings = []
    findings.extend(check_s3_public_buckets(inventory))
    findings.extend(check_iam_wildcards(inventory))

    for f in findings:
        print(f"[{f['rule_id']}] {f['message']}")

    print(f"{len(findings)} finding(s) | exit code {1 if findings else 0}")
    return 1 if findings else 0


def main():
    parser = argparse.ArgumentParser(
        prog="cloudguard",
        description="Compliance-as-Code scanner (MVP)",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Run a scan")
    scan_p.add_argument("--provider", required=True, choices=["aws"])
    scan_p.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to JSON inventory (see sample_data/)",
    )
    scan_p.add_argument(
        "--policies",
        required=True,
        type=Path,
        help="Path to policies directory",
    )
    scan_p.add_argument(
        "--report",
        choices=["text", "html"],
        default="text",
        help="Output format for findings",
    )
    scan_p.add_argument(
        "--out",
        type=Path,
        default=Path("cloudguard_report.html"),
        help="Report path when using --report html",
    )

    args = parser.parse_args()
    if args.command == "scan":
        rc = scan(args.provider, args.input, args.policies)
        if args.report == "html":
            inv = load_inventory(args.input)
            f = []
            f.extend(check_s3_public_buckets(inv))
            f.extend(check_iam_wildcards(inv))
            render_html(f, args.out)
            print(f"HTML report written to {args.out}")
        sys.exit(rc)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
