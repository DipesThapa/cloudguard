import argparse
import json
import sys
from pathlib import Path

def load_inventory(path: Path) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def check_s3_public_buckets(inventory: dict) -> list[dict]:
    findings = []
    for bucket in inventory.get("buckets", []):
        name = bucket.get("name")
        is_public = bool(bucket.get("public"))
        if is_public:
            findings.append({
                "rule_id": "S3-PUBLIC-001",
                "severity": "HIGH",
                "message": f"Public bucket detected: {name}",
                "resource": name,
            })
    return findings

def scan(provider: str, input_path: Path, policies_dir: Path) -> int:
    if provider != "aws":
        print(f"[!] Provider '{provider}' not yet supported in MVP", file=sys.stderr)
        return 2

    inventory = load_inventory(input_path)
    findings = check_s3_public_buckets(inventory)

    for f in findings:
        print(f"[{f['rule_id']}] {f['message']}")

    print(f"{len(findings)} finding(s) | exit code {1 if findings else 0}")
    return 1 if findings else 0

def main():
    parser = argparse.ArgumentParser(prog="cloudguard", description="Compliance-as-Code scanner (MVP)")
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Run a scan")
    scan_p.add_argument("--provider", required=True, choices=["aws"])
    scan_p.add_argument("--input", required=True, type=Path, help="Path to JSON inventory (see sample_data/)")
    scan_p.add_argument("--policies", required=True, type=Path, help="Path to policies directory")

    args = parser.parse_args()
    if args.command == "scan":
        rc = scan(args.provider, args.input, args.policies)
        sys.exit(rc)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
