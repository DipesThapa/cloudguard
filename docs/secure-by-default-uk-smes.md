# Secure by Default — CloudGuard for UK SMEs (Draft)

Status: draft

Purpose
- Help UK SMEs adopt a “secure by default” posture using CloudGuard.
- Provide pragmatic steps, examples, and CI integration guidance.

Audience
- Tech‑savvy SMEs (founders, platform engineers, dev leads) managing AWS.

Outcomes
- Run CloudGuard locally and in CI.
- Understand common misconfigurations and suggested remediations.

Quick Start
- Requirements: Python 3.10+, repo checkout, internet for GitHub Actions.
- Local scan examples:

```bash
# From repo root
python3 src/cloudguard/cli.py --provider aws --input sample_data/aws/s3_buckets.json \
  --report html --out reports/sample_s3.html

python3 src/cloudguard/cli.py --provider aws --input sample_data/aws/iam_policies.json \
  --report html --out reports/sample_iam.html
```

Common Risks (Initial Rules)
- Public S3 buckets: Flags buckets exposed to the internet.
- IAM wildcard actions: Flags policies with `Action: "*"`.

How Findings Are Reported
- HTML report with rule ID, severity, resource, and message.
- Example rule IDs: `S3-PUBLIC-001`, `IAM-WILDCARD-001`.

Remediation Playbook (High Level)
- S3 Public Buckets
  - Disable public access unless there’s a strict business need.
  - Use block public access at account and bucket levels.
  - Restrict bucket policies to specific principals and actions.
- IAM Wildcards
  - Replace `Action: "*"` with least‑privilege actions.
  - Scope `Resource` when possible; avoid `Resource: "*"` for write/delete.

CI Integration (GitHub Actions)
- Add or extend a workflow to lint, run CloudGuard, and attach reports.

```yaml
name: security-scan
on:
  pull_request:
  push:
    branches: [ main ]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install
        run: |
          python -m pip install -r requirements.txt
      - name: CloudGuard scan (sample data)
        run: |
          python src/cloudguard/cli.py --provider aws \
            --input sample_data/aws/s3_buckets.json \
            --report html --out reports/cg_s3.html
      - name: Upload report artifact
        uses: actions/upload-artifact@v4
        with:
          name: cloudguard-report
          path: reports/cg_s3.html
```

Operational Tips
- Keep reports out of Git history; store as CI artifacts.
- Consider a `--fail-on-findings` gate for CI when your org is ready.
- Track exceptions with time‑boxed approvals.

Roadmap (Next Iterations)
- Add Azure/GCP providers.
- Expand rule set (e.g., public EC2 SGs, KMS key policies, MFA checks).
- JSON report output for machine parsing.

Acceptance Checklist (for this guide)
- [ ] Contains runnable quick‑start commands.
- [ ] Shows CI integration example.
- [ ] Links added from README (follow‑up PR).

