## Docker
Run the scanner in a container:
```
docker run --rm ghcr.io/dipesthapa/cloudguard:latest \
  scan --provider aws --input /data/iam_policies.json --policies /app/policies/aws
```

# CloudGuard — Compliance‑as‑Code scanner (MVP)

CloudGuard is a lightweight, open-source **Compliance‑as‑Code** scanner. The MVP runs locally and scans JSON inventory to flag common misconfigurations (starting with **AWS S3 public buckets**). It’s designed to expand into real cloud APIs and formal policy engines.

> Goal: provide a product‑led, public impact project suitable for Global Talent evidence (innovation + contribution), while being genuinely useful for UK SMEs/charities.

## Quick start

```bash
# 1) Create a virtual environment (optional but recommended)
python3 -m venv .venv && source .venv/bin/activate

# 2) Install dev tools (for lint/tests)
pip install -r requirements.txt

# 3) Run the sample scan (works offline on sample_data)
python -m src.cloudguard.cli scan --provider aws --input sample_data/aws/s3_buckets.json --policies policies/aws
```

Expected output (MVP):

```
[S3-PUBLIC-001] Public bucket detected: public-assets
1 finding(s) | exit code 1
```

The command exits **1** when any failing finding is detected (useful in CI).

## Features (MVP)
- Offline JSON scan (no credentials required)
- Rules: **S3 public bucket** and **IAM wildcard actions**
- HTML report output (`--report html`)
- Human‑readable findings + non‑zero exit on fail
- Linting and tests (flake8 + pytest), CI workflow included

## Roadmap
- [ ] Real AWS inventory via `boto3` (optional profile)
- [ ] Policy DSL or OPA/Rego integration
- [ ] JSON/SARIF reporting for CI systems
- [ ] More rules (SG `0.0.0.0/0`, RDS snapshots, KMS policies)

## Repository layout
```
src/cloudguard/        # package + CLI
policies/aws/          # YAML policies (MVP: S3 public)
sample_data/aws/       # example inventory to test offline
tests/                 # pytest tests
docs/                  # architecture, threat model
.github/workflows/     # CI (lint + tests + sample reports)
```

## Guides
- Secure by Default — CloudGuard for UK SMEs: docs/secure-by-default-uk-smes.md

## License
MIT — see [LICENSE](LICENSE).

## Security
Please see [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md). Be kind — we follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started
1. Clone this repo
2. Install and run checks: `make dev`
3. Generate sample reports: `make reports`


## Running Tests
- With Makefile: `make test`
- Manually:
  - `python3 -m venv .venv && source .venv/bin/activate`
  - `pip install -r requirements.txt`
  - `pytest -q`

## Project docs
- Architecture: `docs/architecture.md`
- Threat model: `docs/threat-model.md`
- Secure by Default for UK SMEs (draft): `docs/secure-by-default-uk-smes.md`
- Dev log: `docs/DEVLOG.md`

## Credibility & roadmap
- CI: GitHub Actions workflow runs lint and tests on pushes and PRs.
- Tests: See `tests/` for CLI, rules, and HTML report coverage.
- Changelog: See `CHANGELOG.md` for release notes.
