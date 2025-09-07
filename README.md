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
- One policy: **S3 public bucket** detection
- Human‑readable output + non‑zero exit on fail
- Ready for CI (flake8 + pytest)

## Roadmap
- [ ] Real AWS inventory via `boto3` (optional profile)
- [ ] Policy DSL or OPA/Rego integration
- [ ] HTML/JSON/SARIF reporting
- [ ] More rules (IAM `*`, SG `0.0.0.0/0`, RDS snapshots)

## Repository layout
```
src/cloudguard/        # package + CLI
policies/aws/          # YAML policies (MVP: S3 public)
sample_data/aws/       # example inventory to test offline
tests/                 # pytest tests
docs/                  # architecture, threat model
.github/workflows/     # CI
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
2. Run `make install`
3. Start with `make dev`


## Running Tests


