# Architecture (MVP)

- **CLI** (`src/cloudguard/cli.py`) parses args and orchestrates a scan.
- **Inventory reader** loads JSON from `--input` (offline inventory for MVP).
- **Rules engine** iterates YAML policies under `--policies`.
- **Findings** printed to stdout; process exits **1** if any failed findings.

This modular layout allows swapping the inventory reader for live SDK calls.

See also
- Secure by Default guide for UK SMEs: ../docs/secure-by-default-uk-smes.md
