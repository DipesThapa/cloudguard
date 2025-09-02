# Threat Model (MVP)

**Assets**: User cloud inventory data; scan results.
**Actors**: Maintainer, contributors, end users.
**Assumptions**: MVP runs locally; no network calls by default.

**Risks**
- False positives/negatives in rules.
- Sensitive data stored in sample inputs (mitigate by using mocked data).

**Controls**
- Minimal dependencies, tests, Code of Conduct, SECURITY policy.
- No telemetry in MVP.
