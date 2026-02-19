# Architecture

This document describes the enterprise-ready architecture for MVP implementation. Authoritative formulas, enums, and schemas remain in:
- `docs/md/core-decision-engine.md`
- `docs/md/policy-format.md`

## High-Level Diagram

```text
+-----------------------------------------------+
| Local Scanner Outputs                          |
| (scan JSON + optional baseline-scan JSON)      |
+-------------------------+---------------------+
                         |
                         v
+--------------------------+      +--------------------------------------+
| Ingest + Hash            |<-----| context.yaml (untrusted)             |
| - read files             |      | or deterministic CI env auto-context |
| - SHA-256                |      +--------------------------------------+
+------------+-------------+
             |
             v
+--------------------------+      +---------------------------+
| Normalize                |<-----| policy.yaml (untrusted)  |
| -> UnifiedFinding        |      +---------------------------+
+------------+-------------+
             |
             v
+--------------------------+      +---------------------------+
| Governance               |<-----| accepted-risk.yaml        |
| - validate exceptions    |      | (optional, untrusted)     |
| - expiry/approval checks |      +---------------------------+
+------------+-------------+
             |
             v
+--------------------------+
| Score + Trust + Policy   |
| deterministic engine     |
+------------+-------------+
             |
             v
+--------------------------+
| Decision Trace + Report  |
| report.json + report.html|
| checksums + run log      |
| exit code 0/1/2          |
+--------------------------+
```

## Module Boundaries

Reference detailed interfaces in `docs/md/modules.md`.

Boundary goals:
- adapters isolated from core engine
- pure deterministic core logic
- output rendering isolated from decision contract
- governance controls separate from scoring

## Data Flow

1. Input acquisition:
- One or more scanner JSON files by local path
- Optional baseline scanner JSON files by local path (new-findings-only mode)
- Context by either:
  - YAML local path (strict schema)
  - deterministic CI environment auto-detection mode
- Policy YAML by local path (strict schema)
- Accepted Risk YAML optional by local path (strict schema)

2. Input integrity:
- SHA-256 hash each input file
- Record hash and read status in decision trace/report
- Reject unknown/duplicate YAML keys and missing required YAML fields with line-aware diagnostics

3. Normalization:
- Parse scanner-specific records into `UnifiedFinding` via deterministic adapters
- Current adapters: Trivy JSON, SARIF 2.1.0 JSON, Snyk vulnerability JSON, Checkmarx JSON v2, Sonar Generic Issues JSON
- Fill missing values with canonical `unknown`

4. Governance pass:
- Validate Accepted Risk records
- Evaluate scope/expiry/approval requirements

5. Decision engine pass (authoritative precedence):
- hard-stop
- accepted risk application
- scoring/trust
- noise budget (presentation-only)
- stage matrix
- exit mapping

6. Output:
- authoritative `report.json`
- derived `report.html`
- `checksums.sha256` for generated report artifacts
- structured JSON-lines `security-gate.run.log`
- process exit code

## Deterministic vs AI Boundary

Deterministic boundary (authoritative):
- parse/validate/hash
- normalization
- trust + risk computation
- decision and exit code
- decision trace and recommended step IDs

AI boundary (non-authoritative, optional):
- plain-language elaboration of predefined next steps
- must be clearly marked and separately stored in `non_authoritative`
- cannot alter decision fields, thresholds, or actions

## Failure Modes

Authoritative behavior in `core-decision-engine`.

Summary:
- `release`/`deploy`: fail-closed to `BLOCK` on parse/schema/hash/governance failures.
- `pr`/`merge`: fail-open-to-`WARN` with minimal deterministic report; never `ALLOW` on validation failure.

## Trust and Provenance Flow

Trust inputs originate from context and scanner metadata:
- scanner name/version and freshness
- artifact signing state
- provenance level
- build context completeness

Flow:
- each trust signal -> deterministic penalty
- penalties -> `TrustScore`
- trust band -> risk penalty and/or policy tightening
- low trust can directly elevate decisions in stricter stages

## Security Architecture Notes

- Input parser is a security boundary.
- No dynamic code execution from scanner content.
- No shell interpolation from parsed fields.
- Strict schema validation before scoring.
- Local-only mode prevents outbound data movement.

## Extensibility

MVP-compatible extension points:
- additional ingest adapters (`ingest/<scanner>`)
- policy pack composition (local includes, deterministic merge order)
- additional hard-stop domains via policy (cannot remove canonical list)
- additional report renderers derived from `report.json`

Non-goals for MVP:
- remote policy fetch
- cloud services
- CI platform API calls
- webhook integrations

## Acceptance Criteria Checklist

- [ ] High-level architecture diagram is present.
- [ ] Data flow from untrusted inputs to outputs is explicit.
- [ ] Deterministic and AI boundaries are clearly separated.
- [ ] Failure mode strategy per stage class is documented.
- [ ] Trust/provenance flow is defined.
- [ ] Module boundary and extensibility guidance is included.
- [ ] No-network and offline operation are explicit.
