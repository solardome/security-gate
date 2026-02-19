# security-gate

`security-gate` is a local, privacy-first DevSecOps gate that converts scanner outputs into deterministic CI/CD decisions: `ALLOW`, `WARN`, or `BLOCK`.

## Table of Contents

- [Why security-gate](#why-security-gate)
- [Project Status](#project-status)
- [Key Features](#key-features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Run Examples](#run-examples)
- [CLI Usage](#cli-usage)
- [Baseline Diff Mode](#baseline-diff-mode)
- [CI Auto-Context](#ci-auto-context)
- [Decision Contract](#decision-contract)
- [Input Contracts](#input-contracts)
- [Output Artifacts](#output-artifacts)
- [Architecture and Authority Docs](#architecture-and-authority-docs)
- [Repository Layout](#repository-layout)
- [Development and Validation](#development-and-validation)
- [Contributing](#contributing)
- [Security](#security)
- [Roadmap](#roadmap)
- [License](#license)

## Why security-gate

Scanners produce findings; release pipelines need deterministic decisions.

`security-gate` adds context-aware, policy-driven gating on top of scanner reports while keeping the system:

- Local only (no cloud calls, no external APIs)
- Deterministic (same normalized inputs -> same decision and trace)
- Explainable (`report.json` includes decision trace)
- Strict about untrusted input validation

## Project Status

Active development. Core contracts are implemented and validated by unit tests, race tests, and simulation scenarios.

## Key Features

- Deterministic decision engine with canonical outcomes: `ALLOW`, `WARN`, `BLOCK`
- Canonical exit-code contract: `0`, `1`, `2`
- Strict precedence:
  1. hard-stop domains
  2. accepted-risk governance
  3. numeric scoring
  4. noise budget (presentation only)
  5. stage matrix
  6. exit mapping
- Scanner ingestion from local JSON files
- SARIF 2.1.0 adapter ingestion (strict envelope validation)
- Trivy adapter ingestion for vulnerabilities, misconfigurations, and secrets
- Native Snyk vulnerability JSON adapter ingestion
- Native Checkmarx JSON v2 adapter ingestion
- Sonar Generic Issues JSON compatibility adapter ingestion
- Strict adapter-level report envelope checks (required sections + schema version guard when provided)
- Optional baseline diff mode for PR/merge (`--new-findings-only` with `--baseline-scan`)
- Noise-budget preview in derived HTML with suppression counts/reasons (presentation-only)
- Strict YAML validation for context/policy/accepted-risk (unknown fields, duplicate keys, missing required fields)
- Authoritative machine output (`report.json`) + derived human report (`report.html`)
- Artifact integrity outputs (`checksums.sha256`) and structured run logs (`security-gate.run.log`)

## Requirements

- Go `1.25+`
- Local files for:
  - scanner reports (JSON)
  - context (YAML)
  - policy (YAML)
  - optional accepted risk (YAML)

## Installation

Build from source:

```bash
go build -o security-gate ./cmd/security-gate
```

Optional: run directly without a local binary:

```bash
go run ./cmd/security-gate --help
```

## Quick Start

Run the included deterministic simulation:

```bash
./scripts/simulate.sh
```

This generates WARN and BLOCK examples under `examples/simulation/out/`.
It also generates:
- a SARIF example (`block-sarif-pr`)
- a Snyk JSON example (`block-snyk-pr`)
- a Checkmarx JSON v2 example (`block-checkmarx-pr`)
- a Sonar Generic Issues example (`block-sonar-pr`)
- a CI auto-context example (`block-context-auto-github-pr`)
- a baseline diff example (`allow-new-findings-only-baseline-all`)

Run manually with sample inputs:

```bash
./security-gate \
  --scan examples/simulation/scanner-report.warn.json \
  --context examples/simulation/context.yaml \
  --policy examples/simulation/policy.yaml \
  --accepted-risk examples/simulation/accepted-risk.yaml \
  --out-json report.json \
  --out-html report.html
```

Run with CI auto-detected context (when running inside GitHub/GitLab/Jenkins):

```bash
./security-gate \
  --scan examples/simulation/scanner-report.warn.json \
  --context-auto \
  --policy examples/simulation/policy.yaml \
  --out-json report.json \
  --out-html report.html
```

## Run Examples

Run with SARIF 2.1.0:

```bash
./security-gate \
  --scan examples/simulation/scanner-report.warn.sarif.json \
  --context examples/simulation/context.pr-feature.yaml \
  --policy examples/simulation/policy.yaml \
  --out-json report.json \
  --out-html report.html
```

Run with Snyk JSON:

```bash
./security-gate \
  --scan examples/simulation/scanner-report.warn.snyk.json \
  --context examples/simulation/context.pr-feature.yaml \
  --policy examples/simulation/policy.yaml \
  --out-json report.json \
  --out-html report.html
```

Run with Checkmarx JSON v2:

```bash
./security-gate \
  --scan examples/simulation/scanner-report.warn.checkmarx.json \
  --context examples/simulation/context.pr-feature.yaml \
  --policy examples/simulation/policy.yaml \
  --out-json report.json \
  --out-html report.html
```

Run with Sonar Generic Issues JSON:

```bash
./security-gate \
  --scan examples/simulation/scanner-report.warn.sonar.json \
  --context examples/simulation/context.pr-feature.yaml \
  --policy examples/simulation/policy.yaml \
  --out-json report.json \
  --out-html report.html
```

## CLI Usage

```text
security-gate \
  --scan <scan.json> [--scan <scan2.json> ...] \
  [--baseline-scan <baseline.json> ...] \
  [--new-findings-only] \
  [--context <context.yaml> | --context-auto] \
  --policy <policy.yaml> \
  [--accepted-risk <accepted-risk.yaml>] \
  [--out-json report.json] \
  [--out-html report.html] \
  [--checksums checksums.sha256] \
  [--run-log security-gate.run.log] \
  [--no-html]
```

Required:

- `--scan` (repeatable, JSON only)
- one of:
  - `--context` (YAML)
  - `--context-auto` (deterministic CI environment auto-detection)
- `--policy` (YAML)

Optional:

- `--accepted-risk` (YAML)
- `--baseline-scan` (repeatable baseline scanner JSON)
- `--new-findings-only` (only for `pr`/`merge`; requires `--baseline-scan`)
- output path overrides
- `--no-html` to disable `report.html`

## Baseline Diff Mode

`--new-findings-only` is an optional PR/merge workflow mode:

- Requires one or more `--baseline-scan` files.
- Supported only for effective stages `pr` and `merge`.
- Baseline findings are compared deterministically to current findings.
- Numeric aggregation ignores baseline-known non-hard-stop findings.
- Hard-stop domains are still always enforced.

Baseline source model:

- `security-gate` does not persist baseline state.
- Baseline is provided per run via `--baseline-scan`.
- Typical CI usage: pass the latest trusted `main` (or release) scanner artifact into PR jobs.

## Decision Contract

Canonical decisions and exit codes:

- `ALLOW` -> `0`
- `WARN` -> `1`
- `BLOCK` -> `2`

Hard-stop domains always force `BLOCK` and cannot be overridden by accepted-risk records.

## Input Contracts

- Scanner input: JSON only (`--scan`)
- Optional baseline scanner input: JSON only (`--baseline-scan`)
- Supported scanner JSON envelopes:
  - Trivy JSON
  - SARIF 2.1.0 JSON
  - Snyk vulnerability JSON
  - Checkmarx JSON v2 (`scanResults`)
  - Sonar Generic Issues JSON (`issues`)
- Adapter-level envelope validation is strict:
  - Trivy: `Results` array required.
  - SARIF: `version=2.1.0`, `runs` required, each run requires `tool.driver.name` and `results`.
  - Snyk: `vulnerabilities` array required.
  - Checkmarx: `scanResults` array required; if present, `reportType` must be `json-v2`.
  - Sonar Generic: `issues` array required; each issue requires non-empty `ruleId`.
- Context input:
  - YAML (`--context`) OR
  - deterministic CI auto-detection (`--context-auto`)
- Policy/Accepted Risk: YAML only (`--policy`, `--accepted-risk`)
- Input files are untrusted and validated strictly

See authoritative docs for schemas and rules:

- `docs/md/core-decision-engine.md`
- `docs/md/policy-format.md`
- `docs/md/governance-accepted-risk.md`

## Output Artifacts

- `report.json` (authoritative)
  - `inputs[].role` differentiates `scan_json` provenance as `primary` vs `baseline` when baseline mode is used
- `report.html` (derived, non-authoritative)
- `checksums.sha256`
- `security-gate.run.log` (JSON lines)

## CI Auto-Context

`--context-auto` derives context deterministically from local CI environment variables.

Provider detection:

- GitHub Actions: `GITHUB_ACTIONS=true`
- GitLab CI: `GITLAB_CI=true`
- Jenkins: `JENKINS_URL` or `JENKINS_HOME` or (`BUILD_ID` + `JOB_NAME`)
- Otherwise: generic fallback

Deterministic override variables (optional):

- `SECURITY_GATE_BRANCH_TYPE`
- `SECURITY_GATE_PIPELINE_STAGE`
- `SECURITY_GATE_ENVIRONMENT`
- `SECURITY_GATE_REPO_CRITICALITY`
- `SECURITY_GATE_EXPOSURE`
- `SECURITY_GATE_CHANGE_TYPE`
- `SECURITY_GATE_SCANNER_NAME`
- `SECURITY_GATE_SCANNER_VERSION`
- `SECURITY_GATE_ARTIFACT_SIGNED`
- `SECURITY_GATE_PROVENANCE_LEVEL`
- `SECURITY_GATE_BUILD_CONTEXT_INTEGRITY`

All auto-detected values are normalized to canonical enums with safe fallbacks.

## Architecture and Authority Docs

Design authority chain:

1. `docs/md/core-decision-engine.md`
2. `docs/md/policy-format.md`
3. `internal/securitygate`
4. derived docs/html

Supporting docs:

- `docs/md/architecture.md`
- `docs/md/modules.md`

## Repository Layout

- CLI: `cmd/security-gate/main.go`
- Core engine: `internal/securitygate/`
- Scanner ingest: `internal/ingest/trivy/`, `internal/ingest/sarif/`, `internal/ingest/snyk/`, `internal/ingest/checkmarx/`, `internal/ingest/sonar/`
- Scoring: `internal/scoring/`
- Policy rules: `internal/policy/`
- Reporting: `internal/report/`
- Simulation: `examples/simulation/` and `scripts/simulate.sh`

## Development and Validation

Run required checks:

```bash
go test ./...
GOTOOLCHAIN=go1.25.4 go test -race ./...
./scripts/simulate.sh
```

Expected simulation behavior:

- WARN scenario exits with `1`
- BLOCK scenario exits with `2`
- SARIF PR scenario exits with `2`
- Snyk PR scenario exits with `2`
- Checkmarx PR scenario exits with `2`
- Sonar PR scenario exits with `2`
- CI auto-context PR scenario exits with `2`
- new-findings-only with full baseline exits with `0`

## Contributing

Contributions are welcome. Start with:

- `CONTRIBUTING.md` for workflow and quality gates
- `AGENTS.md` for deterministic design constraints and authority chain

## Security

Do not report vulnerabilities in public issues.

Use `SECURITY.md` for responsible disclosure instructions.

## Roadmap

- Additional scanner adapters
- Signed report attestations
- Repository policy packs
- Optional local-only historical analytics

## License

Licensed under Apache License 2.0. See `LICENSE`.
