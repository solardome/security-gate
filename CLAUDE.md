# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build -o security-gate ./cmd/security-gate

# Run all tests
go test ./...

# Run with race detection
GOTOOLCHAIN=go1.25.4 go test -race ./...

# Run a single test
go test ./internal/securitygate/... -run TestFunctionName

# Run simulation scenarios (deterministic integration tests)
./examples/simulation/simulate.sh
```

## Architecture

**security-gate** is a local, privacy-first CLI tool that converts security scanner JSON reports into deterministic CI/CD gating decisions: `ALLOW` (exit 0), `WARN` (exit 1), or `BLOCK` (exit 2). No network calls, no external APIs.

### Data Flow

```
Scanner JSON(s) → Ingest/Hash → Normalize (UnifiedFinding) → Governance → Score+Trust → Decision → Report
Baseline JSON(s) → (diff mode: --new-findings-only)
Context YAML    → Stage mapping, criticality, exposure
Policy YAML     → Rules, thresholds, hard-stops, noise budgets
Accepted-Risk YAML → Suppression governance records
```

### Decision Precedence (immutable, in order)

1. **Hard-stop domains** → Forces `BLOCK`, cannot be overridden by anything
2. **Accepted-risk governance** → Suppress findings if approved and in-scope
3. **Numeric scoring + trust bands** → Risk score [0-100]
4. **Noise budget** → Presentation-only suppression
5. **Stage matrix thresholds** → WARN/BLOCK floors per pipeline stage

### Key Packages

| Package | Role |
|---|---|
| `cmd/security-gate/` | CLI flag parsing → calls `securitygate.Run(cfg)` |
| `internal/securitygate/` | Core engine: orchestrates entire pipeline, types, governance, HTML report |
| `internal/ingest/{trivy,sarif,snyk,checkmarx,sonar}/` | Scanner adapters: parse scanner-specific JSON → `UnifiedFinding` |
| `internal/policy/` | Policy rule evaluation |
| `internal/scoring/` | Risk score + trust score computation |
| `internal/report/` | Report generation and audit |

### Critical Safety Invariants

- Unknown or missing signals must **never** reduce risk
- Hard-stop domains bypass numeric scoring entirely
- Accepted-risk cannot override hard-stops
- Risk scores are clamped to [0, 100] and must remain monotonic
- Strict YAML validation: unknown fields, duplicate keys, and missing required fields are all rejected

## Authoritative Design Documents

Before changing decision logic, read the relevant doc in `docs/md/`:

- `core-decision-engine.md` — Decision precedence, scoring formulas, exit-code contracts
- `policy-format.md` — Policy YAML schema
- `governance-accepted-risk.md` — Accepted-risk record schema
- `architecture.md` — Module boundaries and data flow
- `modules.md` — Module interface specifications

`AGENTS.md` defines the authority chain: docs → `internal/securitygate` code → everything else.

## Development Checklist (from AGENTS.md)

For any behavior-changing PR:
1. Read the relevant `docs/md/` authority docs first
2. Make minimal, deterministic changes
3. Add/adjust unit tests
4. `go test ./...` passes
5. `GOTOOLCHAIN=go1.25.4 go test -race ./...` passes
6. `./examples/simulation/simulate.sh` passes
7. Update `docs/md/` in the same PR if the behavior contract changed

## Prohibited

- Network calls or remote fetches of any kind
- Nondeterministic decision paths
- Executing untrusted input content
- Silently relaxing YAML strict validation
- Changing exit-code contracts or authoritative enums without matching doc updates
