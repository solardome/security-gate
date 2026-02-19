# AGENTS.md

Operational guide for autonomous coding agents working in `security-gate`.

## Mission

Build and maintain a local, privacy-first DevSecOps gate that converts scanner outputs into deterministic CI/CD decisions (`ALLOW` / `WARN` / `BLOCK`) with full decision traceability.

## Scope and Boundaries

- Local execution only.
- No external APIs, no SaaS, no cloud dependencies.
- Decision logic must be deterministic.
- LLM output is optional, non-authoritative, and must never affect decisions.
- Scanner execution is out of scope; scanner report ingestion is in scope.

## Design Authority Chain (Anti-Drift)

When behavior conflicts, this order is authoritative:

1. `docs/md/core-decision-engine.md`
2. `docs/md/policy-format.md`
3. Code implementation in `internal/securitygate`
4. Derived docs and HTML

Never redefine canonical enums/formulas/schemas outside the two authority docs.

## Canonical Contracts

- Decisions: `ALLOW`, `WARN`, `BLOCK`
- Exit codes: `0`, `1`, `2`
- Scanner input: JSON files only (`--scan`)
- Optional baseline scanner input: JSON files only (`--baseline-scan`)
- Context input: YAML (`--context`) or deterministic CI auto-detection (`--context-auto`)
- Policy/Accepted Risk input: YAML files only (`--policy`, `--accepted-risk`)
- `report.json` is authoritative
- `report.html` is derived/non-authoritative

## Determinism and Safety Requirements

- Identical inputs must produce identical outputs.
- Risk scoring must remain monotonic.
- Scores must be clamped to `[0,100]`.
- Unknown or missing signals must never reduce risk.
- Hard-stop domains must bypass numeric scoring and noise budget.
- Accepted Risk must never override hard-stop domains.
- Input files are untrusted and must be validated strictly.

## Strict YAML Requirements

For `policy.yaml`, `context.yaml`, and `accepted-risk.yaml`:

- Reject unknown fields.
- Reject duplicate keys.
- Reject missing required fields.
- Emit validation diagnostics with field path and line number.

Schema validation currently lives in `internal/securitygate/yaml_schema.go`.

## Repository Map

- CLI entrypoint: `cmd/security-gate/main.go`
- Core engine: `internal/securitygate/`
- Split modules:
  - `internal/ingest/trivy/`
  - `internal/scoring/`
  - `internal/policy/`
  - `internal/report/`
- Authoritative specs: `docs/md/`
- Single-page docs: `docs/html/security-gate.html`
- Simulation inputs/outputs: `examples/simulation/`
- Simulation runner: `examples/simulation/simulate.sh`

## Development Workflow

1. Read relevant authority docs first.
2. Make minimal, deterministic code changes.
3. Add/adjust unit tests for behavior changes.
4. Run full tests: `go test ./...`
5. Run race tests: `GOTOOLCHAIN=go1.25.4 go test -race ./...`
6. Run simulation: `./examples/simulation/simulate.sh`
7. If behavior contract changed, update docs in the same PR.

## Testing Expectations

Any behavior change to scoring, policy evaluation, governance, stage mapping, or parsing must include tests.

Minimum checks before completion:

- `go test ./...` passes
- `GOTOOLCHAIN=go1.25.4 go test -race ./...` passes
- Simulation produces expected WARN and BLOCK cases
- Generated reports are written under `examples/simulation/out/`

## Documentation Update Rules

Update docs whenever these change:

- Input format or validation behavior
- Decision precedence/matrix/threshold behavior
- Policy schema or accepted-risk schema
- Report contract fields

Prefer updating:

- `docs/md/core-decision-engine.md` for engine/report contracts
- `docs/md/policy-format.md` for policy schema
- `README.md` for usage and operator-facing behavior
- `docs/html/security-gate.html` as derived summary

## Security and Prohibited Actions

- Do not introduce network calls or remote fetches.
- Do not add nondeterministic decision paths.
- Do not execute untrusted input content.
- Do not silently relax strict YAML validation.
- Do not change authoritative enums/exit-code contracts without matching doc updates.

## Completion Criteria for Agent Tasks

A task is complete only when all apply:

- Implementation compiles.
- Tests pass.
- Simulation runs successfully.
- Behavior matches authoritative docs.
- Docs are updated if contracts changed.
