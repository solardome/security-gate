# security-gate Enhancement Prompts (P0-P3)

Use these prompts as implementation tickets for coding agents. Each prompt is scoped to this repository and assumes strict alignment with `AGENTS.md`, `docs/md/core-decision-engine.md`, and `docs/md/policy-format.md`.

## P0 Prompt: CI Templates + PR Comment Output

```text
You are implementing P0 adoption enhancements for security-gate.

Goal:
1) Add ready-to-use CI templates for GitHub Actions and GitLab CI.
2) Add a PR-comment-friendly output format that summarizes decision and top findings.

Repository constraints (must follow):
- Keep decisions deterministic: ALLOW/WARN/BLOCK logic and exit codes (0/1/2) cannot change.
- No external API calls and no cloud dependencies.
- report.json remains authoritative; any comment/markdown output is derived.
- Unknown/missing signals must never reduce risk.
- Maintain strict validation behavior for YAML inputs.

Implementation tasks:
1) Add `.github/workflows/security-gate.yml` with matrix examples for:
   - single scan input
   - baseline diff input
   - policy + accepted-risk + context usage
2) Add `docs/examples/gitlab-ci/security-gate.gitlab-ci.yml` with equivalent stages.
3) Add a new output mode, e.g. `--format github-pr-comment`, that emits markdown including:
   - decision badge/text (ALLOW/WARN/BLOCK)
   - risk score
   - hard-stop trigger status
   - top findings table (id, severity, package/file, rationale)
   - link/reference to authoritative `report.json` artifact path
4) Ensure this output is deterministic in ordering and formatting.
5) Update README usage docs with copy/paste CI snippets and CLI example for PR comment mode.

Testing requirements:
- Add/adjust unit tests for formatter behavior and deterministic ordering.
- `go test ./...` must pass.
- `GOTOOLCHAIN=go1.25.4 go test -race ./...` must pass.
- `./examples/simulation/simulate.sh` must still produce expected WARN and BLOCK outcomes.

Deliverables:
- New CI template files.
- Formatter implementation + tests.
- README/docs updates.
- Short change summary with file list and sample output.
```

## P1 Prompt: Scanner Coverage + Supply Chain Inputs + Policy Testing

```text
You are implementing P1 competitiveness enhancements for security-gate.

Goal:
1) Add Semgrep native ingestion and a generic JSON/CSV adapter with mapping config.
2) Add SBOM/VEX ingestion for supply-chain-aware gating inputs.
3) Add a policy testing command for policy-as-code confidence.

Repository constraints (must follow):
- Deterministic behavior only; identical inputs => identical outputs.
- Existing decision contracts (ALLOW/WARN/BLOCK + exit codes 0/1/2) remain unchanged.
- Hard-stop domains always override score/noise budget.
- Accepted Risk must not override hard-stop domains.
- Strict input validation; reject malformed/unexpected fields where schemas define strictness.
- LLM output (if any) remains non-authoritative.

Implementation tasks:
1) Add `internal/ingest/semgrep/` parser:
   - Normalize Semgrep findings into existing internal finding model.
   - Deterministic sort/order.
   - Unit tests with realistic fixtures.
2) Add generic adapter for JSON/CSV:
   - New CLI option for mapping file (YAML) describing source field -> canonical field mapping.
   - Validation errors must include field path and line where applicable.
   - Add tests for valid mappings, missing required mappings, and malformed inputs.
3) Add SBOM ingestion (CycloneDX + SPDX minimal viable fields):
   - Parse package/component identities and versions.
   - Correlate with vulnerability findings by package identity.
4) Add VEX ingestion:
   - Support “not affected” suppression semantics with explicit audit trail in report.
   - Ensure suppression never hides hard-stop conditions unless explicitly allowed by canonical rules.
5) Add `security-gate test-policy` command:
   - Example: `security-gate test-policy --policy policy.yaml --fixture scan.json --expect BLOCK`
   - Deterministic pass/fail output and non-zero exit on mismatch.
6) Update docs:
   - supported scanner matrix
   - adapter mapping spec
   - SBOM/VEX behavior and precedence
   - policy testing command usage

Testing requirements:
- Add focused tests for all new parsers/adapters/CLI paths.
- `go test ./...` pass.
- `GOTOOLCHAIN=go1.25.4 go test -race ./...` pass.
- Simulation script still passes.

Deliverables:
- New ingest modules + tests.
- CLI updates + docs.
- Explicit precedence table for SBOM/VEX interaction with existing governance logic.
```

## P2 Prompt: Compliance Packs + Sigstore Signing + Policy Composition

```text
You are implementing P2 enterprise-scale enhancements for security-gate.

Goal:
1) Add compliance policy packs (SOC2, PCI-DSS baseline templates).
2) Add optional Sigstore/cosign signing integration for report artifacts.
3) Add policy composition/import support for multi-team policy layering.

Repository constraints (must follow):
- Core decision contracts are immutable unless authority docs are updated in same change.
- No nondeterministic policy evaluation.
- No network dependence in default execution path.
- `report.json` stays authoritative.
- Imported/composed policies must preserve strict YAML validation (unknown fields, duplicates, missing required fields).

Implementation tasks:
1) Add compliance policy pack files under `docs/` or `examples/` with clear schema-valid YAML.
2) Add `--policy-pack` convenience support (or documented workflow) to load these templates safely.
3) Add policy composition:
   - Support deterministic import ordering, e.g. `imports: [base.yaml, team.yaml]`.
   - Define merge/override semantics explicitly (last-wins or strict conflict errors).
   - Detect import cycles with clear diagnostics.
4) Add optional signing workflow:
   - CLI flags for signing `report.json` / `report.html` using local cosign key material.
   - If signing tool unavailable, fail clearly or skip only when explicitly configured.
   - Signature metadata must be included in derived output/audit section.
5) Update docs:
   - policy composition spec in `docs/md/policy-format.md`
   - any decision-impacting behavior in `docs/md/core-decision-engine.md`
   - operator usage in README

Testing requirements:
- Unit tests for composition merge rules and cycle detection.
- Unit/integration tests for signing command path using deterministic test fixtures/mocks.
- `go test ./...`, race tests, and simulation all pass.

Deliverables:
- compliance pack examples
- composition engine + tests
- signing integration + docs
- migration notes for existing single-policy users
```

## P3 Prompt: Local State + Init Bootstrapping

```text
You are implementing P3 ecosystem enhancements for security-gate.

Goal:
1) Add optional local historical state (SQLite) for trend tracking and SLA visibility.
2) Add `security-gate init` to bootstrap policy/config from existing scan artifacts.

Repository constraints (must follow):
- Keep default mode stateless and fully deterministic.
- State features must be opt-in and local-only (no remote calls).
- Historical state must never silently alter current-run decision rules.
- Current run decision remains authoritative; trend views are advisory unless explicitly configured.

Implementation tasks:
1) Add state module (`internal/state/`):
   - SQLite schema for runs, findings, decisions, timestamps, policy version fingerprint.
   - Deterministic writes keyed by run metadata and content hashes.
2) Add CLI options:
   - `--state-db <path>` to enable state persistence.
   - `security-gate trends` for summary views (new vs fixed findings, decision trend).
   - `security-gate sla` for overdue findings based on policy-defined windows.
3) Add `security-gate init`:
   - Analyze provided scan JSON and generate starter `policy.yaml`, `accepted-risk.yaml`, and optional `context.yaml` skeleton.
   - Keep generated files conservative (never understate risk).
   - Include inline comments or docs pointers for manual review.
4) Ensure explicit boundary:
   - Gate decision path must work unchanged when state DB is absent.
   - State read/write failures must be explicit and test-covered.

Testing requirements:
- Add tests for schema migrations (if any), trend calculations, and init output determinism.
- `go test ./...` and race tests must pass.
- Simulation still passes without requiring state DB.

Deliverables:
- `internal/state` implementation + tests
- new CLI commands and docs
- init-generated sample outputs in `examples/`
- clear note on what is authoritative vs advisory
```

## Suggested Execution Order

1. Run P0 first (fastest adoption impact).
2. Run P1 second (coverage + supply chain + policy confidence).
3. Run P2 third (enterprise usability and governance scale).
4. Run P3 last (stateful enhancements with highest implementation risk).
