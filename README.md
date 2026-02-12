# security-gate

Authority Notice
This document is descriptive and non-authoritative. Design intent lives in design/architecture.prompt.md, deterministic decision logic and evaluation order live in docs/core-decision-engine.md, and the policy schema lives in docs/policy-format.md. In conflicts, those authoritative sources prevail and this document must not override or reinterpret them.

**Deterministic, stage-aware release decisions for CI/CD — not just scanner severities.**

security-gate is a **local, privacy-first DevSecOps control** that consumes security scanner outputs
and converts them into **clear, deterministic CI/CD decisions**: **ALLOW / WARN / BLOCK**, with a
full, auditable decision trace.

Optional local LLM support (e.g., via Ollama) can generate **human-friendly explanations**, but
**never influences decisions**.

## Problem Statement
Security scanners produce findings and severities. Release gates need **decisions** that consider
stage, exposure, trust, provenance, and governance. Teams face:
- High noise and inconsistent gating between repos
- Severity-only decisions that ignore context
- Suppressions that are permanent and unaudited
- Untrusted inputs with unclear provenance

**security-gate solves this by classifying releases, not findings.**

## Key Principles
- **Deterministic decisions**: same inputs always yield the same outcome.
- **Decision trace**: every input, modifier, and rule evaluation is auditable.
- **Stage-aware escalation**: pr, main, release, and prod use distinct gates.
- **Privacy-first local execution**: no SaaS, no external APIs, no network dependency.
- **Input hashing**: all decision-affecting inputs (scanner outputs, context, policy, accepted risks) are hashed and recorded in decision.json/trace.
- **Deterministic 'allow_warn_in_prod'**: it only keeps WARN when every warn-causing finding is covered; partial coverage still escalates to BLOCK.
- **Accepted Risk / Justification Workflow**: time-bound, approved exceptions with expiry.
- **Provenance-aware trust**: trust_score influences release risk and gating.
- **Optional, non-authoritative LLM**: explanation-only, never part of decision logic.

## Conceptual Quickstart (No Commands)
1) Produce scanner outputs (MVP: Trivy JSON) and store them locally.
2) Provide a local context input with pipeline stage, exposure, and trust signals.
3) Provide policy rules and any accepted risk records.
4) Run security-gate to ingest, normalize, score, and decide.
5) Consume decision.json, summary.md, and the exit code in your CI/CD stage.

## CLI Flags and Usage
The binary is non-interactive and is controlled entirely via flags.

Usage:
```bash
security-gate [flags]
```

Flag reference:

| Flag | Required | Description |
| --- | --- | --- |
| `--input <path>` | Conditionally | Path to a Trivy JSON input file. Repeatable for multiple files. Required unless `--stdin` is used. |
| `--stdin` | Conditionally | Read one Trivy JSON payload from standard input. Can be combined with one or more `--input` flags. |
| `--context <path>` | No | Path to context JSON. If omitted, defaults are used (`pipeline_stage=pr`, `environment=dev`, `exposure=unknown`, `change_type=unknown`). |
| `--policy <path>` | No | Path to policy JSON. If omitted, the embedded default policy is used. |
| `--accepted-risk <path>` | No | Path to accepted risks JSON. If omitted, an empty accepted-risks set is used. |
| `--output-dir <path>` | No | Directory where reports are written. Default is `reports/<timestamp>`. |
| `--stage <pr\|main\|release\|prod>` | No | Overrides the stage from context for evaluation. |
| `--report-html` | No | Also emit `report.html` in the output directory (in addition to `decision.json` and `summary.md`). |
| `--llm <on\|off>` | No | Toggle optional LLM explanation metadata. Default is `off`. |

Exit codes:
- `0` = `ALLOW`
- `1` = `WARN`
- `2` = `BLOCK` (and fatal CLI/runtime errors)

Examples:

Run with one scan file:
```bash
security-gate \
  --input testdata/trivy-report-sample.json
```

Run with full inputs:
```bash
security-gate \
  --input reports/trivy-app.json \
  --context context.json \
  --policy policy.json \
  --accepted-risk accepted-risks.json \
  --stage main \
  --output-dir reports/main-run \
  --report-html \
  --llm off
```

Run from stdin:
```bash
cat testdata/trivy-report-sample.json | security-gate --stdin --output-dir reports/stdin-run
```

## Architecture Overview
- **Ingest**: read local scanner outputs and hash inputs.
- **Normalize**: convert to the unified finding schema.
- **Score**: compute risk_score per finding and trust_score for provenance.
- **Policy**: apply noise budget (pr only by default), exceptions, accepted risks, and
  the stage decision matrix.
- **Decision trace**: record a complete, ordered audit trail.
- **Report**: emit decision.json and summary.md (optional HTML).
- **LLM (optional)**: generate non-authoritative explanations from sanitized trace data.
- Evaluation order for governance, scoring, noise budget, policy, and the stage decision matrix is defined canonically in `docs/core-decision-engine.md` under **“Canonical Deterministic Evaluation Order (Authoritative)”** and is not re-specified here.

## Decision Model Summary
- Findings are normalized and scored deterministically (risk_score 0-100).
- Hard-stop behavior is defined canonically in `docs/core-decision-engine.md` under
  **“Hard-Stop Conditions (Authoritative)”**. Examples include SECRET, MALWARE, specific
  synthetic PROVENANCE violations, and the synthetic UNKNOWN_DOMAIN_MAPPING condition.
- Hard-stop findings are never suppressible, bypass noise budget, and always force BLOCK
  regardless of other signals.
- trust_score (0-100) is computed from provenance and build context signals.
- release_risk = max(finding risk) + context modifiers (stage, exposure, change, trust).
- Noise budget can reduce pr friction but never applies to hard-stop domains and is
  strictly PR-only in the MVP; any attempt to enable a noise budget on main/release/prod
  is treated as a fatal policy error and results in fail-closed behavior (see
  `docs/core-decision-engine.md` and `docs/policy-format.md`).
- A stage-specific decision matrix produces ALLOW, WARN, or BLOCK.
- `allow_warn_in_prod` only avoids WARN→BLOCK when every warn-causing fingerprint is covered; partial coverage still results in BLOCK.

### Provenance & Signing Layers
- Explicit provenance/signing hard stops emit synthetic findings (`domain=PROVENANCE`, `hard_stop=true`, `risk_score=100`) for invalid signatures, provenance mismatches, unsigned artifacts when signing is required, or insufficient provenance level. These synthetic findings are evaluated ahead of scoring and noise budgeting and always block, regardless of trust_score or release_risk.
- Trust penalties only adjust `trust_score` when optional provenance signals are missing (unsigned/unknown signatures or unknown provenance level when the policy does not demand them). Unsigned artifacts are therefore not automatically a minor penalty—only when the policy does not enforce the evidence. The canonical hard-stop tokens are `PROVENANCE_INVALID_SIGNATURE`, `PROVENANCE_MISMATCH`, `PROVENANCE_UNSIGNED_ARTIFACT`, and `PROVENANCE_INSUFFICIENT_LEVEL`.

Stage identifiers are canonical tokens defined in `docs/core-decision-engine.md`
(`Stage Enum (Canonical)`). Informally:
| Legacy term | Canonical token |
| --- | --- |
| PR/feature | pr |
| merge/main | main |
| release | release |
| deploy-to-prod | prod |

## High-Level Decision Matrix by Stage
Hard-stop findings always force BLOCK.

| Stage | ALLOW | WARN | BLOCK |
| --- | --- | --- | --- |
| pr | release_risk <= 45 and trust_score >= 20 | release_risk 46-70 or trust_score 10-19 | release_risk >= 71 or trust_score < 10 |
| main | release_risk <= 35 and trust_score >= 30 | release_risk 36-60 or trust_score 20-29 | release_risk >= 61 or trust_score < 20 |
| release | release_risk <= 30 and trust_score >= 40 | release_risk 31-50 or trust_score 30-39 | release_risk >= 51 or trust_score < 30 |
| prod | release_risk <= 25 and trust_score >= 50 | release_risk 26-40 or trust_score 40-49 | release_risk >= 41 or trust_score < 40 |

Default policy: WARN escalates to BLOCK in prod unless an approved accepted risk explicitly
allows WARN in prod.

## Outputs and Their Meaning
- **decision.json (authoritative)**: full decision artifact with trace, scores, policy results,
  and exit code.
- **summary.md**: human-readable decision summary.
- **Optional HTML report**: static report for local sharing.
- **Exit codes**: 0=ALLOW, 1=WARN, 2=BLOCK.
- **Optional LLM explanation**: non-authoritative text linked from decision.json.

## Security Considerations
- Inputs are untrusted; all scanner outputs are treated as attacker-controlled.
- All inputs are hashed and recorded in the decision trace for auditability.
- Redaction and minimization prevent secret leakage into reports or LLM prompts.
- Prompt-injection awareness is mandatory for any LLM usage.
- Safe defaults: missing or low-trust signals tighten gates, especially in prod.

## MVP Scope vs Roadmap
MVP:
- Local-only execution.
- Trivy JSON ingestion (file path and optional stdin).
- Deterministic scoring, trust computation, and stage-aware decisions.
- decision.json and summary.md outputs; optional local LLM explanations.
- Noise budget is PR-only in MVP. No noise budget on main/release/prod.

Roadmap (non-exhaustive):
- Additional scanners (e.g., Gitleaks) using the same unified schema.
- Expanded policy rules and governance workflows.
- Optional HTML report improvements.
- Optional main-stage noise budget and advanced selector configuration.

## License Considerations
- Apache 2.0 is the preferred license.
- LLM-off mode must remain fully functional and usable without any LLM dependency.

## Why Scanner Severity ≠ Release Decision
Scanner severity alone does not account for:
- Stage-specific risk tolerance (pr vs prod)
- Provenance and trust signals
- Exposure and change context
- Hard-stop domains that require immediate blocking
- Governed exceptions and accepted risk with expiry

security-gate combines these factors into a deterministic release decision.

## Acceptance Criteria
- [ ] Problem statement and core pain points are clear.
- [ ] Key principles match deterministic, stage-aware, and provenance-aware goals.
- [ ] Conceptual quickstart includes no real commands.
- [ ] Architecture overview and decision model summary are consistent with the core engine.
- [ ] Decision matrix by stage matches the authoritative thresholds.
- [ ] Outputs, security considerations, MVP scope, roadmap, and license notes are included.
- [ ] "Why severity ≠ release decision" is explicitly addressed.
