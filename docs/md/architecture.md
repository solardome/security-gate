# Architecture

Authority Notice
This document is descriptive and non-authoritative. Design intent lives in design/architecture.prompt.md, deterministic decision logic and evaluation order live in docs/md/core-decision-engine.md, and the policy schema lives in docs/md/policy-format.md. In conflicts, those authoritative sources prevail and this document must not override or reinterpret them.

This document defines the system architecture for security-gate. It is consistent with
`docs/md/core-decision-engine.md` and focuses on components, data flow, trust/provenance,
and safe defaults. It avoids implementation details.

## Goals
- Deterministic, stage-aware CI/CD decisions (ALLOW, WARN, BLOCK).
- Local execution only; no network dependencies.
- Full decision trace with auditable inputs and outputs.
- Clear boundary between deterministic logic and optional LLM explanation.

## High-Level Diagram

The rendered HTML view shows this canonical flow:
ingest → normalize → score → policy → decision_trace → report,
with optional LLM explanation consuming sanitized trace data only.

## Module Boundaries
- cmd/security-gate orchestrates the pipeline and owns exit code behavior.
- ingest/trivy parses scanner outputs and hashes inputs.
- normalize converts scanner-specific data to the unified finding schema.
- score computes risk_score and trust_score deterministically.
- policy applies noise budget, exceptions, accepted risks, and stage decision matrix.
- decision_trace records ordered trace events and all authoritative inputs.
- governance (accepted risk) validates time-bound justifications and scope.
- report renders decision.json, summary.md, and optional HTML.
- llm consumes sanitized trace data and produces non-authoritative text only.

## Data Flow (Authoritative)
At a high level, data flows from ingest → normalize → score → policy → decision_trace → report, with optional LLM explanation consuming sanitized trace data. Evaluation order for governance, scoring, noise budget, policy, and decision matrix is defined canonically in `docs/md/core-decision-engine.md` under **“Canonical Deterministic Evaluation Order (Authoritative)”** and is not re-specified here.

## Deterministic vs AI Boundary
- Deterministic boundary includes ingest, normalize, score, policy, and decision_trace.
- LLM is explanation-only and never affects risk scoring, policy, or decisions.
- LLM input is sanitized and minimized; output is labeled non-authoritative.

## Trust and Provenance Flow
- Trust signals are gathered from context and scanner metadata (pinned versions,
  freshness, input integrity, artifact signing, provenance level, build context).
- trust_score is computed deterministically and stored in decision.json.
- trust_score directly affects release_risk via the trust modifier and can be used
  in policy rules.
- Missing or unknown signals reduce trust_score and tighten gating.
- All decision-affecting inputs (scanner outputs, context input, policy file, accepted risk file) are hashed and recorded in both decision.json and the decision_trace so the architecture produces a fully audit-ready snapshot of every influence on the decision.
- Provenance and signing are enforced in two layers: explicit synthetic findings in `domain=PROVENANCE` that hard-stop BLOCK when deterministic requirements fail, and trust penalties that only adjust `trust_score`.
  - Synthetic provenance hard stops cover `PROVENANCE_INVALID_SIGNATURE`, `PROVENANCE_MISMATCH`, `PROVENANCE_UNSIGNED_ARTIFACT`, and `PROVENANCE_INSUFFICIENT_LEVEL`, are normalized before scoring, and bypass governance suppressions and noise budget.
  - Trust penalties only apply when the policy does not require the evidence (e.g., unsigned/unknown signatures or provenance_level=unknown without a minimum requirement).
  - Deterministic evaluation always resolves these provenance hard stops before risk scoring and noise budgeting so that provenance failures block regardless of numeric scores.

## Stage Enum (Canonical)
The canonical stage enum and legacy-to-canonical mapping are defined in
`docs/md/core-decision-engine.md` under **“Stage Enum (Canonical)”** and are the single source
of truth. Informally for architecture discussions: stages are `pr`, `main`, `release`,
and `prod` (with legacy terms like PR/feature, merge/main, and deploy-to-prod mapping to
those canonical tokens).

## Failure Modes and Safe Defaults
- Hard-stop conditions are defined authoritatively in `docs/md/core-decision-engine.md` under **“Hard-Stop Conditions (Authoritative)”**.
- These hard-stop conditions are never suppressible, bypass noise budgets, and always force BLOCK regardless of release risk or trust.
- input_sha256 is mandatory and computed at ingest; if it cannot be computed, the decision is fail-closed for stage=main, release, and prod. For stage=pr, proceed only with a recorded warning and low-trust defaults.
- scan_timestamp must be present; if missing from scanner output, substitute ingest_time and record timestamp_source=ingest.
- pr may produce WARN for partial data only when trust_score remains above the lowest bucket and no hard-stop exists.
- main, release, and prod default to fail-closed on any fatal ingest/normalize/score/policy error.
- decision_trace always records failures, substitutions, and the safe-default path taken.

## Extensibility Approach
- New scanners are added as ingest adapters that map to the unified schema.
- New domains must define severity mapping and any hard-stop rules.
- Policy-as-code is versioned and evaluated deterministically; rules are traceable.
- Accepted risk and exception handling are modular and time-bound.
- Report formats can be extended without affecting decision logic.

## Acceptance Criteria
- [ ] Architecture diagram reflects the deterministic pipeline and optional LLM boundary.
- [ ] Module boundaries match the core decision engine responsibilities.
- [ ] Data flow includes ingest, normalize, score, policy, decision trace, and report.
- [ ] Trust/provenance flow and its effect on decisions is explicit.
- [ ] Failure modes describe fail-closed behavior for merge/release/prod.
- [ ] Extensibility guidance does not alter deterministic decision logic.
