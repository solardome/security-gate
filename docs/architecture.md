# Architecture

This document defines the system architecture for security-gate. It is consistent with
`docs/core-decision-engine.md` and focuses on components, data flow, trust/provenance,
and safe defaults. It avoids implementation details.

## Goals
- Deterministic, stage-aware CI/CD decisions (ALLOW, WARN, BLOCK).
- Local execution only; no network dependencies.
- Full decision trace with auditable inputs and outputs.
- Clear boundary between deterministic logic and optional LLM explanation.

## High-Level ASCII Diagram

+---------------------------+      +-------------------------+
| Scanner outputs (files)   |      | Context + Policy inputs |
| - Trivy JSON (MVP)        |      | - context.json          |
| - stdin (optional)        |      | - policy file           |
+------------+--------------+      | - accepted risk file    |
             |                     +-----------+-------------+
             v                                 |
      +------+-------+                         |
      | ingest/trivy |                         |
      +------+-------+                         |
             |                                 v
             v                          +------+-------+
      +------+-------+                  | normalize    |
      | normalize    |----------------->| unified schema|
      +------+-------+                  +------+-------+
             |                                 |
             v                                 v
      +------+-------+                  +------+-------+
      | score (risk) |<-----------------| score (trust)|
      +------+-------+   trust signals  +------+-------+
             |                                 |
             +---------------+-----------------+
                             v
                      +------+-------+
                      | policy       |
                      | noise budget |
                      | exceptions   |
                      | decision     |
                      +------+-------+
                             |
                             v
                      +------+-------+
                      | decision     |
                      | trace        |
                      +------+-------+
                             |
             +---------------+-----------------+
             v                                 v
     +-------+--------+                 +------+-------+
     | report         |                 | llm (optional)|
     | decision.json  |                 | explanation  |
     | summary.md     |                 | non-author.  |
     +----------------+                 +--------------+

## Module Boundaries
- cmd/cli orchestrates the pipeline and owns exit code behavior.
- ingest/trivy parses scanner outputs and hashes inputs.
- normalize converts scanner-specific data to the unified finding schema.
- score computes risk_score and trust_score deterministically.
- policy applies noise budget, exceptions, accepted risks, and stage decision matrix.
- decision_trace records ordered trace events and all authoritative inputs.
- governance (accepted risk) validates time-bound justifications and scope.
- report renders decision.json, summary.md, and optional HTML.
- llm consumes sanitized trace data and produces non-authoritative text only.

## Data Flow (Authoritative)
1) Ingest scanner outputs and compute input hashes.
2) Normalize to the unified finding schema (required fields enforced).
3) Score findings (risk_score) and compute trust_score from provenance signals.
4) Apply noise budget (PR only by default), exceptions, and accepted risk.
5) Apply the stage decision matrix to derive ALLOW/WARN/BLOCK and exit code.
6) Emit decision.json and summary.md with full decision trace.
7) Optionally generate LLM explanation text using sanitized trace data.

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

## Failure Modes and Safe Defaults
- Hard-stop domains (SECRET, MALWARE, PROVENANCE) always force BLOCK.
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
