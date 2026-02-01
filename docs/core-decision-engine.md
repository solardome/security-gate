# Core Decision Engine

Authoritative specification for the deterministic decision engine. This document defines
normalized inputs, scoring, trust, gating, and outputs. It must be internally consistent
and implementation-agnostic.

## Purpose and Scope
- Convert scanner findings into deterministic, stage-aware CI/CD decisions: ALLOW, WARN, BLOCK.
- Produce auditable decision artifacts, including a complete decision trace.
- Enforce safe defaults for missing or untrusted signals.
- Keep LLM usage strictly non-authoritative and outside decision logic.

## Glossary (Canonical Terms)
- finding: A normalized security issue from a scanner output.
- domain: Classification of a finding (VULNERABILITY, SECRET, MALWARE, LICENSE, CONFIG, PROVENANCE).
- risk_score: 0-100 score for a single finding after normalization and modifiers.
- release_risk: 0-100 score for the release, computed from max(finding risk) plus context modifiers.
- trust_score: 0-100 score for input provenance and build context trustworthiness.
- hard-stop: A finding or condition that forces BLOCK regardless of numeric risk.
- stage: Pipeline stage (pr, main, release, prod).
- noise budget: Stage-scoped cap on the number of non-hard-stop findings considered for decision.
- accepted risk: A time-bound, approved justification that can suppress or downgrade specific findings.
- exception: A narrow, deterministic rule to suppress known false positives; always time-bound.

## Inputs (Authoritative)
- Normalized findings (Unified Finding Schema below), derived from scanner outputs.
- Context inputs (from context.json or CLI), including:
  - pipeline_stage (pr, main, release, prod), branch_type, environment
  - repo_criticality, exposure, change_type
  - scanner_version pinning, scan_timestamp, artifact signing/provenance signals
- Policy-as-code rules and accepted risk objects.

## Stage Enum (Canonical)
Stages are represented by the following tokens:
- pr
- main
- release
- prod

Legacy-to-canonical mapping:
| Legacy term | Canonical token |
| --- | --- |
| PR/feature | pr |
| merge/main | main |
| deploy-to-prod | prod |

## 1) Unified Finding Schema
All scanner outputs MUST be normalized into this schema before scoring.

### Required Fields
| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| finding_id | string | yes | Stable deterministic ID (hash of key fields). |
| domain | enum | yes | VULNERABILITY, SECRET, MALWARE, LICENSE, CONFIG, PROVENANCE. |
| severity | enum | yes | CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN. |
| title | string | yes | Short, human-readable label. |
| description | string | yes | Short summary; no raw secrets. |
| source_scanner | string | yes | e.g., trivy. |
| source_version | string | yes | Pinned scanner version if known. |
| input_sha256 | string | yes | Hash of the raw scanner output file or stream. |
| scan_timestamp | string | yes | RFC3339 time of scan generation or ingest_time substitute. |
| timestamp_source | enum | yes | scanner or ingest. |
| location | object | yes | File path, package name, image, repo, or artifact target. |
| evidence_ref | string | yes | Reference to evidence in decision trace. |

### Optional Fields
| Field | Type | Notes |
| --- | --- | --- |
| cve_id | string | For vulnerability domain when available. |
| cvss_v3 | number | 0.0-10.0. Overrides severity for base score. |
| fix_available | enum | true, false, unknown. |
| fix_version | string | Target fix version if known. |
| exploit_maturity | enum | confirmed, functional, poc, none, unknown. |
| reachability | enum | reachable, potentially, not_reachable, unknown. |
| dependency_scope | enum | direct, transitive, unknown. |
| license_type | enum | permissive, weak_copyleft, strong_copyleft, unknown. |
| confidence | enum | high, medium, low, unknown. |
| tags | array<string> | Freeform tags from source. |
| vendor_status | enum | affected, not_affected, unknown. |
| remediation_hint | string | Deterministic hint only (no LLM). |

### Required vs Optional Field Handling
Required for authoritative decision artifacts (must exist in normalized findings and decision.json):
- finding_id, domain, severity, title, description, source_scanner, source_version, input_sha256, scan_timestamp, timestamp_source, location, evidence_ref.

Mandatory handling rules:
- Missing required fields must not be silently set to UNKNOWN. Any substitution must be explicit and recorded in the decision trace.
- input_sha256 must be computed at ingest from the raw input. If the raw input cannot be hashed, the decision is fail-closed for stage=main, release, and prod. For stage=pr, proceed with a recorded warning and low-trust defaults.
- scan_timestamp must be present. If missing from scanner output, substitute ingest_time and set timestamp_source=ingest. If present in scanner output, set timestamp_source=scanner.

Optional with safe defaults:
- cve_id, cvss_v3, fix_available, fix_version, exploit_maturity, reachability, dependency_scope, license_type, confidence, tags, vendor_status, remediation_hint.
- Missing optional fields are treated as unknown and handled per risk scoring modifiers.

### Enumerations (Canonical)
- domain: VULNERABILITY, SECRET, MALWARE, LICENSE, CONFIG, PROVENANCE
- severity: CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN
- exploit_maturity: confirmed, functional, poc, none, unknown
- reachability: reachable, potentially, not_reachable, unknown
- fix_available: true, false, unknown
- dependency_scope: direct, transitive, unknown
- timestamp_source: scanner, ingest

## 2) Risk Scoring Model (Per Finding)
### Overview
Each finding receives a deterministic risk_score in 0-100. Scoring is monotonic:
adding findings or reducing trust can never decrease release risk.

### Base Score
- If cvss_v3 is present: base_score = round(cvss_v3 * 10).
- Otherwise map severity:
  - CRITICAL = 90
  - HIGH = 70
  - MEDIUM = 50
  - LOW = 25
  - INFO = 5
  - UNKNOWN = 50 (safe default)

### Hard-Stop Domains
These domains bypass numeric scoring and force BLOCK:
- SECRET
- MALWARE
- PROVENANCE (e.g., unsigned artifact, provenance mismatch)
Hard-stop findings MUST still include risk_score = 100 and hard_stop = true in the trace.

### Additive Modifiers (Non-Hard-Stop Domains)
Modifiers are added to base_score and then clamped to 0-100.

- exploit_maturity:
  - confirmed +15
  - functional +10
  - poc +5
  - none +0
  - unknown +5
- reachability:
  - reachable +15
  - potentially +8
  - not_reachable +0
  - unknown +5
- fix_available:
  - false +5
  - true +0
  - unknown +3
- dependency_scope:
  - direct +5
  - transitive +0
  - unknown +3
- license_type (LICENSE domain only):
  - strong_copyleft +10
  - weak_copyleft +5
  - permissive +0
  - unknown +5

### Unknown Handling
Unknown signals must not reduce risk. All unknown values either add a small penalty or
are treated as medium severity.

### Per-Finding Risk Output
- risk_score = clamp(base_score + modifiers, 0, 100)
- hard_stop = true only for hard-stop domains

## 3) Trust Score Computation
Trust is a first-class input to policy evaluation and release risk.

### Trust Signals and Weights (0-100 total)
| Signal | Weight | Notes |
| --- | --- | --- |
| scanner_pinned | 20 | Scanner version pinned and verified. |
| scan_freshness | 15 | Age of scan artifact. |
| input_integrity | 15 | Input hash present and matches. |
| artifact_signing | 20 | Artifact signature verified. |
| provenance_level | 20 | e.g., SLSA level or equivalent. |
| build_context_trust | 10 | Protected branch, trusted CI context. |

### Signal Scoring (0.0-1.0)
- scanner_pinned: yes=1.0, no/unknown=0.2
- scan_freshness (age): <=24h=1.0, <=7d=0.7, <=30d=0.4, >30d or unknown=0.2
- input_integrity: verified=1.0, missing/unknown=0.2, mismatch=0.0
- artifact_signing: verified=1.0, unsigned/unknown=0.2, invalid=0.0
- provenance_level: level3+=1.0, level2=0.7, level1=0.4, none/unknown=0.2
- build_context_trust: protected=1.0, unprotected/unknown=0.3

### Calculation
- trust_score = round(sum(weight * signal_score))
- Result is clamped to 0-100.

### Trust Usage
- trust_score is added to decision.json and is addressable in policy rules.
- trust_score contributes to release_risk via a trust modifier (see Section 4).
- scan_timestamp freshness is validated before trust scoring. If the timestamp is more than 5 minutes in the future, or older than `now - max_age_days` (default 30 days) and no explicit override flag is present, the `scan_freshness` signal is forced to the unknown/low bucket (0.2) and the trace records an event (e.g., `scan_timestamp.stale` or `scan_timestamp.future`) with the offending timestamp and configured `max_age_days`. `timestamp_source` must still reflect whether the value came from the scanner or was substituted (ingest). This prevents freshness spoofing from artificially inflating trust.

## 4) Release Risk Computation
Release risk is computed as:
- release_risk = clamp(max_finding_risk + stage_modifier + exposure_modifier + change_modifier + trust_modifier, 0, 100)

### Context Modifiers
- stage_modifier:
  - pr: +0
  - main: +5
  - release: +10
  - prod: +15
- exposure_modifier (from context):
  - public: +10
  - internal: +5
  - private: +0
  - unknown: +5
- change_modifier:
  - high_risk (privileged/infra/identity): +5
  - moderate: +3
  - low: +0
  - unknown: +3
- trust_modifier (based on trust_score):
  - >=80: +0
  - 60-79: +3
  - 40-59: +6
  - 20-39: +10
  - <20: +15

### Release Risk Algorithm (Deterministic)
1) Normalize findings to Unified Finding Schema.
2) Compute risk_score for each finding.
3) Identify hard-stop findings (SECRET, MALWARE, PROVENANCE).
4) Apply noise budget (Section 6) to non-hard-stop findings.
5) max_finding_risk = max(risk_score of remaining findings; 0 if none).
6) Compute release_risk with context and trust modifiers.
7) Apply decision matrix for the current stage (Section 5).
8) Generate decision trace and decision.json.

## Deterministic Evaluation Order
1) Ingest, validate, and hash every decision-affecting input (scanner outputs, context, policy, accepted risks); fatal errors follow the prescribed fail-closed behavior for each stage.
2) Normalize inputs into the Unified Finding Schema and derive stable fingerprints for each finding.
3) Detect hard-stop conditions (e.g., SECRET, MALWARE, PROVENANCE, UNKNOWN_DOMAIN_MAPPING, synthetic provenance findings); these findings bypass governance and noise budget steps and always force BLOCK.
4) Apply governance: valid exceptions and Accepted Risks with `suppress_from_scoring` effects remove findings from the scoring set, while each governance event records the suppressed fingerprints and counts in the trace/report. Expired or invalid accepted risks do not contribute to scoring (although their expiry escalation rules still apply).
5) Score only the remaining scoring set, computing per-finding risk_score and the trust modifiers defined in Section 3.
6) Apply the PR-only noise budget to the scored scoring set (hard-stop findings are excluded by definition); any noise budget configuration targeting main/release/prod is a fatal policy error.
7) Evaluate policy rules in deterministic order, including selectors and tightening actions.
8) Apply the stage matrix plus escalation logic (prod warn_to_block and allow_warn_in_prod coverage).
9) Enforce governance floors such as “Accepted Risk covering HIGH/CRITICAL findings mandates at least WARN.”
10) Emit `decision.json`, `decision_trace`, `summary.md`, and other optional reports, ensuring every suppressed finding remains visible with its `suppressed_by_*` flags.
11) Optionally generate an LLM explanation artifact using sanitized, non-authoritative inputs derived from the finalized trace.

Suppressed findings continue to appear in `decision.findings.items` with their suppression flags, and every governance event (exception, accepted risk) records the bounded fingerprint list and suppressed count so the audit trail remains complete even though those findings no longer feed into scoring.

## 5) Explicit Decision Matrices by Stage
Hard-stop findings always force BLOCK regardless of numeric scores.

### pr
- ALLOW: release_risk <= 45 and trust_score >= 20
- WARN: release_risk 46-70 or trust_score 10-19
- BLOCK: release_risk >= 71 or trust_score < 10

### main
- ALLOW: release_risk <= 35 and trust_score >= 30
- WARN: release_risk 36-60 or trust_score 20-29
- BLOCK: release_risk >= 61 or trust_score < 20

### release
- ALLOW: release_risk <= 30 and trust_score >= 40
- WARN: release_risk 31-50 or trust_score 30-39
- BLOCK: release_risk >= 51 or trust_score < 30

### prod
- ALLOW: release_risk <= 25 and trust_score >= 50
- WARN: release_risk 26-40 or trust_score 40-49
- BLOCK: release_risk >= 41 or trust_score < 40
- Default policy: WARN escalates to BLOCK in prod unless an approved accepted risk explicitly allows WARN in prod.

## Prod WARN Escalation and allow_warn_in_prod Coverage
Prod warn_to_block escalation applies globally. The deterministic **warn-causing set** consists of:
1. All non-hard-stop findings in the scoring set with `severity >= HIGH`.
2. If no severity values exist, the single top finding determined by the Deterministic Finding Ordering.
The **warn_causing_fingerprints** are the fingerprints of that set. Escalation to BLOCK is prevented only when a valid Accepted Risk (active stage_scope includes prod, environment matches, not expired/revoked) with `allow_warn_in_prod=true` covers **every warn_causing_fingerprint**. Partial coverage is insufficient; any uncovered warn-causing fingerprint leaves the escalation intact and the final outcome is BLOCK. This rule never overrides hard-stop findings or other blocking causes.

## 6) Escalation Logic (Stage and Expiry)
- Decisions are recomputed at every stage; no stage inherits decisions from earlier stages.
- Accepted risks must explicitly list stage_scope and environment_scope.
- If an accepted risk does not cover the current stage, it is ignored.
- Expired accepted risks are ignored and generate a governance warning.
- Expiry escalation:
  - pr/main: expired accepted risk adds WARN in decision trace.
  - release/prod: expired accepted risk forces BLOCK if it covers a HIGH or CRITICAL finding.

## Precedence Rules
- Policy rules are tighten-only except that an explicitly approved Accepted Risk may prevent warn_to_block escalation for its scoped findings when allow_warn_in_prod=true.
- Accepted Risk never overrides hard-stop domains (SECRET, MALWARE, PROVENANCE) and never overrides provenance/signing hard-stops.
- Accepted Risk affects only the scoped finding fingerprints; unrelated findings or conditions may still cause BLOCK.
- Decision trace MUST record accepted_risks_applied, accepted_risks_coverage (risk_id to finding_ids), and whether allow_warn_in_prod was used.

## Deterministic Finding Ordering
All selection or ranking of findings must follow a stable total order so that top-k subsets, noise budgets, and selectors stay deterministic. The canonical order is:
1. `hard_stop` descending (`true` before `false`). (Noise budget never includes hard-stop findings, but selectors respect this precedence when they interact with mixed sets.)
2. `risk_score` descending.
3. `severity` descending, with the fixed ranking `CRITICAL > HIGH > MEDIUM > LOW > INFO > UNKNOWN`.
4. `fingerprint` lexicographically ascending as the final tie-breaker.
Noise budget ranking applies this order to the non-hard-stop scoring set. `global selector=top_findings` uses the same stable order to pick `top_n` entries, and `selector=all_high_or_critical` filters to `severity` in `{HIGH, CRITICAL}` before sorting by this order to derive matched_fingerprints.

## 7) Noise Budget Mechanism (Guardrails)
Purpose: reduce pr friction only. Noise budget MUST NOT apply to hard-stop domains.
Ranking for noise budget strictly follows the Deterministic Finding Ordering applied to the non-hard-stop scoring set.

Default behavior:
- pr: top-5 non-hard-stop findings determined by the Deterministic Finding Ordering are considered for decision.
- main/release/prod: noise budget disabled (all findings are considered). Any policy that attempts to enable noise budget for these stages is treated as a fatal policy error that triggers fail-closed behavior.

Rules:
- Noise budget is applied after scoring and before stage decision, and only for stage=pr.
- Suppressed findings remain in the decision trace and summary metrics.
- Hard-stop findings bypass noise budget and always count.

## 8) False Positives, Exceptions, Accepted Risk Governance
- False positives must be addressed via an exception or accepted risk, never by deleting findings.
- Exceptions are narrow, deterministic, time-bound rules keyed by finding signature.
- Accepted risk is a formal justification with owner, ticket, scope, approval, and expiry.
- Neither exceptions nor accepted risks can suppress hard-stop domains.
- Accepted risks must be reviewed on expiry; expired items trigger escalation (Section 6).

## 9) decision.json Schema (Authoritative)
The engine MUST output decision.json with the following structure:

- schema_version: string
- tool_version: string
- generated_at: RFC3339 timestamp
- inputs:
  - scans: array of { source_scanner, source_version, input_sha256, scan_timestamp }
  - context:
    - sha256: string
    - source: string
    - payload: { pipeline_stage, branch_type, environment, repo_criticality, exposure, change_type }
  - policy:
    - sha256: string
    - policy_version: string
    - source: string
  - accepted_risks:
    - sha256: string
    - source: string
  - These hashes ensure every decision-affecting input is traceable. When policy is optional, `policy_version` MUST be `"embedded-default"` and `policy.sha256` MUST equal the SHA-256 of the embedded default policy text. When no accepted risks file is supplied, `accepted_risks.sha256` MUST be the hash of the canonical empty representation (`[]`). Decision_trace events for ingest, policy application, and governance MUST record the same hash/source metadata so the audit trail reflects the exact inputs that shaped the decision.
- trust:
  - trust_score: number (0-100)
  - trust_signals: object with per-signal scores and raw inputs
- findings:
  - total_count: number
  - hard_stop_count: number
  - considered_count: number
  - suppressed_by_noise_budget: number
  - max_finding_risk: number
  - items: array of normalized findings with computed risk_score and hard_stop flag
    - suppressed_by_accepted_risk: boolean
    - suppressed_by_exception: boolean
    - suppressed_by_noise_budget: boolean
- scoring:
  - release_risk: number (0-100)
  - modifiers: { stage_modifier, exposure_modifier, change_modifier, trust_modifier }
- decision:
  - status: ALLOW | WARN | BLOCK
  - exit_code: 0 | 1 | 2
  - rationale: short deterministic summary
- policy:
  - policy_version: string
  - evaluated_rules: array of rule IDs with outcomes
  - exceptions_applied: array of exception IDs
  - accepted_risks_applied: array of accepted risk IDs
  - accepted_risks_coverage: array of { risk_id, finding_ids }
  - allow_warn_in_prod_applied: boolean
- recommended_next_steps:
  - array of deterministic step IDs
- decision_trace:
  - array of ordered trace events (ingest, normalize, score, policy, decision)
    - governance.applied, exception.applied, and noise_budget.applied events MUST emit:
      - `suppressed_fingerprints`: array<string> (bounded to first 20 entries) listing the fingerprints suppressed in this step.
      - `suppressed_count`: number of total suppressed fingerprints (may exceed the bounded list length).
      - `suppressed_by`: string (e.g., `accepted_risk`, `exception`, `noise_budget`) describing the suppression source.
    - These fields ensure every suppressed finding is auditable; the contained fingerprints must correspond to `decision.findings.items` where the matching `suppressed_by_*` boolean is true.
- llm_explanation (optional):
  - enabled: boolean
  - non_authoritative: true
  - content_ref: string

## Provenance & Signing: Hard-Stops vs Trust Penalties (Authoritative)
Provenance and signing controls operate on two deterministic layers so that only explicit, policy-triggered violations block a release while weaker signals only adjust trust.

1. **Hard-stop layer** emits synthetic findings with `domain=PROVENANCE`, `hard_stop=true`, `risk_score=100`, `severity=CRITICAL`, and a stable `fingerprint` derived from the hard-stop token plus the artifact identity and policy scope. These synthetic findings are normalized, traced, and evaluated before scoring and noise budgeting (see Deterministic Evaluation Order step 2); they cannot be suppressed or subject to noise budget.
2. **Trust-penalty layer** adjusts `trust_score` only when the policy does not require the signal in question. Artifact signing and provenance level influence trust_score (see Section 3), but no synthetic finding is emitted unless a hard-stop condition fires.

Canonical hard-stop conditions and their tokens:
   - `artifact_signing_status = invalid` → `PROVENANCE_INVALID_SIGNATURE`
   - `provenance_integrity_status = mismatch`/`invalid` → `PROVENANCE_MISMATCH`
   - `policy.requires_signed_artifact = true` **and** `artifact_signing_status != verified` → `PROVENANCE_UNSIGNED_ARTIFACT`
   - `policy.requires_provenance_level >= L2` **and** `provenance_level < required` → `PROVENANCE_INSUFFICIENT_LEVEL`

Trust-penalty-only cases (no synthetic finding):
   - `artifact_signing_status = unsigned`/`unknown` while the policy does **not** require a signed artifact.
   - `provenance_level = unknown` when the policy does **not** enforce a minimum level.

This separation ensures unsigned artifacts are not always just a minor penalty: they only force BLOCK when the policy requires signing or another hard-stop fails.

## 10) Deterministic recommended_next_steps
The engine produces rule-based actions only. LLM text may rephrase but cannot add actions.

| Step ID | Trigger | Action |
| --- | --- | --- |
| ROTATE_SECRET | domain=SECRET | Rotate secret, purge from history, invalidate tokens. |
| FIX_VULN | fix_available=true and severity>=MEDIUM | Upgrade to fix_version or patched release. |
| MITIGATE_NO_FIX | fix_available=false and severity>=HIGH | Apply compensating controls and open vendor ticket. |
| ADD_ACCEPTED_RISK | severity>=HIGH and justification missing | Create accepted risk record with owner and expiry. |
| VERIFY_PROVENANCE | domain=PROVENANCE | Rebuild with verified provenance and signing. |
| PIN_SCANNER | scanner_pinned=false | Pin scanner version and record in context. |
| REFRESH_SCAN | scan_freshness low | Re-run scanner to refresh data. |
| IMPROVE_TRUST | trust_score < 40 | Add missing provenance signals or protected CI. |

## 11) Example Walkthroughs

### Example A: Same HIGH CVE in pr vs prod
Input:
- Finding: HIGH severity, cvss_v3=7.5, exploit_maturity=poc, reachability=potentially, fix_available=true, dependency_scope=direct
- Context: exposure=internal, change_type=moderate
- Trust: 65 (scanner pinned, signed artifact, scan age 2 days)

Per-finding risk:
- base_score = 75
- modifiers: exploit +5, reachability +8, fix +0, dependency +5
- risk_score = 93 (clamped)

pr stage:
- stage_modifier +0, exposure +5, change +3, trust_modifier +3
- release_risk = 93 + 0 + 5 + 3 + 3 = 104 => 100
- Decision (pr): BLOCK (release_risk >= 71)

prod stage:
- stage_modifier +15, exposure +5, change +3, trust_modifier +3
- release_risk = 93 + 15 + 5 + 3 + 3 = 119 => 100
- Decision (prod): BLOCK (release_risk >= 41)

Outcome: Both stages BLOCK, but prod remains strictly gated by default WARN->BLOCK policy.

### Example B: CRITICAL CVE with no fix + justification
Input:
- Finding: CRITICAL severity, cvss_v3=9.0, exploit_maturity=functional, reachability=reachable, fix_available=false, dependency_scope=direct
- Context: exposure=internal, change_type=moderate
- Trust: 72
- Accepted risk: approved, scope=release stage, expiry in 14 days

Per-finding risk:
- base_score = 90
- modifiers: exploit +10, reachability +15, fix +5, dependency +5
- risk_score = 125 => 100

Release stage risk:
- stage_modifier +10, exposure +5, change +3, trust_modifier +3
- release_risk = 100 + 10 + 5 + 3 + 3 = 121 => 100

Decision without accepted risk: BLOCK.
Decision with accepted risk (release stage approved): WARN with required next steps:
- MITIGATE_NO_FIX
- ADD_ACCEPTED_RISK (already present, confirm expiry)

### Example C: SECRET detection hard-stop
Input:
- Finding: domain=SECRET, severity=HIGH
- Context: any stage
- Trust: any

Hard-stop rules apply:
- risk_score = 100
- hard_stop = true
- Decision: BLOCK at all stages, regardless of noise budget or accepted risk.
- recommended_next_steps: ROTATE_SECRET

## Acceptance Criteria
- [ ] Unified finding schema is fully specified with required and optional fields.
- [ ] Risk scoring model is deterministic, monotonic, and handles unknowns safely.
- [ ] Trust score computation is explicit with weights and signal mapping.
- [ ] Release risk formula includes stage, exposure, and trust modifiers.
- [ ] Decision matrices are defined for all four stages with hard-stop handling.
- [ ] Escalation logic covers stage changes and accepted risk expiry.
- [ ] Noise budget applies only to pr by default and never to hard-stop domains.
- [ ] decision.json schema is authoritative and complete.
- [ ] Deterministic recommended_next_steps are enumerated.
- [ ] All required example walkthroughs are present and consistent.
