# Core Decision Engine

Authoritative specification for the deterministic decision engine. This document defines
normalized inputs, scoring, trust, gating, and outputs. It must be internally consistent
and implementation-agnostic, and is the **single source of truth** for all normative
decision logic (hard-stop conditions, risk and trust formulas, stage matrices, noise
budget semantics, suppression behavior, and provenance handling). Other documents
(`README.md`, `docs/md/architecture.md`, `docs/md/modules.md`, `docs/md/policy-format.md`,
`docs/md/governance-accepted-risk.md`, `docs/md/llm-boundary.md`) may summarize this logic
for readability but MUST NOT redefine or partially override it.

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
  - pipeline_stage (pr, main, release, prod), environment
  - exposure, change_type
  - (optional, record-only in MVP) branch_type, repo_criticality
  - scanner_version pinning, scan_timestamp, artifact signing/provenance signals
- Policy-as-code rules and accepted risk objects.

## Context Input Schema (Authoritative)
The canonical context input is a single JSON object whose `payload` field is used by the
engine. Implementations MAY accept equivalent structures, but MUST normalize them into
this schema before evaluation.

Required fields in `context.payload`:
- `pipeline_stage`: enum (pr, main, release, prod). This is the **declared** stage; the
  effective stage used for gating may be overridden by the CLI `--stage` flag (see
  **Stage Precedence: CLI vs Context** below).
- `environment`: string (e.g., dev, staging, prod). Used for accepted risk scope checks.
- `exposure`: enum (public, internal, private, unknown).
- `change_type`: enum (high_risk, moderate, low, unknown).

Optional fields in `context.payload` (MVP):
- `branch_type`: string/enum (implementation-defined; used only as an input to
  `build_context_trust`).
- `repo_criticality`: enum (low, medium, high, unknown). Record-only in MVP and currently a telemetry placeholder with no scoring/gating impact.
- `artifact_signing_status`: enum (verified, unsigned, invalid, unknown).
- `provenance_level`: enum (level3+, level2, level1, none, unknown).
- `branch_protected`: boolean (used to derive `build_context_trust` when present).
- `scanner_version`: string (used to evaluate `scanner_pinned`).

Context loaders MUST:
- Validate that `pipeline_stage` is one of the canonical tokens or fail validation.
- Default missing optional fields into the “unknown” buckets described in the trust score
  table rather than inventing new enums or semantics.
Other documents (for example, `docs/md/architecture.md`, `docs/md/modules.md`, and
`docs/md/policy-format.md`) MUST treat this section as the single source of truth for the
context payload shape and refer to it rather than re-stating field lists.

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
| finding_id | string | yes | Stable deterministic ID (hash of key fields) supplied by the scanner; canonical `fingerprint` (below) is used for gating and tracing. |
| fingerprint | string | yes | Canonical deterministic hash of normalized key fields (see derivation below); used by selectors, noise budgets, accepted risks, warn coverage, and decision-trace metadata. |
| domain | enum | yes | VULNERABILITY, SECRET, MALWARE, LICENSE, CONFIG, PROVENANCE. |
| severity | enum | yes | CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN. |
| title | string | yes | Short, human-readable label. |
| description | string | yes | Short summary; no raw secrets. |
| source_scanner | string | yes | e.g., trivy. |
| source_version | string | yes | Pinned scanner version if known; normalized to `"unknown"` when absent and recorded in the trace. |
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
- source_version is required; if the scanner output omits it, normalize to a deterministic sentinel (for example, `"unknown"`) and emit a `context.source_version_missing` trace event that records the input reference so the missing data remains auditable.

Optional with safe defaults:
- cve_id, cvss_v3, fix_available, fix_version, exploit_maturity, reachability, dependency_scope, license_type, confidence, tags, vendor_status, remediation_hint.
- Missing optional fields are treated as unknown and handled per risk scoring modifiers.

### Canonical Fingerprint Derivation
Normalized findings MUST include `fingerprint`. It is derived by concatenating the following normalized fields in this exact order, separated by the pipe (`|`) character, lowercased, and trimmed:

1. `domain`
2. `location.path` (or the most specific location identity available, such as `location.package` or `location.target`)
3. `evidence_ref`
4. `title`
5. `severity`
6. `source_scanner`
7. `source_version`
8. `cve_id` (use empty string when absent)
9. `input_sha256`

Hash the resulting string with SHA-256 and encode it as a lowercase hex string. This canonical fingerprint differs from `finding_id` in that `finding_id` tracks the original scanner detection, whereas `fingerprint` stabilizes deterministic consumers such as selectors, noise budgets, accepted risks, warn_causing sets, and every decision_trace event that references findings.

`fingerprint` MUST be recorded in `decision.findings.items` and echo the same value in any `decision_trace` event that lists suppressed, matched, or warn-causing entries, including governance events and `policy.require_accepted_risk.missing`.

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

### Trust Signal Input Mapping (MVP)
The following context.json and scanner metadata fields supply each trust signal. Implementations MUST use this mapping; ad hoc mappings are not permitted.

| Signal | Source | Field or Condition | Value Mapping |
| --- | --- | --- | --- |
| scanner_pinned | context.payload | scanner_version present and matches scan metadata | present+match=1.0, absent/mismatch/unknown=0.2 |
| scan_freshness | scan metadata | scan_timestamp age vs now | <=24h=1.0, <=7d=0.7, <=30d=0.4, >30d/unknown=0.2 |
| input_integrity | ingest | input_sha256 computed and recorded | computed=1.0, missing=0.2, mismatch=0.0 |
| artifact_signing | context.payload | artifact_signing_status | verified=1.0, unsigned/unknown=0.2, invalid=0.0 |
| provenance_level | context.payload | provenance_level | level3+=1.0, level2=0.7, level1=0.4, none/unknown=0.2 |
| build_context_trust | context.payload | branch_type or branch_protected | protected=1.0, unprotected/unknown=0.3 |

When a field is absent from context.json or scan metadata, the signal defaults to the unknown/low bucket (0.2 for scanner_pinned, scan_freshness, input_integrity, artifact_signing, provenance_level; 0.3 for build_context_trust). The context.payload schema is defined by the context input format; optional fields may be omitted and trigger the default.

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
Release risk is computed over the **scoring set** (after governance suppressions and before PR-only noise budget). The canonical pipeline and ordering are defined in **Deterministic Evaluation Order** below; this section summarizes the numeric computation only:

1) Compute per-finding `risk_score` for each finding in the scoring set (hard-stops are handled separately and force BLOCK).
2) Apply the PR-only noise budget (stage=pr only) to select the non-hard-stop findings considered for `max_finding_risk`.
3) `max_finding_risk = max(risk_score of considered findings; 0 if none)`.
4) Compute `release_risk = clamp(max_finding_risk + stage_modifier + exposure_modifier + change_modifier + trust_modifier, 0, 100)`.
5) Apply the stage decision matrix and escalation logic to derive ALLOW/WARN/BLOCK and exit code.
6) Emit `decision.json` and the ordered `decision_trace`, including hashes for all decision-affecting inputs and visibility of suppressed findings.

## Canonical Deterministic Evaluation Order (Authoritative)
1) Ingest, validate, and hash every decision-affecting input (scanner outputs, context, policy, accepted risks); fatal errors follow the prescribed fail-closed behavior for each stage.
2) Normalize inputs into the Unified Finding Schema and derive stable fingerprints for each finding.
3) Detect hard-stop conditions (see **Hard-Stop Conditions (Authoritative)** below); these findings bypass governance and noise budget steps and always force BLOCK.
4) Apply governance: valid exceptions and Accepted Risks with `suppress_from_scoring` effects remove findings from the scoring set, while each governance event records the suppressed fingerprints and counts in the trace/report. Expired or invalid accepted risks do not contribute to scoring (although their expiry escalation rules still apply).
5) Score only the remaining scoring set, computing per-finding risk_score and the trust modifiers defined in Section 3.
6) Apply the PR-only noise budget to the scored scoring set (hard-stop findings are excluded by definition); any noise budget configuration targeting main/release/prod is a fatal policy error.
7) Evaluate policy rules in deterministic order, including selectors and tightening actions.
8) Apply the stage matrix plus escalation logic (prod warn_to_block and allow_warn_in_prod coverage).
9) Enforce governance floors such as “Accepted Risk covering HIGH/CRITICAL findings mandates at least WARN.”
10) Emit `decision.json`, `decision_trace`, `summary.md`, and other optional reports, ensuring every suppressed finding remains visible with its `suppressed_by_*` flags.
11) Optionally generate an LLM explanation artifact using sanitized, non-authoritative inputs derived from the finalized trace.

Suppressed findings continue to appear in `decision.findings.items` with their suppression flags, and every governance event (exception, accepted risk) records the bounded fingerprint list and suppressed count so the audit trail remains complete even though those findings no longer feed into scoring.

## Hard-Stop Conditions (Authoritative)
Hard-stop behavior is **condition-based**, not purely domain-based. The engine inspects
normalized findings and synthetic conditions, and then marks specific findings as
`hard_stop=true`. Domains are an input into these conditions, but domain alone is
insufficient: some domains (for example, PROVENANCE) may emit both hard-stop and
non-hard-stop findings depending on the triggering condition.

The following hard-stop conditions are authoritative and exhaustive:

| Hard-stop condition | Type | Domain | Severity (normalized) | Notes |
| --- | --- | --- | --- | --- |
| SECRET finding | domain-based | SECRET | As provided by the scanner/normalization; hard-stop behavior is independent of severity. | Any normalized finding with `domain=SECRET` is treated as a hard-stop condition. |
| MALWARE finding | domain-based | MALWARE | As provided by the scanner/normalization; hard-stop behavior is independent of severity. | Any normalized finding with `domain=MALWARE` is treated as a hard-stop condition. |
| Synthetic provenance violation | synthetic | PROVENANCE | CRITICAL | Synthetic findings emitted by the provenance/signing hard-stop layer, including `PROVENANCE_INVALID_SIGNATURE`, `PROVENANCE_MISMATCH`, `PROVENANCE_UNSIGNED_ARTIFACT`, and `PROVENANCE_INSUFFICIENT_LEVEL`. These are emitted only when deterministic provenance or signing requirements are violated. |
| UNKNOWN_DOMAIN_MAPPING | synthetic | CONFIG | HIGH | Synthetic finding emitted when a source scanner domain cannot be mapped into the canonical `domain` enumeration. Implemented as a normalized finding with `title=UNKNOWN_DOMAIN_MAPPING`. |

For all hard-stop conditions above, the following invariants apply:

- Hard-stop conditions are **unsuppressible**: exceptions and Accepted Risks MUST NOT remove them from the scoring set or downgrade their effect.
- Hard-stop conditions **bypass the noise budget**: they are never excluded or down-ranked by PR-only noise budgeting.
- Hard-stop conditions **always result in BLOCK** at every stage (pr, main, release, prod), regardless of `risk_score`, `release_risk`, `trust_score`, or policy rules.
- Hard-stop findings MUST still be represented in `decision.findings.items` with `risk_score=100` and `hard_stop=true`, and MUST contribute to `hard_stop_count`.

Engines and policies MUST treat this section as the single source of truth for which
conditions are hard-stops and how they behave. Module- and policy-level documents may
describe how a given hard-stop condition is detected or surfaced, but MUST NOT redefine
or partially re-list hard-stop conditions.

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

## Governance and Escalation Summary (Non-Numeric Tightening)
This section summarizes all non-numeric mechanisms that can tighten a decision after
`release_risk` and the stage decision matrices have been computed. It is a reading aid;
the normative behavior is defined in the sections referenced below.

- **Hard-stop conditions (Section "Hard-Stop Conditions (Authoritative)")**
  - Any hard-stop finding always forces `decision.status=BLOCK` and `exit_code=2` at all
    stages, regardless of `release_risk`, `trust_score`, or policy rules.
  - Hard-stops are never suppressible, never subject to noise budget, and take precedence
    over all other governance or policy mechanisms.

- **Governance WARN floor (Sections "False Positives, Exceptions, Accepted Risk Governance"
  and `docs/md/governance-accepted-risk.md`)**
  - When a valid Accepted Risk record actively covers at least one HIGH/CRITICAL,
    non-hard-stop finding in the current stage/environment, the final decision MUST be at
    least WARN, even if numeric thresholds would otherwise allow ALLOW.

- **Prod WARN→BLOCK escalation and allow_warn_in_prod coverage (Section
  "Prod WARN Escalation and allow_warn_in_prod Coverage")**
  - At stage=prod, a WARN outcome from the stage matrix is escalated to BLOCK unless every
    `warn_causing_fingerprint` is covered by an active Accepted Risk with
    `allow_warn_in_prod=true`.
  - Partial coverage (some but not all warn-causing fingerprints) is insufficient; BLOCK
    remains.

- **Expiry-based escalation (this section and `docs/md/governance-accepted-risk.md`)**
  - Expired or revoked Accepted Risks are never treated as active for suppression or prod
    WARN coverage.
  - Nevertheless, if such a record would have covered a HIGH/CRITICAL finding:
    - pr/main: the final decision is tightened to at least WARN.
    - release/prod: the final decision is forced to BLOCK.

- **require_accepted_risk gates (Section "Noise Budget Mechanism (Guardrails)" and
  `docs/md/policy-format.md`)**
  - When a policy rule with `require_accepted_risk` matches and there is no active,
    in-scope Accepted Risk covering every required fingerprint:
    - pr: the outcome is tightened to at least WARN.
    - main/release/prod: the outcome is tightened to at least BLOCK.

- **Fatal errors and fail-closed behavior (`docs/md/modules.md`)**
  - For stage=main/release/prod, any fatal ingest/normalize/score/policy/accepted-risk
    error forces BLOCK with a minimal decision artifact.
  - For stage=pr, fatal errors produce WARN (with low-trust defaults) only when scanner
    input is present and hashable; otherwise they also result in BLOCK.

These mechanisms are cumulative and always tighten or maintain the severity of an outcome;
none of them can weaken a BLOCK that is already mandated by hard-stops or numeric gating.

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
Noise budget ranking applies this order to the non-hard-stop scoring set. `global selector.type=top_findings` uses the same stable order to pick `top_n` entries, and `selector.type=all_high_or_critical` filters to `severity` in `{HIGH, CRITICAL}` before sorting by this order to derive matched_fingerprints. Because every `fingerprint` follows the canonical derivation above, these tie-breakers reproduce the same identifiers that appear in `decision.findings.items` and the governance events that consume them.

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
  - The **considered set** is the subset of the scoring set that survives the PR-only noise budget. Policy selectors that specify `scope: considered_set` operate on this post-noise-budget subset; selectors without this flag always operate on the pre-budget scoring set. The considered set is undefined for stages other than `pr` because noise budgeting is disabled elsewhere. This definition is the authoritative signal used by `docs/md/policy-format.md` to keep `require_accepted_risk` selectors deterministic.

## 8) False Positives, Exceptions, Accepted Risk Governance
- False positives must be addressed via an exception or accepted risk, never by deleting findings.
- Exceptions are narrow, deterministic, time-bound rules keyed by finding signature.
- Accepted risk is a formal justification with owner, ticket, scope, approval, and expiry.
- Neither exceptions nor accepted risks can suppress hard-stop domains.
- Accepted risks must be reviewed on expiry; expired items trigger escalation (Section 6).

## 9) Suppression and Decision Trace Invariants (Authoritative)
This section defines the canonical behavior for any mechanism that removes findings from
the scoring set (exceptions, accepted risks, PR-only noise budget) and how those actions
are reflected in `decision.json` and `decision_trace`.

### Suppression Semantics
- Suppression is **logical only**: suppressed findings remain present in
  `decision.findings.items` and in the trace; they are excluded only from scoring sets.
- Hard-stop conditions are **never suppressible** and **never subject to noise budget**.
- Exceptions and accepted risks may only suppress **non-hard-stop** findings.
- PR-only noise budget may only suppress non-hard-stop findings for `stage=pr` and never
  for `main`, `release`, or `prod`. Any attempt to enable a noise budget outside `pr`
  is a fatal policy error (see **Fatal Errors and Fail-Closed Defaults (Authoritative)** in
  `docs/md/modules.md`).

### Suppression Precedence (Authoritative)
When multiple suppression mechanisms could apply to the same non-hard-stop finding
within a single evaluation pass, the engine MUST apply the following precedence order
and set only one suppression flag on the finding:

1. Accepted risk (governance-driven, time-bound justification)
2. Exception (false-positive focused)
3. PR-only noise budget

Concretely:
- If an active, in-scope Accepted Risk with an effect that suppresses scoring matches a
  finding, the finding is marked `suppressed_by_accepted_risk=true` and MUST NOT also be
  marked as suppressed by an exception or the noise budget, even if those mechanisms
  would otherwise match.
- If no Accepted Risk applies but a valid exception matches, the finding is marked
  `suppressed_by_exception=true` and MUST NOT also be marked as suppressed by the noise
  budget.
- Only findings that are not covered by either Accepted Risks or exceptions may be
  suppressed by the PR-only noise budget, in which case they are marked
  `suppressed_by_noise_budget=true`.

Decision_trace events MUST remain aligned with this precedence:
- A given finding’s fingerprint MUST appear under `suppressed_fingerprints` in exactly
  one of `governance.applied` (accepted risk), `exception.applied`, or
  `noise_budget.applied` for a single evaluation, matching its chosen suppression flag.
- Policy and governance documents MUST NOT redefine this precedence order; if they
  describe suppression, they MUST reference this section.

### Per-Finding Flags
- Every normalized finding in `decision.findings.items` MUST expose:
  - `suppressed_by_accepted_risk: boolean`
  - `suppressed_by_exception: boolean`
  - `suppressed_by_noise_budget: boolean`
- At most one of these flags should be true for any given suppression mechanism in a
  single evaluation pass; if multiple mechanisms could apply, governance MUST define and
  document precedence but still keep only one suppression cause per finding.

### Trace Events and Fingerprint Alignment
- For every suppression-producing mechanism, the engine MUST emit a corresponding
  `decision_trace` event:
  - `governance.applied` (accepted risks)
  - `exception.applied` (exceptions)
  - `noise_budget.applied` (PR-only noise budget)
- Each such event MUST include:
  - `suppressed_fingerprints`: array<string> of canonical fingerprints, bounded to the
    first 20 entries.
  - `suppressed_count`: total number of suppressed fingerprints (may exceed the bounded
    list length).
  - `suppressed_by`: string describing the source (`accepted_risk`, `exception`,
    `noise_budget`).
- The `suppressed_fingerprints` in trace events MUST match the `fingerprint` values of
  findings whose corresponding `suppressed_by_*` flag is true in `decision.findings.items`.
  This alignment is mandatory for auditability and for downstream tooling to reconcile
  per-finding state with governance events.

### Governance Floors and Expiry
- Accepted risks that cover HIGH/CRITICAL findings may impose a WARN floor or influence
  prod WARN coverage, but they **never** change the suppression invariants above.
- Expired or revoked accepted risks are **never** treated as active for suppression or
  WARN-coverage decisions; they are reflected only via governance warnings and
  expiry-based escalation (Section 6).

## 10) decision.json Schema (Authoritative)
The engine MUST output decision.json with the following structure:

- schema_version: string
- tool_version: string
- generated_at: RFC3339 timestamp
- inputs:
  - scans: array of { source_scanner, source_version, input_sha256, scan_timestamp }
  - context:
    - sha256: string
    - source: string
    - payload: { pipeline_stage, environment, exposure, change_type, (optional) branch_type, (optional) repo_criticality }
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
    - finding_id: string
    - fingerprint: string
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
    - `suppressed_fingerprints`: array<string> (bounded to first 20 entries) listing the canonical fingerprints suppressed in this step.
    - `suppressed_count`: number of total suppressed fingerprints (may exceed the bounded list length).
    - `suppressed_by`: string (e.g., `accepted_risk`, `exception`, `noise_budget`) describing the suppression source.
    - These fields ensure every suppressed finding is auditable; the contained fingerprints must match the `fingerprint` recorded in `decision.findings.items` for the suppressed findings.
  - Redaction metadata for LLM inputs MUST be recorded in a `redaction.events` array inside the decision_trace with objects containing at least:
    - `event_id`: string (unique identifier for the redaction action).
    - `timestamp`: RFC3339 time when the redaction was applied.
    - `redacted_field`: string (path in the LLM payload that was stripped or masked).
    - `reason`: string (brief rationale for the removal).
    - `sanitized_ref`: string (reference to the sanitized artifact or field that was sent to the LLM).
    - `original_hash` (optional): hash of the original field content to prove it was seen.
    These entries satisfy the LLM boundary requirement to “record all redactions” and provide a deterministically referenceable audit trail.
- llm_explanation (optional):
  - enabled: boolean
  - non_authoritative: true
  - content_ref: string

### MVP vs Recommended Trace and Audit Detail
For **MVP compliance**, the following decision_trace and audit elements are mandatory:
- Presence of a `decision_trace` array covering ingest, normalize, score, policy, and
  decision events.
- For each suppression-producing mechanism
  (`governance.applied`, `exception.applied`, `noise_budget.applied`):
  - `suppressed_fingerprints` (bounded to at least the first 20 entries).
  - `suppressed_count`.
  - `suppressed_by`.
- For each LLM redaction event in `decision_trace.redaction.events`:
  - `event_id`, `timestamp`, `redacted_field`, `reason`, `sanitized_ref`.

The following fields and additional events are **strongly recommended** but not required
for the initial 2–3 week MVP implementation:
- `original_hash` in redaction events.
- Rich, engine-emitted governance floor and escalation events beyond the minimum needed to
  reconstruct decisions (for example, specialized `governance.floor.warn` and
  `governance.expired_escalation` event types).
- Extended audit trails on accepted risk objects beyond the minimal lifecycle information
  required in `docs/md/governance-accepted-risk.md`.

Later versions SHOULD implement the recommended fields and events for stronger
auditability, but an MVP implementation that satisfies the mandatory items above is
considered conformant.

## Provenance & Signing: Hard-Stops vs Trust Penalties (Authoritative)
**MVP scope:** Provenance hard-stops are MVP-in-scope. Policy fields `requires_signed_artifact` and `requires_provenance_level` (in policy or context) control when synthetic PROVENANCE findings are emitted. When absent, only trust penalties apply; no hard-stop is emitted for unsigned/unknown provenance.

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

## 11) Deterministic recommended_next_steps
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

## 12) Example Walkthroughs

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

### Example D: Accepted Risk with suppress_from_scoring + WARN floor
Inputs:
- Findings:
  - F1: HIGH severity VULNERABILITY, `fingerprint=fp-high-1`
  - F2: MEDIUM severity VULNERABILITY, `fingerprint=fp-med-1`
- Context: stage=main, exposure=internal, change_type=moderate
- Trust: 70
- Accepted risk:
  - risk_id=AR-001, `status=active`, `effects=["suppress_from_scoring"]`
  - stage_scope includes main; environment_scope includes current environment
  - finding_selector matches `fingerprint=fp-high-1` only

Behavior:
- During governance (step 4 of **Canonical Deterministic Evaluation Order (Authoritative)**), F1 is removed from the scoring set because AR-001 is active and includes `suppress_from_scoring`.
- F2 remains in the scoring set and contributes to `findings.considered_count` and `scoring.max_finding_risk`.
- Because AR-001 actively covers a HIGH-severity finding (F1) in the current stage/environment, the **Precedence Rules** and governance document’s WARN floor require the final decision to be at least WARN even if `release_risk` computed from F2 alone would otherwise allow ALLOW.

decision.json highlights:
- `findings.total_count = 2`
- `findings.considered_count = 1` (F2 only)
- `findings.items`:
  - F1: `suppressed_by_accepted_risk=true`, `risk_score=100` (still recorded), `hard_stop=false`
  - F2: `suppressed_by_accepted_risk=false`
- `scoring.max_finding_risk` reflects only F2.
- `decision.status = WARN`, `decision.exit_code = 1` (due to WARN floor, not just numeric thresholds).
- `policy.accepted_risks_applied` includes `AR-001`, and `policy.accepted_risks_coverage` links `risk_id=AR-001` to `finding_ids` / `fingerprints` including `fp-high-1`.

decision_trace highlights:
- `governance.applied` event listing `suppressed_fingerprints=["fp-high-1"]` and `suppressed_by="accepted_risk"`.
- A governance-floor event (e.g., `governance.floor.warn`) documenting that coverage of a HIGH finding by AR-001 forced at least WARN for this stage.

### Example E: Expired Accepted Risk forcing BLOCK in release/prod
Inputs:
- Findings:
  - F3: CRITICAL severity VULNERABILITY, `fingerprint=fp-crit-1`
- Context: stage=release (similar behavior applies to prod), exposure=internal, change_type=moderate
- Trust: 80
- Accepted risk:
  - risk_id=AR-002, `status=expired` or `status=active` but `now >= expires_at`
  - stage_scope includes release; environment_scope includes current environment
  - finding_selector matches `fingerprint=fp-crit-1`

Behavior:
- At CLI validation time, AR-002 is treated as expired and therefore **inactive** for suppression, WARN floor, or prod WARN coverage (see governance **Expiry-Based Escalation** and this document’s **Escalation Logic (Stage and Expiry)**).
- During governance, F3 is **not** suppressed from the scoring set because AR-002 is no longer active.
- Release risk computed from F3 and context exceeds the BLOCK threshold.
- Because an expired accepted risk would have covered a CRITICAL finding at release/prod, expiry escalation forces BLOCK even if other factors (e.g., trust) might have allowed WARN.

decision.json highlights:
- `findings.total_count = 1`, `findings.considered_count = 1`.
- `findings.items[0]` shows `suppressed_by_accepted_risk=false`.
- `policy.accepted_risks_applied` does **not** include `AR-002` (it is inactive).
- `decision.status = BLOCK`, `decision.exit_code = 2`.

decision_trace highlights:
- An `accepted_risk.status_change` or `governance.expired` event referencing `risk_id=AR-002`, `status=expired`, and `matched_fingerprints` including `fp-crit-1`.
- A corresponding escalation event (e.g., `governance.expired_escalation`) indicating that expiry of AR-002 at release/prod forced BLOCK, referencing the same fingerprint and stage.

### Example F: Partial prod WARN coverage still escalates to BLOCK
Inputs:
- Findings in scoring set (all non-hard-stop):
  - F4: HIGH severity VULNERABILITY, `fingerprint=fp-high-a`
  - F5: HIGH severity VULNERABILITY, `fingerprint=fp-high-b`
- Context: stage=prod, exposure=public, change_type=high_risk
- Trust: 75
- Accepted risk:
  - risk_id=AR-003, `status=active`, `allow_warn_in_prod=true`
  - stage_scope includes prod; environment_scope includes current environment
  - finding_selector matches only `fingerprint=fp-high-a`

Behavior:
- After scoring and governance, both F4 and F5 remain in the scoring set (no suppress_from_scoring effects).
- The **Deterministic Finding Ordering** identifies both findings as non-hard-stop with `severity >= HIGH`, so the **warn-causing set** for prod consists of fingerprints `{fp-high-a, fp-high-b}`.
- AR-003 covers only `fp-high-a`. Because not **every** `warn_causing_fingerprint` is covered by an active accepted risk with `allow_warn_in_prod=true`, prod WARN→BLOCK escalation remains in effect.
- If the stage decision matrix initially yields WARN, the global prod escalation upgrades the final decision to BLOCK.

decision.json highlights:
- `findings.total_count = 2`, `findings.considered_count = 2`.
- `policy.accepted_risks_applied` includes `AR-003`, and `policy.accepted_risks_coverage` maps `AR-003` to `fingerprints=["fp-high-a"]` only.
- `policy.allow_warn_in_prod_applied = false` because not all warn-causing fingerprints are covered.
- `decision.status = BLOCK`, `decision.exit_code = 2` (due to WARN→BLOCK escalation).

decision_trace highlights:
- A `policy.warn_causing_set` event listing `warn_causing_fingerprints=["fp-high-a","fp-high-b"]`.
- A `policy.accepted_risk.applied` event for `risk_id=AR-003` showing `matched_fingerprints=["fp-high-a"]`.
- A prod escalation event (e.g., `policy.warn_to_block.escalated`) that references the unmatched fingerprint `fp-high-b` and records that `allow_warn_in_prod` could not be applied because coverage was partial.

## Acceptance Criteria
- [ ] Unified finding schema is fully specified with required and optional fields.
- [ ] Risk scoring model is deterministic, monotonic, and handles unknowns safely.
- [ ] Trust score computation is explicit with weights and signal mapping.
- [ ] Release risk formula includes stage, exposure, and trust modifiers.
- [ ] Decision matrices are defined for all four stages with hard-stop handling.
- [ ] Escalation logic covers stage changes and accepted risk expiry.
- [ ] Noise budget applies only to pr by default and never to hard-stop domains.
- [ ] Suppression and decision trace invariants are explicitly defined and referenced by other docs.
- [ ] decision.json schema is authoritative and complete.
- [ ] Deterministic recommended_next_steps are enumerated.
- [ ] All required example walkthroughs are present and consistent.
