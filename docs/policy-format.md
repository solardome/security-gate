# Policy Format

This document defines the minimal policy-as-code format used by security-gate. It is
deterministic, stage-aware, and consistent with `docs/core-decision-engine.md`.

## Purpose
- Define rule structure and evaluation behavior.
- Provide stage-aware conditions and trust-based tightening.
- Specify exception objects (false positives) with scope and expiry.
- Specify accepted risk objects (justified, time-bound) for policy evaluation.

## Format Overview
- Declarative JSON or YAML.
- All policies are local files; no network dependencies.
- The base decision matrix and scoring model are fixed by
  `docs/core-decision-engine.md`. Policy rules may only **tighten** decisions; accepted risk handling follows Precedence Rules.
- Noise budget configuration is limited to `stage=pr` in the MVP. Any policy that attempts to enable noise budgeting for `main`, `release`, or `prod` is treated as a fatal policy error for those stages; such policies must not be shipped with the MVP.

## Provenance & Signing Controls
Policy requirements such as `requires_signed_artifact=true` or `requires_provenance_level>=L2` are enforced deterministically in two layers:
1. **Hard-stop synthetic findings** (`domain=PROVENANCE`, `hard_stop=true`, `risk_score=100`) are emitted for explicit violations (invalid signatures, provenance mismatches, unsigned artifacts when signing is required, insufficient provenance level). These findings bypass governance suppressions and noise budgets and are evaluated before scoring (see Deterministic Evaluation Order step 3).
2. **Trust penalties** only adjust `trust_score` (artifact signing and provenance level signals) when the policy does **not** demand the signal. Unsigned or unknown provenance data therefore do **not** automatically emit a hard stop—they remain penalties on trust_score unless the policy requires them.

All policy rules observe a deterministic scoring set that excludes hard-stop findings, and governance/accepted risk never suppresses those synthetic provenance findings.

## Top-Level Structure
- policy_version: string
- rules: array of Rule
- exceptions: array of Exception (optional)
- metadata: object (optional)

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

## Rule Structure
A rule has deterministic conditions and tightening actions.

Required fields:
- id: string (unique)
- description: string
- stage_scope: array of stages (pr, main, release, prod)
- when: object of conditions (all must match)
- then: object of actions

Optional fields:
- enabled: boolean (default true)
- tags: array of strings

### Conditions (when)
Supported condition keys:
- release_risk_gte, release_risk_lte
- trust_score_gte, trust_score_lt
- max_finding_risk_gte, max_finding_risk_lte
- domain_in (list of domains)
- severity_in (list of severities)
- change_type_in (list)
- exposure_in (list)
- fix_available_in (list: true, false, unknown)
- has_hard_stop (boolean)

### Actions (then)
Actions must be deterministic and may only tighten decisions (see Precedence Rules for the accepted risk exception to warn_to_block).
- decision: ALLOW | WARN | BLOCK (tightening only; never override hard-stop)
- warn_to_block: boolean (explicitly enforce WARN -> BLOCK in scoped stages)
- noise_budget_top_k: integer (pr only; enabling the field for other stages is a fatal policy error; applied at step 6 of Deterministic Evaluation Order)
- add_required_steps: array of deterministic step IDs (from core decision engine)
- require_accepted_risk: object (requires a valid accepted risk for deterministically derived matched_fingerprints)
  - selector: object (required)
    - type: enum (top_findings | all_high_or_critical)
    - top_n: integer (only for type=top_findings; default=1; bounds 1..10)
  - scope: enum (scoring_set | considered_set) (default=scoring_set)
    - scoring_set: derive fingerprints after governance suppressions and before PR-only noise budget
    - considered_set: derive fingerprints after PR-only noise budget (stage=pr only)

Selector semantics (MVP):
- `all_high_or_critical`: select all non-hard-stop findings in the scoring set with severity in {HIGH, CRITICAL}.
- `top_findings`: select the first `top_n` non-hard-stop findings by the canonical Deterministic Finding Ordering.
- The resulting fingerprint list is the rule’s `matched_fingerprints` and is used to enforce `require_accepted_risk` (see enforcement below).

Enforcement (MVP):
- A rule with `require_accepted_risk` is evaluated at step 7 of the Deterministic Evaluation Order.
- If the rule’s `when` conditions match and **no valid Accepted Risk** covers **every** `matched_fingerprints` produced by the selector (respecting stage/environment scope and expiry), the policy engine MUST tighten the outcome to:
  - `decision=BLOCK` for stage=main/release/prod
  - `decision=WARN` for stage=pr
- The decision_trace MUST include a `policy.require_accepted_risk.missing` event with the bounded fingerprint list and total count, and `recommended_next_steps` MUST include `ADD_ACCEPTED_RISK`.

## Exception Objects (False Positives)
Exceptions suppress known false positives. They are always time-bound and scoped.

Required fields:
- id: string (unique)
- description: string
- finding_selector: object (deterministic match criteria)
- stage_scope: array of stages
- environment_scope: array (e.g., dev, staging, prod)
- expires_at: RFC3339 timestamp
- owner: string
- rationale: string

Supported finding_selector keys (all match if present):
- domain
- cve_id
- title_contains
- location_contains
- source_scanner
- severity

Rules:
- Exceptions never apply to hard-stop domains.
- Expired exceptions are ignored and recorded as governance warnings.
- Exceptions suppress findings from decision scoring but keep them in the trace.

## Accepted Risk Objects (Justified Risk Acceptance)
Accepted risk objects are defined in `docs/governance-accepted-risk.md` and are
provided as a local file. This policy format references the same schema.

Rules:
- Accepted risks are time-bound and scoped by stage and environment.
- Accepted risks cannot apply to hard-stop domains.
- Accepted risks may allow WARN in prod **only if** explicitly stated.

## Deterministic Evaluation Order
The policy module observes the same canonical order defined in `docs/core-decision-engine.md` and must never imply a different sequence:
1) Ingest, validate, and hash every decision-affecting input (scanner outputs, context, policy, accepted risks).
2) Normalize inputs into the Unified Finding Schema and derive stable fingerprints.
3) Detect hard-stop conditions (SECRET, MALWARE, PROVENANCE, UNKNOWN_DOMAIN_MAPPING, synthetic provenance findings); these findings are unsuppressible by definition.
4) Apply governance: valid exceptions and Accepted Risks with `suppress_from_scoring` effects remove findings from the scoring set while each governance event records suppressed fingerprints/counts; expired/invalid accepted risks do not affect scoring (but still respect their escalation rules).
5) Score only the remaining scoring set with the risk_score and trust modifiers outlined in the core engine.
6) Apply the PR-only noise budget to the scored scoring set; hard-stop findings are excluded and any policy enabling noise budgeting for main/release/prod is a fatal error.
7) Evaluate policy rules deterministically (selectors/tightening actions referencing the same ordering).
8) Apply the stage matrix plus escalation logic (prod warn_to_block and allow_warn_in_prod coverage).
9) Enforce governance floors (e.g., HIGH/CRITICAL-matching accepted risks mandate at least WARN).
10) Emit `decision.json`, `decision_trace`, `summary.md`, and optional reports, ensuring suppressed findings remain visible with their suppression metadata.
11) Optionally serve sanitized data to the non-authoritative LLM explanation layer.

## Deterministic Finding Ordering for Selectors and Noise Budget
Selectors, selectors-driven suppressions (e.g., require_accepted_risk), and the PR-only noise budget must reuse a single stable ordering so that results stay deterministic. The canonical order is:
1. `hard_stop` descending (`true` before `false`), though noise budget explicitly excludes hard-stop findings.
2. `risk_score` descending.
3. `severity` descending, using the fixed ranking `CRITICAL > HIGH > MEDIUM > LOW > INFO > UNKNOWN`.
4. `fingerprint` lexicographically ascending as the final tie-breaker.
`noise_budget_top_k` ranking applies these rules to the non-hard-stop scoring set. `selector=top_findings` selects the `top_n` entries by the same order, and `selector.type=all_high_or_critical` first filters to severity `{HIGH, CRITICAL}` before sorting by this order to derive `matched_fingerprints`.

## MVP vs v2: Noise Budget and Selectors
- MVP: Noise budget configuration is limited to `stage=pr` only. Selectors or suppression logic that rely on `noise_budget_top_k` must respect the deterministic ordering above and must not be extended to main/release/prod in the MVP.
- v2: Optional main-stage noise budget extensions and more advanced selector configurations (e.g., multi-stage selectors or finer-grained require_accepted_risk filters) can be evaluated later, but they must keep the ordering deterministic and the existing failure-safe behavior for stage-specific gating.

## Prod WARN Escalation and allow_warn_in_prod Coverage
Prod warn_to_block escalation is global. Define warn_causing_fingerprints as the fingerprints of:
1. All non-hard-stop findings in the scoring set with `severity >= HIGH`.
2. If severity data is missing, the single top finding determined by the Deterministic Finding Ordering.
`allow_warn_in_prod=true` only prevents WARN → BLOCK when a valid Accepted Risk (active stage_scope includes prod, environment matches, not expired/revoked) covers every warn_causing_fingerprint. Partial coverage leaves escalation intact and the policy still records BLOCK. Hard-stop findings remain unaffected.

## Precedence Rules
- Policy rules are tighten-only except that an explicitly approved Accepted Risk may prevent warn_to_block escalation for its scoped findings when allow_warn_in_prod=true.
- Accepted Risk never overrides hard-stop domains (SECRET, MALWARE, PROVENANCE) and never overrides provenance/signing hard-stops.
- Accepted Risk affects only the scoped finding fingerprints; unrelated findings or conditions may still cause BLOCK.
- When a finding is suppressed by an accepted risk, exception, or noise budget, its normalized record must set the matching `suppressed_by_*` boolean and the corresponding `governance.applied`, `exception.applied`, or `noise_budget.applied` event in the decision_trace must list the suppressed fingerprints (bounded to 20 entries) plus the total suppressed count. This ensures the per-finding suppression flags recorded in `decision.findings.items` align with the auditable trace of suppressed fingerprints.
- Decision trace MUST record accepted_risks_applied, accepted_risks_coverage (risk_id to finding_ids), and whether allow_warn_in_prod was used.

## Example Rules (YAML)
Below are example rules demonstrating stage-aware tightening and trust-based gating.

```yaml
policy_version: "1"
rules:
  - id: R-PROD-WARN-BLOCK
    description: Escalate WARN to BLOCK in prod unless accepted risk allows WARN.
    stage_scope: [prod]
    when:
      release_risk_gte: 0
    then:
      warn_to_block: true

  - id: R-LOW-TRUST-BLOCK
    description: Block main, release, and prod when trust is very low.
    stage_scope: [main, release, prod]
    when:
      trust_score_lt: 20
    then:
      decision: BLOCK

  - id: R-PUBLIC-RELEASE-TIGHTEN
    description: Tighten release gating for public exposure.
    stage_scope: [release]
    when:
      exposure_in: [public]
      release_risk_gte: 40
    then:
      decision: BLOCK

  - id: R-STRONG-COPYLEFT-PROD
    description: Block strong copyleft licenses in prod.
    stage_scope: [prod]
    when:
      domain_in: [LICENSE]
      severity_in: [HIGH, CRITICAL]
    then:
      decision: BLOCK

  - id: R-NOISE-BUDGET-pr
    description: Apply pr noise budget top-5 (default behavior).
    stage_scope: [pr]
    when:
      release_risk_gte: 0
    then:
      noise_budget_top_k: 5

  - id: R-NO-FIX-REQUIRES-ACCEPTED-RISK
    description: Require accepted risk for HIGH+ findings with no fix in release/prod.
    stage_scope: [release, prod]
    when:
      severity_in: [HIGH, CRITICAL]
      fix_available_in: [false]
    then:
      require_accepted_risk:
        selector:
          type: all_high_or_critical

  - id: R-HIGH-VULN-pr-REMEDIATION
    description: Require deterministic remediation steps for HIGH+ vulns in pr.
    stage_scope: [pr]
    when:
      domain_in: [VULNERABILITY]
      severity_in: [HIGH, CRITICAL]
    then:
      add_required_steps: [FIX_VULN]
```

## Future v2: Extended Noise Budget
MVP policy processing rejects any rule that activates a noise budget outside `stage=pr`. The following rule illustrates how a future v2 might safely introduce stage-aware noise budgets while respecting deterministic ordering—do not use this in MVP policy files.

```yaml
- id: R-NOISE-BUDGET-main
  description: (v2) Apply limited noise budget on main when explicitly allowed.
  stage_scope: [main]
  when:
    trust_score_gte: 70
  then:
    noise_budget_top_k: 3
```

This block is for planning reference only; enabling it today would be a fatal policy error for main/release/prod.

## Acceptance Criteria
- [ ] Rule structure, conditions, and actions are explicitly defined.
- [ ] Stage-aware conditions and trust-based tightening are supported.
- [ ] Exceptions and accepted risk objects include scope and expiry.
- [ ] Evaluation order is deterministic and recorded in the decision trace.
- [ ] Example rules (6-10) are provided and do not contradict the core engine.
