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
- noise_budget_top_k: integer (pr only by default; may be explicitly enabled for main; applied at step 4 of Deterministic Evaluation Order)
- add_required_steps: array of deterministic step IDs (from core decision engine)
- require_accepted_risk: boolean (requires a valid accepted risk for matching findings)

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
1) Ingest and normalize inputs to the unified finding schema.
2) Score findings and compute trust_score.
3) Identify hard-stop domains (SECRET, MALWARE, PROVENANCE); mark them as hard_stop. Hard-stop always forces BLOCK.
4) Apply noise budget to non-hard-stop findings only. Noise budget never applies to hard-stop domains and is scoped to stage=pr unless explicitly enabled by policy for stage=main.
5) Compute max_finding_risk and release_risk, then apply the stage decision matrix to determine the stage outcome.

## Precedence Rules
- Policy rules are tighten-only except that an explicitly approved Accepted Risk may prevent warn_to_block escalation for its scoped findings when allow_warn_in_prod=true.
- Accepted Risk never overrides hard-stop domains (SECRET, MALWARE, PROVENANCE) and never overrides provenance/signing hard-stops.
- Accepted Risk affects only the scoped finding fingerprints; unrelated findings or conditions may still cause BLOCK.
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

  - id: R-NOISE-BUDGET-main
    description: Allow limited noise budget on main only if policy enables it.
    stage_scope: [main]
    when:
      trust_score_gte: 60
    then:
      noise_budget_top_k: 3

  - id: R-NO-FIX-REQUIRES-ACCEPTED-RISK
    description: Require accepted risk for HIGH+ findings with no fix in release/prod.
    stage_scope: [release, prod]
    when:
      severity_in: [HIGH, CRITICAL]
      fix_available_in: [false]
    then:
      require_accepted_risk: true

  - id: R-HIGH-VULN-pr-REMEDIATION
    description: Require deterministic remediation steps for HIGH+ vulns in pr.
    stage_scope: [pr]
    when:
      domain_in: [VULNERABILITY]
      severity_in: [HIGH, CRITICAL]
    then:
      add_required_steps: [FIX_VULN]
```

## Acceptance Criteria
- [ ] Rule structure, conditions, and actions are explicitly defined.
- [ ] Stage-aware conditions and trust-based tightening are supported.
- [ ] Exceptions and accepted risk objects include scope and expiry.
- [ ] Evaluation order is deterministic and recorded in the decision trace.
- [ ] Example rules (6-10) are provided and do not contradict the core engine.
