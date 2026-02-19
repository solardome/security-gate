# Core Decision Engine (Authoritative)

This document is the single authority for:
- Canonical enums/tokens
- Scoring formulas and clamping
- Precedence rules
- Decision matrices and exit codes
- `report.json` schema

All other documents must reference this file and must not redefine these items.

## 1) Canonical Tokens and Global Invariants

### Canonical Decision Enum
- `ALLOW`
- `WARN`
- `BLOCK`

### Canonical Exit Codes
- `0` = `ALLOW`
- `1` = `WARN`
- `2` = `BLOCK`

### Canonical Context Enums
- `branch_type`: `dev | feature | main | release`
- `pipeline_stage`: `pr | merge | release | deploy`
- `environment`: `ci | prod`

### Canonical Stage Strictness Order
`pr < merge < release < deploy`

### Global Invariants
- Identical normalized inputs must produce identical outputs (including finding ordering, tie-breaks, and `recommended_next_steps`).
- Numeric aggregation is monotonic: adding findings cannot reduce computed risk.
- Every numeric score is clamped to `[0,100]`.
- Unknown/missing signals never reduce risk.
- Hard-stop domains bypass numeric scoring and bypass noise budget.
- `report.json` is authoritative.
- `report.html` is derived and non-authoritative.
- No network calls are permitted.

## 2) Precedence Rules (Authoritative Evaluation Order)

The engine evaluates in this exact order:
1. Hard-stop domains (first; bypass numeric and noise budget)
2. Accepted Risk records / exceptions (cannot override hard-stops)
3. Numeric risk scoring (monotonic, clamped)
4. Noise budget (presentation-only)
5. Stage decision matrix
6. Exit code mapping

Any implementation that changes this order is non-compliant.

## 3) Unified Finding Schema (Normalized Internal Record)

Every scanner record is transformed into this normalized structure before policy and scoring.

```yaml
UnifiedFinding:
  finding_id: string               # stable scanner finding ID or deterministic hash fallback
  scanner:
    name: string
    version: string | "unknown"
  artifact:
    target_ref: string             # image digest, file path, module identifier
    component: string | "unknown"
    location: string | "unknown"  # file/package/layer path
  classification:
    category: vuln | secret | misconfig | license | malware | integrity | unknown
    domain_id: string              # canonical or policy-defined domain ID
    cve: string | null
    cwe: string | null
    severity: critical | high | medium | low | info | unknown
    confidence: high | medium | low | unknown
    exploit_maturity: known_exploited | poc | none | unknown
    reachability: reachable | potentially_reachable | not_reachable | unknown
  evidence:
    title: string
    description: string
    references: [string]
  timestamps:
    detected_at: RFC3339 | "unknown"
  raw:
    source_file: string
    source_index: integer
```

### Normalization Requirements
- Missing scanner fields must be represented as canonical `unknown` values, not omitted.
- Finding-level `scanner.name` and `scanner.version` must be adapter-derived from scanner report evidence only (never backfilled from context YAML/auto-context).
- Severity mapping must be deterministic and scanner-specific adapters must be pure functions.
- For missing `finding_id`, fallback is SHA-256 over immutable fields in this order:
  `scanner.name + scanner.version + artifact.target_ref + artifact.location + classification.category + evidence.title`.

## 4) Hard-Stop Domains (Non-Overridable)

If any active finding maps to one of these domain IDs, decision is `BLOCK` regardless of score, noise budget, or Accepted Risk.

Canonical hard-stop domain IDs:
- `HS_SECRET_IN_PROD_PATH`
- `HS_ACTIVE_RUNTIME_MALWARE`
- `HS_UNSIGNED_PROD_ARTIFACT`
- `HS_PROVENANCE_TAMPERED`
- `HS_POLICY_INTEGRITY_BROKEN`
- `HS_KNOWN_EXPLOITED_UNPATCHED`

Rules:
- Accepted Risk cannot suppress hard-stop domains.
- Noise budget is not evaluated for hard-stop findings.
- Report must contain explicit `hard_stop_triggered=true` and list domain IDs.

## 5) Validation and Failure Modes

### Validation Inputs
- Scan input JSON files (one or more local paths)
- Optional baseline scan JSON files (for baseline diff mode)
- Supported scan envelopes:
  - Trivy JSON
  - SARIF 2.1.0 JSON
  - Snyk vulnerability JSON
  - Checkmarx JSON v2
  - Sonar Generic Issues JSON
- CI context from one of:
  - context YAML file
  - deterministic local CI environment auto-detection mode
- Policy YAML file
- Accepted Risk YAML file (optional)
- Scanner adapter envelope checks (for example required report sections and supported schema version when provided)

SARIF-specific envelope rules (authoritative):
- Top-level `version` is required and must equal `2.1.0`.
- Top-level `runs` is required and must be an array.
- For each run: `tool.driver.name` is required and non-empty.
- For each run: `results` is required and must be an array.

Snyk-specific envelope rules (authoritative):
- Top-level `vulnerabilities` is required and must be an array.

Checkmarx-specific envelope rules (authoritative):
- Top-level `scanResults` is required and must be an array.
- If `reportType` is present, it must be `json-v2` (case-insensitive; separators ignored).

Sonar Generic Issues envelope rules (authoritative):
- Top-level `issues` is required and must be an array.
- If `rules` is present, it must be an array.
- Each issue must include a non-empty `ruleId`.

### CI Context Fields
Required:
- `pipeline_stage`
- `branch_type`
- `environment`
- `repo_criticality`
- `exposure`
- `change_type`

Optional (if known, strongly recommended for trust computation):
- `scanner.name`
- `scanner.version`
- `provenance.artifact_signed`
- `provenance.level`
- `provenance.build_context_integrity`

### Validation Classes
- `validation_ok`
- `validation_warn` (PR/feature fail-open behavior)
- `validation_error`

### Failure Mode Contract
For effective stage `release` or `deploy`:
- Any of the following MUST force `BLOCK`:
  - unreadable files
  - invalid JSON/YAML
  - unknown `schema_version`
  - missing required fields
  - hash failures
  - invalid or expired Accepted Risk records

For effective stage `pr` or `merge`:
- Validation failures return `WARN` (exit `1`), never `ALLOW`.
- Minimal deterministic report must still be emitted.

## 6) Canonical Stage Mapping (Branch Primary, Pipeline Secondary)

### Inputs
- `branch_type`
- `pipeline_stage`
- `environment`

### Step A: Base Stage from Branch (Primary)
- `dev` -> `pr`
- `feature` -> `pr`
- `main` -> `merge`
- `release` -> `release`

### Step B: Candidate Stage from Pipeline (Secondary)
- `pipeline_stage` maps 1:1 to candidate stage

### Step C: Candidate Stage from Environment
- if `environment=prod`, candidate stage is `deploy`
- if `environment=ci`, no extra candidate

### Step D: Effective Stage
`effective_stage = max_strictness(base_stage, pipeline_candidate, environment_candidate)`

Because max strictness is used, secondary signals can tighten but never loosen branch-derived behavior.

Examples:
- `branch_type=main`, `pipeline_stage=pr`, `environment=ci` -> `merge`
- `branch_type=feature`, `pipeline_stage=release`, `environment=ci` -> `release`
- `branch_type=release`, `pipeline_stage=merge`, `environment=prod` -> `deploy`

## 7) Trust Computation (0-100)

Trust is computed before numeric risk modifiers.

### Trust Inputs
- scanner version pinning
- scanner output freshness
- artifact signing state
- provenance level
- build context integrity
- completeness of required context fields

### Trust Formula
`TrustScore = clamp(100 - Σ(trust_penalties), 0, 100)`

Penalties (additive):
- Scanner version unknown: `+15`
- Scanner version unpinned: `+10`
- Scan age > policy freshness SLA: `+15`
- Artifact unsigned (when signing expected): `+20`
- Provenance unknown: `+10`
- Provenance below required SLSA-like level: `+15`
- Build context missing/partial: `+10`
- Any required context field missing: `+5` each (max `+20` from this rule)

Unknown values always apply the defined penalty.
Malformed or future scan timestamps are treated as unknown for freshness evaluation.

### Trust-to-Risk Penalty Mapping
- `TrustScore >= 80` -> `+0`
- `60..79` -> `+5`
- `40..59` -> `+10`
- `20..39` -> `+15`
- `0..19` -> `+20`

## 8) Finding Risk Scoring (0-100)

Each non-hard-stop finding gets a `FindingRiskScore`.

### Component Weights
Severity base:
- `critical=70`
- `high=50`
- `medium=30`
- `low=15`
- `info=5`
- `unknown=35`

Exploit maturity modifier:
- `known_exploited=+20`
- `poc=+10`
- `none=+0`
- `unknown=+8`

Reachability modifier:
- `reachable=+10`
- `potentially_reachable=+5`
- `not_reachable=+0`
- `unknown=+4`

Confidence modifier:
- `high=+0`
- `medium=-2`
- `low=-5`
- `unknown=+2`

Asset/context modifier:
- `repo_criticality=mission_critical` -> `+10`
- `repo_criticality=high` -> `+6`
- `repo_criticality=medium` -> `+3`
- `repo_criticality=low` -> `+0`
- `repo_criticality=unknown` -> `+5`

- `exposure=internet` -> `+10`
- `exposure=internal` -> `+4`
- `exposure=isolated` -> `+0`
- `exposure=unknown` -> `+6`

### Formula
`FindingRiskScore = clamp(severity_base + exploit_modifier + reachability_modifier + confidence_modifier + criticality_modifier + exposure_modifier, 0, 100)`

## 9) Overall Risk Scoring (0-100)

Let `F = max(FindingRiskScore of active non-hard-stop findings)`.
If no active non-hard-stop findings exist, `F = 0`.

Context modifiers:
- `change_type=security_sensitive` -> `+8`
- `change_type=infra_or_supply_chain` -> `+6`
- `change_type=application` -> `+2`
- `change_type=docs_or_tests` -> `+0`
- `change_type=unknown` -> `+5`

- `effective_stage=merge` -> `+3`
- `effective_stage=release` -> `+6`
- `effective_stage=deploy` -> `+10`
- `effective_stage=pr` -> `+0`

`TrustPenalty` from Section 7.

Final formula:
`OverallRiskScore = clamp(F + change_type_modifier + stage_modifier + TrustPenalty, 0, 100)`

Monotonicity note:
- Since `F` is max across active findings and all modifiers are non-negative constants for a given context, adding findings cannot reduce `OverallRiskScore`.

## 10) Accepted Risk Interaction

Accepted Risk records are evaluated after hard-stops and before numeric scoring.

A finding can be marked `accepted=true` only when all are true:
- Record is structurally valid.
- Record is not expired.
- Record scope matches finding.
- Required approvals for stage/domain are present.
- Finding is NOT in hard-stop domain.

If record is invalid or expired:
- `release`/`deploy`: `BLOCK` (validation error path)
- `pr`/`merge`: `WARN` (validation warn path)

Accepted findings are excluded from numeric risk aggregation but retained in report trace.

## 11) Noise Budget Rules (Presentation-Only)

Noise budget may suppress annotations or truncate display lists for `pr` and `merge` only.

Mandatory constraints:
- Must not modify `FindingRiskScore`, `OverallRiskScore`, or decision.
- Must not apply to hard-stop findings.
- Must not hide validation failures.
- Must preserve full findings in `report.json`; only rendered surfaces may be reduced.

Derived presentation outputs should include suppression transparency:
- suppressed counts
- suppression reasons (for example severity floor vs stage display limit)

## 12) Stage Decision Matrix (Authoritative)

Apply this matrix after hard-stop and validation handling.

### Preconditions
- If hard-stop triggered -> `BLOCK`
- Else if validation failure:
  - `effective_stage in {release, deploy}` -> `BLOCK`
  - `effective_stage in {pr, merge}` -> `WARN`

### Risk Threshold Matrix
For cases with no hard-stop and validation_ok:

| Effective Stage | ALLOW if OverallRiskScore | WARN if OverallRiskScore | BLOCK if OverallRiskScore |
|---|---:|---:|---:|
| `pr` | `0-44` | `45-74` | `75-100` |
| `merge` | `0-34` | `35-64` | `65-100` |
| `release` | `0-24` | `25-49` | `50-100` |
| `deploy` | `0-14` | `15-34` | `35-100` |

### Trust Floor Tightening
Independent of risk thresholds:
- If `effective_stage in {release, deploy}` and `TrustScore < 40` -> minimum decision is `WARN`.
- If `effective_stage=deploy` and `TrustScore < 25` -> `BLOCK`.

`deploy` is the production-equivalent decision stage for matrix evaluation.

`minimum decision is WARN` means `ALLOW` is upgraded to `WARN`.

## 13) Escalation Logic

Escalation events produce deterministic decision upgrades and required next steps:
- Accepted Risk expires within SLA window (for example <= 7 days):
  - no decision change by itself
  - must append escalation step `REVIEW_ACCEPTED_RISK_EXPIRY`
- Accepted Risk expired:
  - handled as validation failure per stage
- Repeated WARN streak in same branch (optional local state file enabled):
  - if WARN streak threshold met and stage is `merge` or stricter, upgrade `WARN` -> `BLOCK`
  - feature is optional in MVP; default disabled

Optional baseline diff mode (`new_findings_only`):
- Supported for effective stage `pr` and `merge` only.
- Requires baseline scan JSON inputs.
- Numeric scoring aggregation considers only findings not present in baseline.
- Hard-stop evaluation is unchanged and always enforced.
- Accepted Risk, validation handling, and stage matrix precedence are unchanged.

## 14) Deterministic Ordering and Tie-Breaking

For report generation and stable outputs, active findings are sorted by:
1. hard-stop membership (`true` first)
2. `FindingRiskScore` descending
3. `classification.severity` rank (`critical > high > medium > low > info > unknown`)
4. `classification.domain_id` lexicographic
5. `finding_id` lexicographic
6. `artifact.location` lexicographic
7. `raw.source_file` lexicographic
8. `raw.source_index` ascending

## 15) report.json Schema (Authoritative)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "security-gate/report.schema.json",
  "title": "security-gate report",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version",
    "generated_at",
    "run_id",
    "inputs",
    "context",
    "effective_stage",
    "trust",
    "risk",
    "hard_stop",
    "decision",
    "exit_code",
    "findings",
    "accepted_risk",
    "recommended_next_steps",
    "decision_trace",
    "non_authoritative"
  ],
  "properties": {
    "schema_version": { "type": "string", "const": "1.0.0" },
    "generated_at": { "type": "string", "format": "date-time" },
    "run_id": { "type": "string" },
    "inputs": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["path", "sha256", "kind"],
        "properties": {
          "kind": { "type": "string", "enum": ["scan_json", "context_yaml", "policy_yaml", "accepted_risk_yaml"] },
          "role": { "type": "string", "enum": ["primary", "baseline"] },
          "path": { "type": "string" },
          "sha256": { "type": "string", "pattern": "^[a-f0-9]{64}$" },
          "read_ok": { "type": "boolean", "default": true }
        }
      }
    },
    "context": {
      "type": "object",
      "additionalProperties": false,
      "required": ["branch_type", "pipeline_stage", "environment", "repo_criticality", "exposure", "change_type"],
      "properties": {
        "branch_type": { "type": "string", "enum": ["dev", "feature", "main", "release"] },
        "pipeline_stage": { "type": "string", "enum": ["pr", "merge", "release", "deploy"] },
        "environment": { "type": "string", "enum": ["ci", "prod"] },
        "repo_criticality": { "type": "string", "enum": ["low", "medium", "high", "mission_critical", "unknown"] },
        "exposure": { "type": "string", "enum": ["isolated", "internal", "internet", "unknown"] },
        "change_type": { "type": "string", "enum": ["docs_or_tests", "application", "infra_or_supply_chain", "security_sensitive", "unknown"] },
        "scanner": {
          "type": "object",
          "additionalProperties": false,
          "required": ["name", "version"],
          "properties": {
            "name": { "type": "string" },
            "version": { "type": "string" }
          }
        },
        "provenance": {
          "type": "object",
          "additionalProperties": false,
          "required": ["artifact_signed", "level", "build_context_integrity"],
          "properties": {
            "artifact_signed": { "type": "string", "enum": ["yes", "no", "unknown"] },
            "level": { "type": "string", "enum": ["none", "basic", "verified", "unknown"] },
            "build_context_integrity": { "type": "string", "enum": ["verified", "partial", "unknown"] }
          }
        }
      }
    },
    "effective_stage": { "type": "string", "enum": ["pr", "merge", "release", "deploy"] },
    "trust": {
      "type": "object",
      "additionalProperties": false,
      "required": ["score", "penalties", "risk_penalty"],
      "properties": {
        "score": { "type": "integer", "minimum": 0, "maximum": 100 },
        "risk_penalty": { "type": "integer", "minimum": 0, "maximum": 20 },
        "penalties": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["code", "value"],
            "properties": {
              "code": { "type": "string" },
              "value": { "type": "integer", "minimum": 0, "maximum": 30 }
            }
          }
        }
      }
    },
    "risk": {
      "type": "object",
      "additionalProperties": false,
      "required": ["overall_score", "max_finding_score", "context_modifiers"],
      "properties": {
        "overall_score": { "type": "integer", "minimum": 0, "maximum": 100 },
        "max_finding_score": { "type": "integer", "minimum": 0, "maximum": 100 },
        "context_modifiers": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["code", "value"],
            "properties": {
              "code": { "type": "string" },
              "value": { "type": "integer", "minimum": 0, "maximum": 20 }
            }
          }
        }
      }
    },
    "hard_stop": {
      "type": "object",
      "additionalProperties": false,
      "required": ["triggered", "domains"],
      "properties": {
        "triggered": { "type": "boolean" },
        "domains": { "type": "array", "items": { "type": "string" } }
      }
    },
    "decision": { "type": "string", "enum": ["ALLOW", "WARN", "BLOCK"] },
    "exit_code": { "type": "integer", "enum": [0, 1, 2] },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["finding_id", "domain_id", "severity", "hard_stop", "accepted", "finding_risk_score", "source_file", "source_index"],
        "properties": {
          "finding_id": { "type": "string" },
          "domain_id": { "type": "string" },
          "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info", "unknown"] },
          "hard_stop": { "type": "boolean" },
          "accepted": { "type": "boolean" },
          "finding_risk_score": { "type": "integer", "minimum": 0, "maximum": 100 },
          "source_file": { "type": "string" },
          "source_index": { "type": "integer", "minimum": 0 }
        }
      }
    },
    "accepted_risk": {
      "type": "object",
      "additionalProperties": false,
      "required": ["records_evaluated", "records_applied", "invalid_records"],
      "properties": {
        "records_evaluated": { "type": "integer", "minimum": 0 },
        "records_applied": { "type": "integer", "minimum": 0 },
        "invalid_records": { "type": "integer", "minimum": 0 }
      }
    },
    "recommended_next_steps": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "priority", "text"],
        "properties": {
          "id": { "type": "string" },
          "priority": { "type": "integer", "minimum": 1, "maximum": 999 },
          "text": { "type": "string" }
        }
      }
    },
    "decision_trace": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["order", "phase", "result"],
        "properties": {
          "order": { "type": "integer", "minimum": 1 },
          "phase": { "type": "string" },
          "result": { "type": "string" },
          "details": { "type": "object" }
        }
      }
    },
    "non_authoritative": {
      "type": "object",
      "additionalProperties": false,
      "required": ["llm_enabled", "llm_text"],
      "properties": {
        "llm_enabled": { "type": "boolean" },
        "llm_text": { "type": "string" }
      }
    }
  }
}
```

## 16) Deterministic recommended_next_steps Catalog

The engine outputs ordered steps from this fixed catalog. Implementations may only use IDs from this list.

| ID | Priority | Condition | Text |
|---|---:|---|---|
| `FIX_HARD_STOP_IMMEDIATELY` | 100 | hard-stop triggered | Remove or remediate all hard-stop findings before rerun. |
| `RESTORE_ARTIFACT_SIGNING` | 20 | unsigned/tampered artifact evidence | Rebuild and sign artifact with approved local signing workflow. |
| `REFRESH_SCANS` | 300 | stale scans | Re-run scanners and provide fresh local JSON artifacts. |
| `COMPLETE_MISSING_CONTEXT` | 40 | missing required context fields | Populate missing context values in context YAML and rerun. |
| `REMEDIATE_TOP_FINDING` | 50 | non-hard-stop risk above warn threshold | Fix highest-risk unaccepted finding first. |
| `REVIEW_ACCEPTED_RISK_EXPIRY` | 60 | accepted risk near expiry | Renew, close, or remediate accepted findings before SLA breach. |
| `SECURITY_APPROVAL_REQUIRED` | 70 | release/deploy with required approval unmet | Obtain required local security approval record for scoped exception. |
| `VALIDATE_POLICY_FILE` | 80 | policy parse/schema issues | Correct policy YAML schema violations and rerun. |
| `VALIDATE_ACCEPTED_RISK_FILE` | 90 | accepted risk parse/schema issues | Correct accepted risk file and rerun. |

Selection and ordering rules:
- Include each applicable ID at most once.
- Sort by `priority` ascending then `id` lexicographic.
- Text is fixed and must not be modified by LLM.

## 17) LLM Boundary

- LLM output is optional and non-authoritative.
- LLM text may elaborate `recommended_next_steps` but cannot add new step IDs.
- LLM text cannot influence decision, score, trust, or exit code.
- LLM can be disabled via configuration (`llm_enabled=false`) and default for offline mode is disabled.

## 18) Example Walkthroughs

### Example A: Feature PR with Missing Context
- Inputs:
  - branch_type=`feature`, pipeline_stage=`pr`, environment=`ci`
  - One high severity reachable finding
  - Missing `exposure`
- Effective stage: `pr`
- Hard-stop: none
- Trust penalty includes missing required context
- OverallRiskScore lands in WARN band
- Decision: `WARN`, exit `1`

### Example B: Release with Expired Accepted Risk
- Inputs:
  - branch_type=`release`, pipeline_stage=`release`, environment=`ci`
  - Accepted Risk record expired yesterday
- Effective stage: `release`
- Validation failure class for release: fail-closed
- Decision: `BLOCK`, exit `2`

### Example C: Deploy with Hard-Stop
- Inputs:
  - branch_type=`release`, pipeline_stage=`deploy`, environment=`prod`
  - Finding domain `HS_UNSIGNED_PROD_ARTIFACT`
- Effective stage: `deploy`
- Hard-stop precedence applies before scoring
- Decision: `BLOCK`, exit `2`

## Acceptance Criteria Checklist

- [ ] Canonical decision/context enums are present and exact.
- [ ] Precedence order is explicitly defined and testable.
- [ ] Hard-stop domain list is explicit, canonical, and non-overridable.
- [ ] Stage mapping is deterministic with branch_type as primary driver.
- [ ] Risk and trust formulas are numeric, bounded, and clamped.
- [ ] Unknown signals explicitly never reduce risk.
- [ ] Noise budget is explicitly presentation-only.
- [ ] Accepted Risk interaction is defined with expiry/invalid behavior.
- [ ] Decision matrices for `pr`, `merge`, `release`, `deploy` are defined.
- [ ] Exit code mapping is fixed (`0/1/2`).
- [ ] `report.json` schema is authoritative and complete.
- [ ] Deterministic `recommended_next_steps` catalog is defined.
