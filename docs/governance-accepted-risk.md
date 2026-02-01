# Governance: Accepted Risk

This document defines the justification workflow for accepted risks. It is consistent
with `docs/core-decision-engine.md` and `docs/policy-format.md`.

## Purpose
- Provide a time-bound, approved mechanism to accept risk.
- Ensure accepted risks are scoped, auditable, and expire automatically.
- Enforce escalation rules when accepted risks expire.

## Storage Location (MVP)
- Accepted risk records are stored in a **repo-local file**.
- The file path is provided to the CLI or context input.
- No external systems or network calls are used in MVP.

## Accepted Risk Schema
All fields are required unless marked optional.

| Field | Type | Notes |
| --- | --- | --- |
| risk_id | string | Unique ID for tracking. |
| title | string | Short label. |
| rationale | string | Justification and business context. |
| owner | string | Responsible owner (name or team). |
| ticket | string | Tracking ticket or change record. |
| stage_scope | array | Allowed stages (pr, main, release, prod). |
| environment_scope | array | Allowed environments (dev, staging, prod, etc.). |
| finding_selector | object | Deterministic match criteria. |
| effects | array | List of effects (may be empty for governance-only); valid value: suppress_from_scoring. |
| allow_warn_in_prod | boolean | Explicitly allow WARN in prod (default false). |
| approvals | array | List of approver records. |
| created_at | RFC3339 | Creation timestamp. |
| updated_at | RFC3339 | Last update timestamp. |
| expires_at | RFC3339 | Expiry timestamp (required). |
| status | enum | active, expired, revoked. |
| audit | array (optional) | Append-only audit events. |

Legacy-to-canonical mapping:
| Legacy term | Canonical token |
| --- | --- |
| PR/feature | pr |
| merge/main | main |
| release | release |
| deploy-to-prod | prod |

### finding_selector Keys
All listed fields must match if present:
- domain
- cve_id
- fingerprint
- title_contains
- location_contains
- source_scanner
- severity

## Validation Rules
- stage_scope and environment_scope are mandatory and non-empty.
- expires_at must be a valid future timestamp at creation time.
- status must be one of: active, expired, revoked.
- effects cannot apply to hard-stop domains.
- allow_warn_in_prod must be explicitly true to allow WARN in prod.
- finding_selector must be specific enough to avoid broad suppression.
- finding_selector must target fingerprint for deterministic matching; other fields are supplemental.

## Approval Rules
- All accepted risks require at least one approval.
- If stage_scope includes prod **and** a matched finding is HIGH or CRITICAL,
  at least one approver must have the role "security".
- Approval records must include approver name, role, and timestamp.

## Precedence Rules
- Policy rules are tighten-only except that an explicitly approved Accepted Risk may prevent warn_to_block escalation for its scoped findings when allow_warn_in_prod=true.
- Accepted Risk never overrides hard-stop domains (SECRET, MALWARE, PROVENANCE) and never overrides provenance/signing hard-stops.
- Accepted Risk affects only the scoped finding fingerprints; unrelated findings or conditions may still cause BLOCK.
- If any valid Accepted Risk covers at least one finding with severity HIGH or CRITICAL in the current stage (and env if scoped), then the final decision MUST be at least WARN, regardless of suppress_from_scoring removing all findings from the scoring set.
- Decision trace MUST record accepted_risks_applied with matched_fingerprints and whether allow_warn_in_prod was used.

## Prod WARN Coverage Requirements
Prod WARN outcomes escalate to BLOCK unless a valid Accepted Risk with `allow_warn_in_prod=true` covers every `warn_causing_fingerprint`. The warn-causing set is deterministic: all non-hard-stop findings in the scoring set with `severity >= HIGH`, or the single top finding by the Deterministic Finding Ordering when severity data is missing. Partial coverage is insufficient—any uncovered warn-causing fingerprint preserves the WARN → BLOCK escalation and the final decision remains BLOCK. Hard-stop findings are never affected by this rule.

## Expiry-Based Escalation
- Expired accepted risks are ignored and recorded as governance warnings.
- For release/prod stages, if an expired accepted risk would have covered a HIGH or
  CRITICAL finding, the decision is forced to BLOCK (per core escalation rules).
- Expiry events are recorded in the decision trace.

## Audit Trail
- audit is an append-only list of events with timestamp, actor, and action.
- All updates to an accepted risk must add a new audit entry.

## Concrete Examples (YAML)
Notes:
- effects: [] means governance approval only; it does not change scoring, but Governance Decision Floor may still enforce WARN for HIGH/CRITICAL coverage.
- If effects include suppress_from_scoring and suppression removes all findings (release_risk becomes 0), a valid accepted risk covering HIGH/CRITICAL in the current stage/environment still yields a final outcome of at least WARN.
- To influence outcomes beyond the WARN floor, use require_accepted_risk policy gates or allow_warn_in_prod=true in prod (for covered fingerprints only).

```yaml
- risk_id: AR-2026-0001
  title: "CRITICAL CVE in base image, no fix"
  rationale: "Vendor has no patch; compensating controls in place."
  owner: "platform-security"
  ticket: "SEC-1234"
  stage_scope: [release]
  environment_scope: [staging]
  finding_selector:
    fingerprint: "fp-3f2c9b7a"
    domain: VULNERABILITY
    severity: CRITICAL
    cve_id: CVE-2025-9999
  effects: []
  allow_warn_in_prod: false
  approvals:
    - name: "Security Lead"
      role: "security"
      approved_at: "2026-02-01T08:00:00Z"
  created_at: "2026-02-01T07:50:00Z"
  updated_at: "2026-02-01T07:50:00Z"
  expires_at: "2026-02-15T00:00:00Z"
  status: active

- risk_id: AR-2026-0002
  title: "Legacy dependency with HIGH CVE in prod"
  rationale: "Migration underway; temporary acceptance with strict monitoring."
  owner: "app-team"
  ticket: "APP-5678"
  stage_scope: [prod]
  environment_scope: [prod]
  finding_selector:
    fingerprint: "fp-9a7d2c14"
    domain: VULNERABILITY
    severity: HIGH
    title_contains: "legacy-lib"
  effects: []
  allow_warn_in_prod: true
  approvals:
    - name: "Security Lead"
      role: "security"
      approved_at: "2026-02-01T09:00:00Z"
    - name: "Engineering Manager"
      role: "engineering"
      approved_at: "2026-02-01T09:05:00Z"
  created_at: "2026-02-01T08:30:00Z"
  updated_at: "2026-02-01T08:30:00Z"
  expires_at: "2026-02-20T00:00:00Z"
  status: active
```

### Partial Coverage Still BLOCKs
If a prod WARN outcome is due to multiple warn-causing fingerprints and an approved accepted risk covers only a subset of them (even with `allow_warn_in_prod=true`), escalation still applies and the final result is BLOCK. Complete fingerprint coverage is required before the policy considers WARN acceptable via `allow_warn_in_prod`.

## Acceptance Criteria
- [ ] Schema includes scope, approvals, expiry, and audit trail.
- [ ] Validation rules enforce time-bound, scoped, and specific records.
- [ ] Approval rules include security approval for prod + critical/high.
- [ ] Expiry escalation aligns with the core decision engine.
- [ ] Examples are concrete and consistent with policy format.
