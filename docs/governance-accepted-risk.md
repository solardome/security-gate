# Governance: Accepted Risk

Authority Notice
This document is descriptive and non-authoritative. Design intent lives in design/architecture.prompt.md, deterministic decision logic and evaluation order live in docs/core-decision-engine.md, and the policy schema lives in docs/policy-format.md. In conflicts, those authoritative sources prevail and this document must not override or reinterpret them.

This document defines the justification workflow for accepted risks. It is consistent
with `docs/core-decision-engine.md` and `docs/policy-format.md`, which remain the
authoritative sources for deterministic decision logic, escalation behavior, and
suppression invariants. This document specifies **governance semantics only** (schema,
validation, approvals, lifecycle) and MUST NOT override any normative rules in the
core decision engine.

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

Legacy-to-canonical mapping for stages is defined canonically in
`docs/core-decision-engine.md` under **“Stage Enum (Canonical)”**. For convenience, this
document uses the same canonical tokens (pr, main, release, prod) when describing
`stage_scope`.

### finding_selector Keys
All listed fields must match if present:
- domain
- cve_id
- fingerprint (required for Accepted Risk; see below)
- title_contains
- location_contains
- source_scanner
- severity

**Accepted Risk vs Exception selectors:** Accepted Risk finding_selector **must** include `fingerprint` for deterministic matching. Unlike policy exceptions (which may use domain, cve_id, title_contains, etc. without fingerprint for broad false-positive suppression), accepted risks require fingerprint so that suppression and prod WARN coverage are stable across runs. The `fingerprint` key must reference the canonical fingerprint described in `docs/core-decision-engine.md`, not the scanner-provided `finding_id`. Records that omit fingerprint are governance-invalid and ignored. Supplemental keys (domain, cve_id, etc.) may narrow the match but do not substitute for fingerprint.

## Validation Rules
- stage_scope and environment_scope are mandatory and non-empty.
- expires_at must be a valid future timestamp at creation time.
- status must be one of: active, expired, revoked.
- effects cannot apply to hard-stop domains.
- allow_warn_in_prod must be explicitly true to allow WARN in prod.
- finding_selector must be specific enough to avoid broad suppression.
- finding_selector must target fingerprint for deterministic matching; other fields are supplemental.

### Engine-Enforced Validation Behavior
The deterministic engine MUST enforce the following behaviors when loading and
evaluating accepted risk records:

- **Parse/shape errors** (malformed JSON/YAML, missing required fields such as risk_id,
  stage_scope, environment_scope, expires_at, or status outside the allowed enum) are
  treated as **accepted risk parse/validation failures** and therefore as **fatal errors**
  (see "Fatal Errors and Fail-Closed Defaults (Authoritative)" in `docs/modules.md`).
  - For stage=main/release/prod: fatal error ⇒ BLOCK with minimal decision.json +
    error metadata.
  - For stage=pr: fatal error ⇒ WARN (exit_code=1) with low-trust defaults ONLY if
    scanner input is present and hashable; otherwise BLOCK.
- **Schema-valid but governance-invalid records** (for example, effects attempting to
  suppress hard-stop domains, allow_warn_in_prod=true without required approvals, or
  finding_selector that does not include a canonical fingerprint) MUST be:
  - Ignored for gating and suppression behavior (never considered "active").
  - Recorded in `decision_trace` as governance warnings, including the offending
    risk_id and reason.
- Records with **expires_at in the past** or `status=expired`/`status=revoked` at
  evaluation time are never considered active for suppression or coverage, but still
  participate in expiry-based escalation as defined in this document and in the
  core decision engine.

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

## Accepted Risk Lifecycle & Decision Influence (Summary)
Lifecycle states:
- **active**: `status=active`, current time is **before** `expires_at`, and the current `stage_scope` and `environment_scope` include the evaluation context. Only active records are considered by the engine for scoring suppression, WARN floors, prod WARN coverage, or `require_accepted_risk`.
- **expired**: `now >= expires_at` or `status=expired`. Expired records are ignored for all gating and coverage decisions but still appear in governance warnings and audit trails (see **Expiry-Based Escalation**).
- **revoked**: `status=revoked` (set manually by the owner). Revoked records are never considered active; they remain only as historical governance/audit evidence.

An accepted risk is therefore considered **“active”** by the engine **only** when all of the following are true:
- `status=active`
- current UTC time `< expires_at`
- current stage and environment are within `stage_scope` and `environment_scope`

Detailed behavior is defined in **Precedence Rules**, **Prod WARN Coverage Requirements**, and **Expiry-Based Escalation** in this document, and in **Escalation Logic (Stage and Expiry)** and **Prod WARN Escalation and allow_warn_in_prod Coverage** in `docs/core-decision-engine.md`, plus **Deterministic Evaluation Order**, **Accepted Risk Objects (Justified Risk Acceptance)**, and **Precedence Rules** in `docs/policy-format.md`.

| Stage  | Scoring suppression (effects)                                                                 | WARN floor (HIGH/CRITICAL coverage)                                             | Prod WARN coverage (allow_warn_in_prod)                                                                                  | Expiry escalation                                                                                           | Interaction with require_accepted_risk                                                        |
| ------ | ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| pr     | Active, in-scope records with `effects` containing `suppress_from_scoring` may remove non-hard-stop findings from the scoring set; expired/revoked records are ignored. | Any active, in-scope record covering at least one HIGH/CRITICAL finding enforces a final outcome of at least WARN. | Not applicable (prod-only behavior).                                                                                    | If an accepted risk that would have applied is expired, the final outcome is at least WARN.                | Missing an active, in-scope accepted risk for required fingerprints tightens the outcome to WARN. |
| main   | Same as pr: active, in-scope records may suppress non-hard-stop findings; expired/revoked are ignored. | Same WARN floor: active coverage of HIGH/CRITICAL enforces a final outcome of at least WARN. | Not applicable (prod-only behavior).                                                                                    | If an accepted risk that would have applied is expired, the final outcome is at least WARN.                | Missing an active, in-scope accepted risk for required fingerprints tightens the outcome to BLOCK. |
| release| Same suppression behavior: active, in-scope records may suppress non-hard-stop findings; expired/revoked are ignored. | Same WARN floor: active coverage of HIGH/CRITICAL enforces a final outcome of at least WARN. | Not applicable (prod-only behavior).                                                                                    | If an accepted risk that would have applied is expired, the final outcome is forced to BLOCK.              | Missing an active, in-scope accepted risk for required fingerprints tightens the outcome to BLOCK. |
| prod   | Same suppression behavior: active, in-scope records may suppress non-hard-stop findings; expired/revoked are ignored. | Same WARN floor: active coverage of HIGH/CRITICAL enforces a final outcome of at least WARN. | Active, in-scope records with `allow_warn_in_prod=true` can prevent WARN→BLOCK escalation **only** when they cover every `warn_causing_fingerprint`; partial coverage still escalates to BLOCK. | If an accepted risk that would have applied is expired, the final outcome is forced to BLOCK.              | Missing an active, in-scope accepted risk for required fingerprints tightens the outcome to BLOCK. |

## Status Lifecycle and Ownership
Accepted risks begin in `status=active` and must transition to `expired` or `revoked` when appropriate. The lifecycle is enforced as follows; only item (1) below is part of the MVP engine behavior:

1. **CLI validation per run (engine behavior, read-only):** Before scoring, the deterministic engine compares the current UTC timestamp with each accepted risk's `expires_at` and `status`. When `now >= expires_at` and `status` is still `active`, the engine treats the risk as expired **for this evaluation**, records a `decision_trace` event, and honors its governance rules as inactive. A similar check treats any `status=revoked` record as inactive immediately; `revoked` entries are never considered for `allow_warn_in_prod` or `suppress_from_scoring`. The engine MUST NOT modify or rewrite the accepted risk file; it derives effective status at runtime and reflects it only in decision artifacts and trace events.
2. **Governance sweep and notifications (operational practice, out of MVP engine scope):** A periodic governance review (for example, a manual checklist or externally scheduled job owned by the `owner` field, usually a security or platform team) may re-scan the accepted risk file, reconcile `expires_at` against the recorded `status`, notify owners before expiry, and flag any inconsistencies for remediation. These sweeps and notifications are guidance for good governance hygiene and are **not** required or implemented by the CLI or core engine.
3. **Manual updates and revocation (operational practice):** The risk `owner` is responsible for editing the record to set `status=revoked` when a mitigation is deployed or the justification changes. Every manual update must add a new `audit` event describing the action, actor, and timestamp so reviewers can trace the lifecycle. This is a governance responsibility and not automated by the MVP engine.

Decision trace events surface these transitions so escalation logic can observe them in practice. Every status change (expiry or revocation) that the engine detects at evaluation time MUST emit a `decision_trace` event such as `accepted_risk.status_change` with at least:

- `event_id`: unique identifier for the trace event.
- `timestamp`: RFC3339 time of the transition.
- `risk_id`: accepted risk identifier.
- `status`: new status (`expired` or `revoked`).
- `reason`: text like `expires_at reached` or `owner revoked`.
- `matched_fingerprints`: list of canonical fingerprints that the risk had covered (bounded to 20 entries, consistent with governance events).
- `stage_scope` / `environment_scope`: to show the contexts the risk applied to.

These events feed the escalation rules so that, for example, a prod WARN → BLOCK escalation can see that `matched_fingerprints` no longer have an active accepted risk coverage and escalate accordingly.

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
