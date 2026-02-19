# Governance: Accepted Risk

This document defines the Accepted Risk workflow for MVP local governance.

Authoritative engine interaction and precedence remain defined in `docs/md/core-decision-engine.md`.

## 1) Purpose

Accepted Risk allows temporary, auditable exceptions for specific findings or scopes, without external dependencies.

Constraints:
- local, in-repo storage only
- deterministic validation and matching
- cannot override hard-stop domains

## 2) File Location

Recommended path:
- `.security-gate/accepted-risk.yaml`

## 3) Schema

```yaml
schema_version: "1.0"
records:
  - id: "AR-2026-0001"
    status: active                 # active | revoked | expired
    owner: "team-security"
    approvers:
      - "sec-lead"
    ticket: "SEC-1234"
    rationale: "Temporary acceptance pending upstream patch"
    scope:
      type: finding_id             # finding_id | cve | component
      value: "TRIVY-2026-XYZ"
      scanner: "trivy"            # optional but recommended
      repository: "*"             # literal repo name or *
      branch_types: [feature, main, release]
      stages: [pr, merge, release]
    constraints:
      max_severity: high           # critical | high | medium | low | info
      environments: [ci]           # ci | prod
    timeline:
      created_at: "2026-02-01T00:00:00Z"
      expires_at: "2026-03-01T00:00:00Z"
      sla_days: 30
    metadata:
      created_by: "jdoe"
      reviewed_by: "sec-lead"
```

## 4) Field Rules

Top-level:
- `schema_version` must be `"1.0"`.
- `records` must be a list (may be empty).

Record requirements:
- `id`, `owner`, `ticket`, `rationale`, `scope`, `timeline` are required.
- `status=active` records are eligible for matching.
- `expires_at` must be RFC3339 and strictly greater than `created_at`.
- `sla_days` must be positive integer.

Scope matching:
- `scope.type=finding_id`: exact match on normalized `finding_id`.
- `scope.type=cve`: exact match on `classification.cve`.
- `scope.type=component`: exact match on normalized component identity.
- `scope.repository`: exact match on normalized repository identity from finding artifact target reference (for example `registry.local/payments-api`) or `*`.

Additional scope filters:
- `repository`, `branch_types`, `stages`, `constraints.environments` must all match current context.
- if any filter is absent, treat as wildcard for that filter.

Scanner filter canonical IDs (`scope.scanner`):
- `trivy`
- `snyk`
- `checkmarx`
- `sonar`
- `sarif`

Scanner variant mapping (normalized before comparison):
- values containing `snyk` (for example `snyk-code`) map to `snyk`
- values containing `checkmarx` (or `cx*`) map to `checkmarx`
- values starting with `sonar` (for example `sonar-security`) map to `sonar`
- SARIF-native/unknown SARIF producer names map to `sarif`

## 5) Storage and Audit Semantics

Storage model:
- file committed in repository
- reviewed via normal code review flow

Audit semantics:
- every applied record must be listed in `report.json`
- include `id`, match target, expiry, and approval state
- revoked/expired/invalid records must be listed with rejection reason

## 6) Validation Rules

A record is invalid if:
- required fields missing
- unknown enum value
- malformed timestamps
- `expires_at` in the past with `status=active`
- stage/environment/severity constraints conflict structurally

An invalid record is treated as governance validation failure and handled according to stage-specific failure policy in core engine.

## 7) Approval Rules (Offline Representation)

Required approvals are evaluated from local file content plus policy exception rules.

MVP approval rules:
- effective stage `release` + critical scope requires at least one security approver if policy requires it
- deploy stage + high-or-above requires at least one security approver if policy requires it

Approver representation:
- plain string identities in `approvers` for user IDs (for example `sec-lead`)
- explicit group entries using `group:<name>` (for example `group:security`)
- policy `exception_rules.security_approver_ids` and `exception_rules.security_approver_groups` define allowed security approvers

No external identity provider is used in MVP.

## 8) Expiry and Escalation

- `active` record with `expires_at <= now`: treated as expired.
- Expired records cannot be applied.
- Expiry handling:
  - `release`/`deploy`: fail-closed (`BLOCK`)
  - `pr`/`merge`: fail-open-to-`WARN`
- Imminent expiry window (for example <= 7 days) triggers deterministic recommended step:
  - `REVIEW_ACCEPTED_RISK_EXPIRY`

## 9) Examples

### Example A: Valid finding_id exception
```yaml
schema_version: "1.0"
records:
  - id: "AR-2026-0007"
    status: active
    owner: "payments-platform"
    approvers: ["sec-lead"]
    ticket: "SEC-991"
    rationale: "Awaiting vendor patch 2.4.1"
    scope:
      type: finding_id
      value: "TRIVY-DB-44881"
      scanner: trivy
      repository: "payments-api"
      branch_types: [main, release]
      stages: [merge, release]
    constraints:
      max_severity: high
      environments: [ci]
    timeline:
      created_at: "2026-02-10T09:00:00Z"
      expires_at: "2026-03-05T09:00:00Z"
      sla_days: 23
    metadata:
      created_by: "alice"
      reviewed_by: "sec-lead"
```

### Example B: CVE scoped exception with wildcard repo
```yaml
schema_version: "1.0"
records:
  - id: "AR-2026-0008"
    status: active
    owner: "shared-security"
    approvers: ["sec-architect"]
    ticket: "SEC-1002"
    rationale: "Documented compensating controls in place"
    scope:
      type: cve
      value: "CVE-2025-12345"
      repository: "*"
      branch_types: [feature, main]
      stages: [pr, merge]
    constraints:
      max_severity: medium
      environments: [ci]
    timeline:
      created_at: "2026-02-12T00:00:00Z"
      expires_at: "2026-02-28T00:00:00Z"
      sla_days: 16
```

### Example C: Expired record (invalid for active use)
```yaml
schema_version: "1.0"
records:
  - id: "AR-2025-0999"
    status: active
    owner: "legacy-team"
    approvers: ["sec-lead"]
    ticket: "SEC-777"
    rationale: "Temporary hold"
    scope:
      type: component
      value: "openssl@1.1.1"
    constraints:
      max_severity: high
      environments: [ci, prod]
    timeline:
      created_at: "2025-11-01T00:00:00Z"
      expires_at: "2026-01-01T00:00:00Z"
      sla_days: 61
```

## 10) Security Notes

- Accepted Risk must remain exceptional and time-bounded.
- Records should reference tickets with remediation plans.
- Broad wildcard scope should be minimized and reviewed.
- Hard-stop domains remain non-overridable by design.

## Acceptance Criteria Checklist

- [ ] Accepted Risk schema is explicitly defined.
- [ ] In-repo local storage approach is documented.
- [ ] Validation rules include expiry, enums, and required fields.
- [ ] Offline approval representation and rules are defined.
- [ ] Expiry escalation and stage-dependent failure handling are defined.
- [ ] Audit/report semantics are defined.
- [ ] YAML examples are included.
