# Policy Format (Authoritative)

This document is the single authority for policy YAML schema. It defines structure and semantics for policy-as-code consumed by `security-gate`.

Do not redefine risk formulas, hard-stop precedence, or decision matrices here. Those remain authoritative in `docs/md/core-decision-engine.md`.

## 1) File Location and Encoding

Recommended file path:
- `.security-gate/policy.yaml`

Requirements:
- UTF-8 text
- YAML 1.2 compatible
- Deterministic parsing (duplicate keys are invalid)

## 2) Top-Level Schema

```yaml
schema_version: "1.0"
policy_id: "string"
policy_name: "string"
defaults:
  enforce_offline_only: true
  llm_enabled: false
  scan_freshness_hours: 24
  unknown_signal_mode: "tighten"      # tighten | block_release
  decision_trace_verbosity: "normal"  # minimal | normal | verbose

stage_overrides:
  pr:
    warn_floor: 45
    block_floor: 75
  merge:
    warn_floor: 35
    block_floor: 65
  release:
    warn_floor: 25
    block_floor: 50
  deploy:
    warn_floor: 15
    block_floor: 35

trust_tightening:
  enabled: true
  release_warn_if_trust_below: 40
  deploy_block_if_trust_below: 25
  additional_risk_penalties:
    trust_60_79: 5
    trust_40_59: 10
    trust_20_39: 15
    trust_0_19: 20

domain_overrides:
  additional_hard_stops: []
  severity_boosts: []

noise_budget:
  enabled: true
  stage_limits:
    pr: 30
    merge: 50
  suppress_below_severity: "medium"   # low | medium | high

exception_rules:
  require_security_approval:
    release_critical: true
    deploy_high_or_above: true
  allow_scope_types:
    - finding_id
    - cve
    - component
  security_approver_ids: ["sec-lead"]
  security_approver_groups: ["security"]

rules: []
```

## 3) Field Definitions

### Required Fields
- `schema_version` (string): must equal `"1.0"` for MVP.
- `policy_id` (string): stable identifier, used in reports.
- `policy_name` (string): human readable label.
- `defaults` (object)
- `stage_overrides` (object)
- `trust_tightening` (object)
- `domain_overrides` (object)
- `noise_budget` (object)
- `exception_rules` (object)
- `rules` (array; may be empty)

### `defaults`
- `enforce_offline_only` (bool): must be `true` for MVP.
- `llm_enabled` (bool): defaults to `false`.
- `scan_freshness_hours` (int 1..720)
- `unknown_signal_mode`:
  - `tighten`: unknowns add trust penalties/risk tightening.
  - `block_release`: unknowns in release/deploy cause validation error.
- `decision_trace_verbosity`: `minimal | normal | verbose`

### `stage_overrides`
Threshold overrides by stage. Values must satisfy:
- `warn_floor` and `block_floor` within `0..100`
- `warn_floor < block_floor`

These values can tighten or relax thresholds compared to defaults in `core-decision-engine`, but cannot violate hard-stop or validation precedence.

### `trust_tightening`
- `enabled` (bool)
- `release_warn_if_trust_below` (0..100)
- `deploy_block_if_trust_below` (0..100)
- `additional_risk_penalties`: integer penalties keyed by trust bands

Penalty keys must be exactly:
- `trust_60_79`
- `trust_40_59`
- `trust_20_39`
- `trust_0_19`

### `domain_overrides`
- `additional_hard_stops`: array of domain IDs to treat as hard-stop in addition to canonical hard-stops.
- `severity_boosts`: array of boost rules:

```yaml
severity_boosts:
  - domain_id: "SUPPLY_CHAIN_DRIFT"
    add_points: 10          # 0..30
    stages: ["merge", "release", "deploy"]
```

Constraints:
- Policy cannot remove canonical hard-stop domains from core engine.
- `add_points` must be non-negative.

### `noise_budget`
Presentation-only controls.
- `enabled` (bool)
- `stage_limits`: supported stages `pr`, `merge`
- `suppress_below_severity`: `low | medium | high`

Constraint:
- Must not alter computed risk or decision.

### `exception_rules`
Defines gating for Accepted Risk consumption.

Fields:
- `require_security_approval.release_critical` (bool)
- `require_security_approval.deploy_high_or_above` (bool)
- `allow_scope_types`: any subset of `finding_id`, `cve`, `component`
- `security_approver_ids`: explicit allowed user IDs for security approval matching
- `security_approver_groups`: explicit allowed group names for approval matching via `group:<name>` approver entries

Constraint:
- if `require_security_approval.release_critical` or `require_security_approval.deploy_high_or_above` is `true`, at least one of `security_approver_ids` or `security_approver_groups` must be non-empty.

### `rules` (Stage-Aware Conditional Tightening)
Each rule:

```yaml
- rule_id: "string"
  enabled: true
  when:
    stages: ["pr", "merge", "release", "deploy"]
    branch_types: ["dev", "feature", "main", "release"]
    environments: ["ci", "prod"]
    repo_criticality: ["low", "medium", "high", "mission_critical", "unknown"]
    exposure: ["isolated", "internal", "internet", "unknown"]
    change_type: ["docs_or_tests", "application", "infra_or_supply_chain", "security_sensitive", "unknown"]
  then:
    add_risk_points: 0        # 0..30
    min_decision: "ALLOW"    # ALLOW | WARN | BLOCK
    require_trust_at_least: 0 # 0..100
    add_recommended_step_ids: []
```

Rule constraints:
- `add_risk_points` cannot be negative.
- `min_decision` can only tighten (`ALLOW->WARN->BLOCK`) and never loosen.
- `require_trust_at_least` failure upgrades decision to at least `WARN`; if stage is `deploy`, policy may set `BLOCK` via `min_decision`.
- `add_recommended_step_ids` must reference IDs defined in core decision engine.

Conflict handling:
- Evaluate enabled rules in lexicographic `rule_id` order.
- Aggregate by taking max of `add_risk_points` and strictest `min_decision`.
- If multiple `require_trust_at_least`, highest value wins.

## 4) Validation Rules

Policy file is invalid if any of the following occur:
- unknown top-level field (strict mode for MVP)
- duplicate keys
- unsupported `schema_version`
- thresholds out of range
- stage names outside canonical enum
- rule references unknown recommended step IDs

Failure handling follows `core-decision-engine` validation mode by effective stage.

## 5) YAML Examples

### Example 1: Minimal Baseline
```yaml
schema_version: "1.0"
policy_id: "baseline-v1"
policy_name: "Baseline local gate"
defaults:
  enforce_offline_only: true
  llm_enabled: false
  scan_freshness_hours: 24
  unknown_signal_mode: tighten
  decision_trace_verbosity: normal
stage_overrides:
  pr: { warn_floor: 45, block_floor: 75 }
  merge: { warn_floor: 35, block_floor: 65 }
  release: { warn_floor: 25, block_floor: 50 }
  deploy: { warn_floor: 15, block_floor: 35 }
trust_tightening:
  enabled: true
  release_warn_if_trust_below: 40
  deploy_block_if_trust_below: 25
  additional_risk_penalties:
    trust_60_79: 5
    trust_40_59: 10
    trust_20_39: 15
    trust_0_19: 20
domain_overrides:
  additional_hard_stops: []
  severity_boosts: []
noise_budget:
  enabled: true
  stage_limits: { pr: 30, merge: 50 }
  suppress_below_severity: medium
exception_rules:
  require_security_approval:
    release_critical: true
    deploy_high_or_above: true
  allow_scope_types: [finding_id, cve, component]
  security_approver_ids: [sec-lead]
  security_approver_groups: [security]
rules: []
```

### Example 2: Strict Release and Deploy Thresholds
```yaml
schema_version: "1.0"
policy_id: "strict-release-v1"
policy_name: "Strict release controls"
defaults:
  enforce_offline_only: true
  llm_enabled: false
  scan_freshness_hours: 12
  unknown_signal_mode: block_release
  decision_trace_verbosity: verbose
stage_overrides:
  pr: { warn_floor: 45, block_floor: 75 }
  merge: { warn_floor: 30, block_floor: 60 }
  release: { warn_floor: 20, block_floor: 40 }
  deploy: { warn_floor: 10, block_floor: 25 }
trust_tightening:
  enabled: true
  release_warn_if_trust_below: 50
  deploy_block_if_trust_below: 35
  additional_risk_penalties:
    trust_60_79: 8
    trust_40_59: 12
    trust_20_39: 18
    trust_0_19: 24
domain_overrides:
  additional_hard_stops: []
  severity_boosts: []
noise_budget:
  enabled: true
  stage_limits: { pr: 20, merge: 40 }
  suppress_below_severity: high
exception_rules:
  require_security_approval:
    release_critical: true
    deploy_high_or_above: true
  allow_scope_types: [finding_id, cve]
  security_approver_ids: [sec-lead]
  security_approver_groups: [security]
rules: []
```

### Example 3: Additional Hard-Stop Domain
```yaml
schema_version: "1.0"
policy_id: "supplychain-hardstop-v1"
policy_name: "Add supply chain hard-stop"
defaults:
  enforce_offline_only: true
  llm_enabled: false
  scan_freshness_hours: 24
  unknown_signal_mode: tighten
  decision_trace_verbosity: normal
stage_overrides:
  pr: { warn_floor: 45, block_floor: 75 }
  merge: { warn_floor: 35, block_floor: 65 }
  release: { warn_floor: 25, block_floor: 50 }
  deploy: { warn_floor: 15, block_floor: 35 }
trust_tightening:
  enabled: true
  release_warn_if_trust_below: 40
  deploy_block_if_trust_below: 25
  additional_risk_penalties:
    trust_60_79: 5
    trust_40_59: 10
    trust_20_39: 15
    trust_0_19: 20
domain_overrides:
  additional_hard_stops:
    - "HS_SUPPLY_CHAIN_KEY_COMPROMISE"
  severity_boosts: []
noise_budget:
  enabled: true
  stage_limits: { pr: 30, merge: 50 }
  suppress_below_severity: medium
exception_rules:
  require_security_approval:
    release_critical: true
    deploy_high_or_above: true
  allow_scope_types: [finding_id, cve, component]
  security_approver_ids: [sec-lead]
  security_approver_groups: [security]
rules: []
```

### Example 4: Domain Severity Boost for Merge+
```yaml
schema_version: "1.0"
policy_id: "domain-boost-v1"
policy_name: "Increase supply chain weighting"
defaults:
  enforce_offline_only: true
  llm_enabled: false
  scan_freshness_hours: 24
  unknown_signal_mode: tighten
  decision_trace_verbosity: normal
stage_overrides:
  pr: { warn_floor: 45, block_floor: 75 }
  merge: { warn_floor: 35, block_floor: 65 }
  release: { warn_floor: 25, block_floor: 50 }
  deploy: { warn_floor: 15, block_floor: 35 }
trust_tightening:
  enabled: true
  release_warn_if_trust_below: 40
  deploy_block_if_trust_below: 25
  additional_risk_penalties:
    trust_60_79: 5
    trust_40_59: 10
    trust_20_39: 15
    trust_0_19: 20
domain_overrides:
  additional_hard_stops: []
  severity_boosts:
    - domain_id: "SUPPLY_CHAIN_DRIFT"
      add_points: 10
      stages: [merge, release, deploy]
noise_budget:
  enabled: true
  stage_limits: { pr: 30, merge: 50 }
  suppress_below_severity: medium
exception_rules:
  require_security_approval:
    release_critical: true
    deploy_high_or_above: true
  allow_scope_types: [finding_id, cve, component]
  security_approver_ids: [sec-lead]
  security_approver_groups: [security]
rules: []
```

### Example 5: Trust-Based Rule for Mission Critical Repos
```yaml
schema_version: "1.0"
policy_id: "mission-critical-trust-v1"
policy_name: "Trust floor for mission critical"
defaults:
  enforce_offline_only: true
  llm_enabled: false
  scan_freshness_hours: 24
  unknown_signal_mode: tighten
  decision_trace_verbosity: normal
stage_overrides:
  pr: { warn_floor: 45, block_floor: 75 }
  merge: { warn_floor: 35, block_floor: 65 }
  release: { warn_floor: 25, block_floor: 50 }
  deploy: { warn_floor: 15, block_floor: 35 }
trust_tightening:
  enabled: true
  release_warn_if_trust_below: 40
  deploy_block_if_trust_below: 25
  additional_risk_penalties:
    trust_60_79: 5
    trust_40_59: 10
    trust_20_39: 15
    trust_0_19: 20
domain_overrides:
  additional_hard_stops: []
  severity_boosts: []
noise_budget:
  enabled: true
  stage_limits: { pr: 30, merge: 50 }
  suppress_below_severity: medium
exception_rules:
  require_security_approval:
    release_critical: true
    deploy_high_or_above: true
  allow_scope_types: [finding_id, cve, component]
  security_approver_ids: [sec-lead]
  security_approver_groups: [security]
rules:
  - rule_id: "mc-release-trust-floor"
    enabled: true
    when:
      stages: [release, deploy]
      branch_types: [release]
      environments: [ci, prod]
      repo_criticality: [mission_critical]
      exposure: [internet, internal, unknown]
      change_type: [application, infra_or_supply_chain, security_sensitive, unknown]
    then:
      add_risk_points: 5
      min_decision: WARN
      require_trust_at_least: 55
      add_recommended_step_ids: [COMPLETE_MISSING_CONTEXT]
```

### Example 6: Security-Sensitive Change Tightening
```yaml
schema_version: "1.0"
policy_id: "security-change-v1"
policy_name: "Tighten for security-sensitive diffs"
defaults:
  enforce_offline_only: true
  llm_enabled: false
  scan_freshness_hours: 24
  unknown_signal_mode: tighten
  decision_trace_verbosity: normal
stage_overrides:
  pr: { warn_floor: 45, block_floor: 75 }
  merge: { warn_floor: 35, block_floor: 65 }
  release: { warn_floor: 25, block_floor: 50 }
  deploy: { warn_floor: 15, block_floor: 35 }
trust_tightening:
  enabled: true
  release_warn_if_trust_below: 40
  deploy_block_if_trust_below: 25
  additional_risk_penalties:
    trust_60_79: 5
    trust_40_59: 10
    trust_20_39: 15
    trust_0_19: 20
domain_overrides:
  additional_hard_stops: []
  severity_boosts: []
noise_budget:
  enabled: true
  stage_limits: { pr: 30, merge: 50 }
  suppress_below_severity: medium
exception_rules:
  require_security_approval:
    release_critical: true
    deploy_high_or_above: true
  allow_scope_types: [finding_id, cve, component]
  security_approver_ids: [sec-lead]
  security_approver_groups: [security]
rules:
  - rule_id: "security-sensitive-min-warn"
    enabled: true
    when:
      stages: [merge, release, deploy]
      branch_types: [main, release]
      environments: [ci, prod]
      repo_criticality: [high, mission_critical, unknown]
      exposure: [internet, internal, unknown]
      change_type: [security_sensitive]
    then:
      add_risk_points: 8
      min_decision: WARN
      require_trust_at_least: 50
      add_recommended_step_ids: [REMEDIATE_TOP_FINDING]
```

### Example 7: PR Friction Reduction (Presentation Only)
```yaml
schema_version: "1.0"
policy_id: "pr-fx-v1"
policy_name: "Reduce PR annotation noise"
defaults:
  enforce_offline_only: true
  llm_enabled: false
  scan_freshness_hours: 24
  unknown_signal_mode: tighten
  decision_trace_verbosity: minimal
stage_overrides:
  pr: { warn_floor: 45, block_floor: 75 }
  merge: { warn_floor: 35, block_floor: 65 }
  release: { warn_floor: 25, block_floor: 50 }
  deploy: { warn_floor: 15, block_floor: 35 }
trust_tightening:
  enabled: true
  release_warn_if_trust_below: 40
  deploy_block_if_trust_below: 25
  additional_risk_penalties:
    trust_60_79: 5
    trust_40_59: 10
    trust_20_39: 15
    trust_0_19: 20
domain_overrides:
  additional_hard_stops: []
  severity_boosts: []
noise_budget:
  enabled: true
  stage_limits:
    pr: 15
    merge: 25
  suppress_below_severity: high
exception_rules:
  require_security_approval:
    release_critical: true
    deploy_high_or_above: true
  allow_scope_types: [finding_id, cve, component]
  security_approver_ids: [sec-lead]
  security_approver_groups: [security]
rules: []
```

### Example 8: Multi-Rule Enterprise Profile
```yaml
schema_version: "1.0"
policy_id: "enterprise-profile-v1"
policy_name: "Enterprise profile"
defaults:
  enforce_offline_only: true
  llm_enabled: false
  scan_freshness_hours: 24
  unknown_signal_mode: block_release
  decision_trace_verbosity: verbose
stage_overrides:
  pr: { warn_floor: 45, block_floor: 75 }
  merge: { warn_floor: 32, block_floor: 62 }
  release: { warn_floor: 22, block_floor: 45 }
  deploy: { warn_floor: 12, block_floor: 30 }
trust_tightening:
  enabled: true
  release_warn_if_trust_below: 45
  deploy_block_if_trust_below: 30
  additional_risk_penalties:
    trust_60_79: 6
    trust_40_59: 11
    trust_20_39: 16
    trust_0_19: 22
domain_overrides:
  additional_hard_stops:
    - "HS_SBOM_TAMPERED"
  severity_boosts:
    - domain_id: "LICENSE_RECIPROCITY_RISK"
      add_points: 7
      stages: [merge, release, deploy]
noise_budget:
  enabled: true
  stage_limits: { pr: 20, merge: 35 }
  suppress_below_severity: high
exception_rules:
  require_security_approval:
    release_critical: true
    deploy_high_or_above: true
  allow_scope_types: [finding_id, cve, component]
  security_approver_ids: [sec-lead]
  security_approver_groups: [security]
rules:
  - rule_id: "internet-release-tighten"
    enabled: true
    when:
      stages: [release, deploy]
      branch_types: [release]
      environments: [ci, prod]
      repo_criticality: [high, mission_critical, unknown]
      exposure: [internet]
      change_type: [application, infra_or_supply_chain, security_sensitive, unknown]
    then:
      add_risk_points: 10
      min_decision: WARN
      require_trust_at_least: 60
      add_recommended_step_ids: [REMEDIATE_TOP_FINDING, SECURITY_APPROVAL_REQUIRED]
  - rule_id: "main-merge-supply-chain"
    enabled: true
    when:
      stages: [merge]
      branch_types: [main]
      environments: [ci]
      repo_criticality: [medium, high, mission_critical, unknown]
      exposure: [internal, internet, unknown]
      change_type: [infra_or_supply_chain, security_sensitive]
    then:
      add_risk_points: 6
      min_decision: WARN
      require_trust_at_least: 50
      add_recommended_step_ids: [REFRESH_SCANS]
```

## 6) Compatibility and Versioning

- MVP supports `schema_version: "1.0"` only.
- Future versions must use explicit migration docs and cannot silently reinterpret fields.
- Unknown schema versions are validation failures.

## Acceptance Criteria Checklist

- [ ] Policy YAML authority is clearly defined and isolated from engine formulas.
- [ ] `schema_version` contract is explicit.
- [ ] Stage-aware threshold structure is defined.
- [ ] Domain override rules are defined and cannot weaken canonical hard-stops.
- [ ] Exception/approval policy controls are defined.
- [ ] Trust-based tightening controls are defined.
- [ ] Deterministic rule evaluation and conflict handling are defined.
- [ ] Validation failure conditions are explicit.
- [ ] 6-10 valid YAML examples are provided.
