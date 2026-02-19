package securitygate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseYAMLStrictUnknownField(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	content := `schema_version: "1.0"
policy_id: "p1"
policy_name: "name"
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
rules: []
extra_field: true
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var pol Policy
	_, _, err := parseYAML(p, "policy", &pol)
	if err == nil {
		t.Fatalf("expected error for unknown field")
	}
	s := err.Error()
	if !strings.Contains(s, "line") || !strings.Contains(s, "policy.extra_field") || !strings.Contains(s, "unknown field") {
		t.Fatalf("unexpected error text: %s", s)
	}
}

func TestParseYAMLStrictDuplicateKey(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "context.yaml")
	content := `branch_type: feature
pipeline_stage: pr
environment: ci
repo_criticality: high
exposure: internet
change_type: application
pipeline_stage: merge
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var ctx Context
	_, _, err := parseYAML(p, "context", &ctx)
	if err == nil {
		t.Fatalf("expected error for duplicate key")
	}
	s := err.Error()
	if !strings.Contains(s, "duplicate key") || !strings.Contains(s, "context.pipeline_stage") {
		t.Fatalf("unexpected error text: %s", s)
	}
}
