package securitygate

import (
	"strings"
	"testing"
)

func TestValidatePolicyDefaultsEnumAndRangeChecks(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Policy)
		wantError string
	}{
		{
			name: "invalid unknown_signal_mode",
			mutate: func(p *Policy) {
				p.Defaults.UnknownSignalMode = "invalid"
			},
			wantError: "defaults.unknown_signal_mode",
		},
		{
			name: "invalid decision_trace_verbosity",
			mutate: func(p *Policy) {
				p.Defaults.DecisionTraceVerbosity = "chatty"
			},
			wantError: "defaults.decision_trace_verbosity",
		},
		{
			name: "invalid scan_freshness_hours",
			mutate: func(p *Policy) {
				p.Defaults.ScanFreshnessHours = 0
			},
			wantError: "defaults.scan_freshness_hours",
		},
		{
			name: "invalid allow_scope_types value",
			mutate: func(p *Policy) {
				p.ExceptionRules.AllowScopeTypes = []string{"finding_id", "ticket"}
			},
			wantError: "exception_rules.allow_scope_types",
		},
		{
			name: "invalid rule stage enum",
			mutate: func(p *Policy) {
				p.Rules = []PolicyRule{
					{
						RuleID:  "r1",
						Enabled: true,
						When: RuleWhen{
							Stages:          []string{"prod-release"},
							BranchTypes:     []string{"feature"},
							Environments:    []string{"ci"},
							RepoCriticality: []string{"high"},
							Exposure:        []string{"internet"},
							ChangeType:      []string{"application"},
						},
						Then: RuleThen{
							AddRiskPoints:       10,
							MinDecision:         DecisionWarn,
							RequireTrustAtLeast: 50,
						},
					},
				}
			},
			wantError: "rules.when.stages",
		},
		{
			name: "invalid rule recommended step id",
			mutate: func(p *Policy) {
				p.Rules = []PolicyRule{
					{
						RuleID:  "r1",
						Enabled: true,
						When: RuleWhen{
							Stages:          []string{"merge"},
							BranchTypes:     []string{"main"},
							Environments:    []string{"ci"},
							RepoCriticality: []string{"high"},
							Exposure:        []string{"internet"},
							ChangeType:      []string{"application"},
						},
						Then: RuleThen{
							AddRiskPoints:         5,
							MinDecision:           DecisionWarn,
							RequireTrustAtLeast:   30,
							AddRecommendedStepIDs: []string{"NOT_A_STEP"},
						},
					},
				}
			},
			wantError: "rules.then.add_recommended_step_ids",
		},
		{
			name: "invalid noise budget stage limit key",
			mutate: func(p *Policy) {
				p.NoiseBudget.StageLimits["deploy"] = 10
			},
			wantError: "noise_budget.stage_limits",
		},
		{
			name: "missing security approver identities",
			mutate: func(p *Policy) {
				p.ExceptionRules.SecurityApproverIDs = nil
				p.ExceptionRules.SecurityApproverGroups = nil
			},
			wantError: "exception_rules requires security_approver_ids or security_approver_groups",
		},
		{
			name: "empty security approver id entry",
			mutate: func(p *Policy) {
				p.ExceptionRules.SecurityApproverIDs = []string{"sec-lead", ""}
			},
			wantError: "exception_rules.security_approver_ids",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := defaultPolicy()
			tc.mutate(&p)
			errs := validatePolicy(p)
			if !containsPolicyValidationError(errs, tc.wantError) {
				t.Fatalf("expected error containing %q, got %v", tc.wantError, errs)
			}
		})
	}
}

func containsPolicyValidationError(errs []string, want string) bool {
	for _, e := range errs {
		if strings.Contains(e, want) {
			return true
		}
	}
	return false
}
