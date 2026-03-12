package policy

import (
	"reflect"
	"slices"
	"testing"
)

func TestValidatePolicyReportsContractViolations(t *testing.T) {
	pol := Policy{
		SchemaVersion: "2.0",
		Defaults: PolicyDefaults{
			EnforceOfflineOnly: false,
		},
		StageOverrides: StageOverrides{
			PR:      StageThreshold{WarnFloor: 50, BlockFloor: 50},
			Merge:   StageThreshold{WarnFloor: 10, BlockFloor: 20},
			Release: StageThreshold{WarnFloor: 20, BlockFloor: 30},
			Deploy:  StageThreshold{WarnFloor: 0, BlockFloor: 101},
		},
		Rules: []Rule{
			{
				Then: RuleThen{
					AddRiskPoints: -1,
					MinDecision:   "maybe",
				},
			},
		},
	}

	errs := ValidatePolicy(pol)

	for _, want := range []string{
		"unsupported policy schema_version",
		"enforce_offline_only must be true",
		"invalid stage_overrides thresholds for pr",
		"invalid stage_overrides thresholds for deploy",
		"rule_id required",
		"rule add_risk_points cannot be negative",
		"rule min_decision invalid",
	} {
		if !slices.Contains(errs, want) {
			t.Fatalf("ValidatePolicy() missing error %q from %v", want, errs)
		}
	}
}

func TestApplyRulesAggregatesMatchingRulesDeterministically(t *testing.T) {
	pol := Policy{
		Rules: []Rule{
			{
				RuleID:  "z-last",
				Enabled: true,
				When: RuleWhen{
					Stages:          []string{"pr"},
					BranchTypes:     []string{"feature"},
					Environments:    []string{"ci"},
					RepoCriticality: []string{"high"},
					Exposure:        []string{"internet"},
					ChangeType:      []string{"application"},
				},
				Then: RuleThen{
					AddRiskPoints:         5,
					MinDecision:           DecisionWarn,
					RequireTrustAtLeast:   30,
					AddRecommendedStepIDs: []string{"STEP_B", "STEP_A"},
				},
			},
			{
				RuleID:  "a-first",
				Enabled: true,
				When: RuleWhen{
					Stages: []string{"pr"},
				},
				Then: RuleThen{
					AddRiskPoints:         12,
					MinDecision:           DecisionBlock,
					RequireTrustAtLeast:   20,
					AddRecommendedStepIDs: []string{"STEP_A", "STEP_C"},
				},
			},
			{
				RuleID:  "disabled",
				Enabled: false,
				When: RuleWhen{
					Stages: []string{"pr"},
				},
				Then: RuleThen{
					AddRiskPoints:         99,
					MinDecision:           DecisionBlock,
					RequireTrustAtLeast:   99,
					AddRecommendedStepIDs: []string{"IGNORED"},
				},
			},
			{
				RuleID:  "non-match",
				Enabled: true,
				When: RuleWhen{
					Stages: []string{"deploy"},
				},
				Then: RuleThen{
					AddRiskPoints:         99,
					MinDecision:           DecisionBlock,
					RequireTrustAtLeast:   99,
					AddRecommendedStepIDs: []string{"IGNORED"},
				},
			},
		},
	}

	gotRisk, gotDecision, gotTrust, gotSteps := ApplyRules(pol, Context{
		BranchType:      " Feature ",
		Environment:     "CI",
		RepoCriticality: "HIGH",
		Exposure:        "internet",
		ChangeType:      "application",
	}, "pr")

	if gotRisk != 12 {
		t.Fatalf("ApplyRules() risk = %d, want 12", gotRisk)
	}
	if gotDecision != DecisionBlock {
		t.Fatalf("ApplyRules() decision = %q, want %q", gotDecision, DecisionBlock)
	}
	if gotTrust != 30 {
		t.Fatalf("ApplyRules() required trust = %d, want 30", gotTrust)
	}

	wantSteps := []string{"STEP_A", "STEP_B", "STEP_C"}
	if !reflect.DeepEqual(gotSteps, wantSteps) {
		t.Fatalf("ApplyRules() steps = %v, want %v", gotSteps, wantSteps)
	}
}
