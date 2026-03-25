package policy

import (
	"reflect"
	"slices"
	"testing"
)

func validPolicy() Policy {
	return Policy{
		SchemaVersion: "1.0",
		Defaults:      PolicyDefaults{EnforceOfflineOnly: true},
		StageOverrides: StageOverrides{
			PR:      StageThreshold{WarnFloor: 40, BlockFloor: 70},
			Merge:   StageThreshold{WarnFloor: 30, BlockFloor: 60},
			Release: StageThreshold{WarnFloor: 20, BlockFloor: 50},
			Deploy:  StageThreshold{WarnFloor: 10, BlockFloor: 35},
		},
		Rules: []Rule{},
	}
}

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

func TestValidatePolicyValid(t *testing.T) {
	errs := ValidatePolicy(validPolicy())
	if len(errs) != 0 {
		t.Fatalf("expected no errors for valid policy, got %v", errs)
	}
}

func TestValidatePolicyWarnFloorEqualBlockFloor(t *testing.T) {
	pol := validPolicy()
	pol.PR = StageThreshold{WarnFloor: 50, BlockFloor: 50}
	errs := ValidatePolicy(pol)
	if !slices.Contains(errs, "invalid stage_overrides thresholds for pr") {
		t.Fatalf("expected error for equal warn/block floors, got %v", errs)
	}
}

func TestValidatePolicyNegativeThreshold(t *testing.T) {
	pol := validPolicy()
	pol.Deploy = StageThreshold{WarnFloor: -1, BlockFloor: 10}
	errs := ValidatePolicy(pol)
	if !slices.Contains(errs, "invalid stage_overrides thresholds for deploy") {
		t.Fatalf("expected error for negative threshold, got %v", errs)
	}
}

func TestApplyRulesNoMatchReturnsDefaults(t *testing.T) {
	pol := Policy{
		Rules: []Rule{
			{
				RuleID:  "deploy-only",
				Enabled: true,
				When:    RuleWhen{Stages: []string{"deploy"}},
				Then:    RuleThen{AddRiskPoints: 50, MinDecision: DecisionBlock},
			},
		},
	}
	risk, decision, trust, steps := ApplyRules(pol, Context{}, "pr")
	if risk != 0 {
		t.Fatalf("expected 0 risk points when no rule matches, got %d", risk)
	}
	if decision != DecisionAllow {
		t.Fatalf("expected ALLOW when no rule matches, got %s", decision)
	}
	if trust != 0 {
		t.Fatalf("expected 0 required trust when no rule matches, got %d", trust)
	}
	if len(steps) != 0 {
		t.Fatalf("expected no steps when no rule matches, got %v", steps)
	}
}

func TestApplyRulesDisabledRulesNotApplied(t *testing.T) {
	pol := Policy{
		Rules: []Rule{
			{
				RuleID:  "all-disabled",
				Enabled: false,
				When:    RuleWhen{},
				Then:    RuleThen{AddRiskPoints: 99, MinDecision: DecisionBlock},
			},
		},
	}
	risk, decision, _, _ := ApplyRules(pol, Context{}, "pr")
	if risk != 0 || decision != DecisionAllow {
		t.Fatalf("disabled rules must not be applied, got risk=%d decision=%s", risk, decision)
	}
}

func TestTighterDecision(t *testing.T) {
	cases := []struct {
		current, candidate, want string
	}{
		{DecisionAllow, DecisionWarn, DecisionWarn},
		{DecisionAllow, DecisionBlock, DecisionBlock},
		{DecisionWarn, DecisionAllow, DecisionWarn},
		{DecisionWarn, DecisionBlock, DecisionBlock},
		{DecisionBlock, DecisionWarn, DecisionBlock},
		{DecisionBlock, DecisionAllow, DecisionBlock},
		{DecisionAllow, DecisionAllow, DecisionAllow},
	}
	for _, c := range cases {
		got := tighterDecision(c.current, c.candidate)
		if got != c.want {
			t.Fatalf("tighterDecision(%s, %s) = %s, want %s", c.current, c.candidate, got, c.want)
		}
	}
}

func TestContainsPolicy(t *testing.T) {
	if !contains(nil, "x") {
		t.Fatal("empty list should match any target")
	}
	if !contains([]string{"FOO"}, "foo") {
		t.Fatal("contains must be case-insensitive")
	}
	if contains([]string{"a"}, "b") {
		t.Fatal("contains returned true for non-member")
	}
}
