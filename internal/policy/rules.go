package policy

import (
	"sort"
	"strings"
)

const (
	DecisionAllow = "ALLOW"
	DecisionWarn  = "WARN"
	DecisionBlock = "BLOCK"
)

type Policy struct {
	SchemaVersion string
	Defaults      PolicyDefaults
	StageOverrides
	Rules []Rule
}

type PolicyDefaults struct {
	EnforceOfflineOnly bool
}

type StageThreshold struct {
	WarnFloor  int
	BlockFloor int
}

type StageOverrides struct {
	PR      StageThreshold
	Merge   StageThreshold
	Release StageThreshold
	Deploy  StageThreshold
}

type Context struct {
	BranchType      string
	Environment     string
	RepoCriticality string
	Exposure        string
	ChangeType      string
}

type Rule struct {
	RuleID  string
	Enabled bool
	When    RuleWhen
	Then    RuleThen
}

type RuleWhen struct {
	Stages          []string
	BranchTypes     []string
	Environments    []string
	RepoCriticality []string
	Exposure        []string
	ChangeType      []string
}

type RuleThen struct {
	AddRiskPoints         int
	MinDecision           string
	RequireTrustAtLeast   int
	AddRecommendedStepIDs []string
}

func ValidatePolicy(pol Policy) []string {
	var errs []string
	if pol.SchemaVersion != "1.0" {
		errs = append(errs, "unsupported policy schema_version")
	}
	if !pol.Defaults.EnforceOfflineOnly {
		errs = append(errs, "enforce_offline_only must be true")
	}
	for name, th := range map[string]StageThreshold{
		"pr":      pol.PR,
		"merge":   pol.Merge,
		"release": pol.Release,
		"deploy":  pol.Deploy,
	} {
		if th.WarnFloor < 0 || th.WarnFloor > 100 || th.BlockFloor < 0 || th.BlockFloor > 100 || th.WarnFloor >= th.BlockFloor {
			errs = append(errs, "invalid stage_overrides thresholds for "+name)
		}
	}
	for _, r := range pol.Rules {
		if r.RuleID == "" {
			errs = append(errs, "rule_id required")
		}
		if r.Then.AddRiskPoints < 0 {
			errs = append(errs, "rule add_risk_points cannot be negative")
		}
		if r.Then.MinDecision != DecisionAllow && r.Then.MinDecision != DecisionWarn && r.Then.MinDecision != DecisionBlock {
			errs = append(errs, "rule min_decision invalid")
		}
	}
	return errs
}

func ApplyRules(pol Policy, ctx Context, stage string) (int, string, int, []string) {
	rules := append([]Rule{}, pol.Rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })
	maxRisk := 0
	minDecision := DecisionAllow
	requiredTrust := 0
	stepSet := map[string]bool{}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if !contains(r.When.Stages, stage) ||
			!contains(r.When.BranchTypes, normalizeToken(ctx.BranchType)) ||
			!contains(r.When.Environments, normalizeToken(ctx.Environment)) ||
			!contains(r.When.RepoCriticality, normalizeToken(ctx.RepoCriticality)) ||
			!contains(r.When.Exposure, normalizeToken(ctx.Exposure)) ||
			!contains(r.When.ChangeType, normalizeToken(ctx.ChangeType)) {
			continue
		}
		if r.Then.AddRiskPoints > maxRisk {
			maxRisk = r.Then.AddRiskPoints
		}
		minDecision = tighterDecision(minDecision, r.Then.MinDecision)
		if r.Then.RequireTrustAtLeast > requiredTrust {
			requiredTrust = r.Then.RequireTrustAtLeast
		}
		for _, id := range r.Then.AddRecommendedStepIDs {
			stepSet[id] = true
		}
	}
	steps := make([]string, 0, len(stepSet))
	for s := range stepSet {
		steps = append(steps, s)
	}
	sort.Strings(steps)
	return maxRisk, minDecision, requiredTrust, steps
}

func contains(values []string, target string) bool {
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}

func normalizeToken(s string) string {
	t := strings.TrimSpace(strings.ToLower(s))
	if t == "" {
		return "unknown"
	}
	return t
}

func tighterDecision(current, candidate string) string {
	rank := map[string]int{DecisionAllow: 0, DecisionWarn: 1, DecisionBlock: 2}
	if rank[candidate] > rank[current] {
		return candidate
	}
	return current
}
