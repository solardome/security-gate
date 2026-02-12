package policy

import (
	"strings"
	"time"

	"github.com/solardome/security-gate/internal/domain"
	"github.com/solardome/security-gate/internal/scoring"
)

func applyPolicyRules(decision PolicyDecision, input EvaluationInput, stage Stage, releaseRisk, maxFindingRisk int, consideredSet, scoringSet []scoring.ScoredFinding, coverage map[string][]string, appliedRiskIDs []string, fingerprintCoverage map[string]bool) (policyResult, error) {
	result := policyResult{decision: decision, evaluation: PolicyEvaluation{AcceptedRisksApplied: appliedRiskIDs, AcceptedRisksCoverage: copyCoverage(coverage)}}

	for _, rule := range input.Policy.Rules {
		if rule.Enabled != nil && !*rule.Enabled {
			continue
		}
		if !stageInScope(stage, rule.StageScope) {
			continue
		}
		if !ruleConditionMatches(rule.When, releaseRisk, maxFindingRisk, input.ScoreResult.TrustScore, scoringSet, input.Exposure, input.ChangeType) {
			continue
		}

		result.evaluation.EvaluatedRules = append(result.evaluation.EvaluatedRules, rule.ID)

		if rule.Then.Decision != domain.DecisionType("") {
			result.decision = tightenDecision(result.decision, rule.Then.Decision)
			result.decision.ExitCode = decisionExitCode(result.decision)
		}

		if rule.Then.WarnToBlock != nil && *rule.Then.WarnToBlock && stage == StageProd && result.decision.Status == domain.DecisionWarn {
			result.decision.Status = domain.DecisionBlock
			result.decision.ExitCode = 2
			result.decision.Rationale += "; warn_to_block escalated"
			result.events = append(result.events, newDecisionTraceEvent("policy.warn_to_block.escalated", map[string]any{"rule_id": rule.ID}, input.Now))
		}

		if len(rule.Then.AddRequiredSteps) > 0 {
			for _, step := range rule.Then.AddRequiredSteps {
				result.extraSteps = appendIfMissing(result.extraSteps, step)
			}
		}

		if rule.Then.RequireAcceptedRisk != nil {
			selectorSet := scoringSet
			if rule.Then.RequireAcceptedRisk.Scope == ScopeConsideredSet {
				selectorSet = consideredSet
			}
			matched := selectFingerprints(rule.Then.RequireAcceptedRisk.Selector, selectorSet)
			if len(matched) == 0 {
				continue
			}
			uncovered := []string{}
			for _, fingerprint := range matched {
				if !fingerprintCoverage[fingerprint] {
					uncovered = append(uncovered, fingerprint)
				}
			}
			if len(uncovered) > 0 {
				event := newDecisionTraceEvent("policy.require_accepted_risk.missing", map[string]any{
					"rule_id":              rule.ID,
					"stage":                stage,
					"matched_fingerprints": takeFirstN(matched, 20),
					"missing_fingerprints": takeFirstN(uncovered, 20),
					"missing_count":        len(uncovered),
				}, input.Now)
				result.events = append(result.events, event)
				result.extraSteps = appendIfMissing(result.extraSteps, "ADD_ACCEPTED_RISK")
				if stage == StagePR {
					if result.decision.Status == domain.DecisionAllow {
						result.decision.Status = domain.DecisionWarn
					}
					result.decision.ExitCode = 1
					result.decision.Rationale += "; require_accepted_risk missing"
				} else {
					result.decision.Status = domain.DecisionBlock
					result.decision.ExitCode = 2
					result.decision.Rationale += "; require_accepted_risk missing"
				}
			}
		}
	}

	return result, nil
}

func copyCoverage(source map[string][]string) map[string][]string {
	if len(source) == 0 {
		return map[string][]string{}
	}
	target := make(map[string][]string, len(source))
	for k, v := range source {
		target[k] = append([]string{}, v...)
	}
	return target
}

func tightenDecision(current PolicyDecision, candidate domain.DecisionType) PolicyDecision {
	if decisionRank(candidate) <= decisionRank(current.Status) {
		return current
	}
	return PolicyDecision{Status: candidate, ExitCode: decisionExitCode(PolicyDecision{Status: candidate}), Rationale: current.Rationale}
}

func decisionRank(status domain.DecisionType) int {
	switch status {
	case domain.DecisionAllow:
		return 0
	case domain.DecisionWarn:
		return 1
	case domain.DecisionBlock:
		return 2
	default:
		return 0
	}
}

func ruleConditionMatches(cond RuleCondition, releaseRisk, maxFindingRisk, trustScore int, findings []scoring.ScoredFinding, exposure, changeType string) bool {
	if cond.ReleaseRiskGTE != nil && releaseRisk < *cond.ReleaseRiskGTE {
		return false
	}
	if cond.ReleaseRiskLTE != nil && releaseRisk > *cond.ReleaseRiskLTE {
		return false
	}
	if cond.TrustScoreGTE != nil && trustScore < *cond.TrustScoreGTE {
		return false
	}
	if cond.TrustScoreLT != nil && trustScore >= *cond.TrustScoreLT {
		return false
	}
	if cond.MaxRiskGTE != nil && maxFindingRisk < *cond.MaxRiskGTE {
		return false
	}
	if cond.MaxRiskLTE != nil && maxFindingRisk > *cond.MaxRiskLTE {
		return false
	}
	if cond.DomainIn != nil && !findingMatchesDomain(cond.DomainIn, findings) {
		return false
	}
	if cond.SeverityIn != nil && !findingMatchesSeverity(cond.SeverityIn, findings) {
		return false
	}
	if cond.ChangeTypeIn != nil && !stringInSlice(changeType, cond.ChangeTypeIn) {
		return false
	}
	if cond.ExposureIn != nil && !stringInSlice(exposure, cond.ExposureIn) {
		return false
	}
	if cond.FixAvailableIn != nil && !findingMatchesFix(cond.FixAvailableIn, findings) {
		return false
	}
	if cond.HasHardStop != nil && *cond.HasHardStop != hasHardStop(findings) {
		return false
	}
	return true
}

func findingMatchesDomain(domains []string, findings []scoring.ScoredFinding) bool {
	for _, f := range findings {
		if stringInSlice(f.Finding.Domain, domains) {
			return true
		}
	}
	return false
}

func findingMatchesSeverity(severities []string, findings []scoring.ScoredFinding) bool {
	for _, f := range findings {
		if stringInSlice(f.Finding.Severity, severities) {
			return true
		}
	}
	return false
}

func findingMatchesFix(fixStates []string, findings []scoring.ScoredFinding) bool {
	for _, f := range findings {
		if stringInSlice(f.Finding.FixAvailable, fixStates) {
			return true
		}
	}
	return false
}

func selectFingerprints(selector RequireAcceptedRiskSelector, dataset []scoring.ScoredFinding) []string {
	var result []string
	ordered := orderDeterministic(dataset)
	switch strings.ToLower(strings.TrimSpace(selector.Type)) {
	case "all_high_or_critical":
		for _, f := range ordered {
			if f.HardStop {
				continue
			}
			if isHighSeverity(f.Finding.Severity) {
				result = appendIfMissing(result, f.Finding.Fingerprint)
			}
		}
	default:
		topN := selector.TopN
		if topN == nil {
			count := 1
			topN = &count
		}
		n := *topN
		if n < 1 {
			n = 1
		}
		if n > 10 {
			n = 10
		}
		for _, f := range ordered {
			if f.HardStop {
				continue
			}
			if len(result) >= n {
				break
			}
			result = append(result, f.Finding.Fingerprint)
		}
	}
	return result
}

func applyProdWarnEscalation(decision *PolicyDecision, stage Stage, scoringSet []scoring.ScoredFinding, allowCoverage map[string]bool, now time.Time) (*DecisionTraceEvent, bool) {
	if stage != StageProd || decision.Status != domain.DecisionWarn {
		return nil, false
	}
	warnSet := warnCausingFingerprints(scoringSet)
	if len(warnSet) == 0 {
		return nil, false
	}
	uncovered := []string{}
	for _, fp := range warnSet {
		if !allowCoverage[fp] {
			uncovered = append(uncovered, fp)
		}
	}
	if len(uncovered) > 0 {
		decision.Status = domain.DecisionBlock
		decision.ExitCode = 2
		decision.Rationale += "; prod warn_to_block escalation"
		event := newDecisionTraceEvent("policy.warn_to_block.escalated", map[string]any{
			"uncovered_fingerprints":    takeFirstN(uncovered, 20),
			"warn_causing_fingerprints": takeFirstN(warnSet, 20),
			"reason":                    "allow_warn_in_prod coverage incomplete",
		}, now)
		return &event, false
	}
	event := newDecisionTraceEvent("policy.allow_warn_in_prod.applied", map[string]any{
		"covered_fingerprints": takeFirstN(warnSet, 20),
		"reason":               "allow_warn_in_prod coverage satisfied",
	}, now)
	return &event, true
}

func warnCausingFingerprints(scoringSet []scoring.ScoredFinding) []string {
	candidates := []string{}
	for _, f := range scoringSet {
		if f.HardStop {
			continue
		}
		if isHighSeverity(f.Finding.Severity) {
			candidates = appendIfMissing(candidates, f.Finding.Fingerprint)
		}
	}
	if len(candidates) > 0 {
		return candidates
	}
	ordered := orderDeterministic(scoringSet)
	for _, f := range ordered {
		if f.HardStop {
			continue
		}
		if f.Finding.Fingerprint != "" {
			return []string{f.Finding.Fingerprint}
		}
	}
	return nil
}
