package policy

import (
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/solardome/security-gate/internal/domain"
	"github.com/solardome/security-gate/internal/ingest/trivy"
	"github.com/solardome/security-gate/internal/scoring"
)

var traceEventCounter atomic.Uint64

const defaultNoiseBudgetTopK = 5

func convertTrace(raw []trivy.TraceEvent) []DecisionTraceEvent {
	converted := make([]DecisionTraceEvent, 0, len(raw))
	for _, event := range raw {
		details := make(map[string]any, len(event.Details)+1)
		for k, v := range event.Details {
			details[k] = v
		}
		if event.Message != "" {
			details["message"] = event.Message
		}
		if len(details) == 0 {
			details = nil
		}
		converted = append(converted, newDecisionTraceEvent(event.Type, details, event.Timestamp))
	}
	return converted
}

func determineNoiseBudget(rules []Rule, stage Stage) (int, *Rule, error) {
	var selected *Rule
	var topK int
	for i := range rules {
		rule := &rules[i]
		if rule.Then.NoiseBudgetTopK == nil {
			continue
		}
		if !stageInScope(stage, rule.StageScope) {
			continue
		}
		if stage != StagePR {
			return 0, nil, PolicyError{Message: fmt.Sprintf("noise budget only allowed in stage=pr, rule=%s", rule.ID)}
		}
		if selected != nil {
			return 0, nil, PolicyError{Message: "multiple noise budget rules target stage=pr"}
		}
		if *rule.Then.NoiseBudgetTopK < 1 {
			return 0, nil, PolicyError{Message: fmt.Sprintf("rule %s noise_budget_top_k must be >= 1", rule.ID)}
		}
		selected = rule
		topK = *rule.Then.NoiseBudgetTopK
	}
	if topK == 0 && stage == StagePR {
		topK = defaultNoiseBudgetTopK
	}
	return topK, selected, nil
}

func applyNoiseBudget(stage Stage, scoringSet []scoring.ScoredFinding, topK int, rule *Rule, now time.Time) ([]scoring.ScoredFinding, *DecisionTraceEvent) {
	if topK <= 0 || stage != StagePR || len(scoringSet) == 0 {
		return scoringSet, nil
	}

	ordered := orderDeterministic(scoringSet)
	kept := 0
	suppressed := make([]string, 0, len(scoringSet))
	indexByFingerprint := make(map[string]int, len(scoringSet))
	for idx, finding := range scoringSet {
		indexByFingerprint[finding.Finding.Fingerprint] = idx
	}

	for _, candidate := range ordered {
		if candidate.HardStop {
			continue
		}
		idx, ok := indexByFingerprint[candidate.Finding.Fingerprint]
		if !ok {
			continue
		}
		if scoringSet[idx].SuppressedByNoiseBudget {
			continue
		}
		if kept < topK {
			kept++
			continue
		}
		scoringSet[idx].SuppressedByNoiseBudget = true
		suppressed = append(suppressed, candidate.Finding.Fingerprint)
	}

	considered := make([]scoring.ScoredFinding, 0, len(scoringSet)-len(suppressed))
	for _, finding := range scoringSet {
		if !finding.SuppressedByNoiseBudget {
			considered = append(considered, finding)
		}
	}

	if len(suppressed) == 0 {
		return considered, nil
	}

	details := map[string]any{
		"suppressed_fingerprints": takeFirstN(suppressed, 20),
		"suppressed_count":        len(suppressed),
		"noise_budget_top_k":      topK,
	}
	if rule != nil {
		details["rule_id"] = rule.ID
	}

	event := newDecisionTraceEvent("noise_budget.applied", details, now)
	return considered, &event
}

func computeMaxRisk(consideredSet []scoring.ScoredFinding) int {
	max := 0
	for _, finding := range consideredSet {
		if finding.RiskScore > max {
			max = finding.RiskScore
		}
	}
	return max
}

func stageModifier(stage Stage) int {
	switch stage {
	case StageMain:
		return 5
	case StageRelease:
		return 10
	case StageProd:
		return 15
	default:
		return 0
	}
}

func exposureModifier(exposure string) int {
	switch strings.ToLower(strings.TrimSpace(exposure)) {
	case "public":
		return 10
	case "internal":
		return 5
	case "private":
		return 0
	default:
		return 5
	}
}

func changeModifier(changeType string) int {
	switch strings.ToLower(strings.TrimSpace(changeType)) {
	case "high_risk":
		return 5
	case "moderate":
		return 3
	case "low":
		return 0
	default:
		return 3
	}
}

func baseStageDecision(stage Stage, releaseRisk, trustScore int) domain.DecisionType {
	switch stage {
	case StageMain:
		if releaseRisk >= 61 || trustScore < 20 {
			return domain.DecisionBlock
		}
		if releaseRisk >= 36 || trustScore < 30 {
			return domain.DecisionWarn
		}
		return domain.DecisionAllow
	case StageRelease:
		if releaseRisk >= 51 || trustScore < 30 {
			return domain.DecisionBlock
		}
		if releaseRisk >= 31 || trustScore < 40 {
			return domain.DecisionWarn
		}
		return domain.DecisionAllow
	case StageProd:
		if releaseRisk >= 41 || trustScore < 40 {
			return domain.DecisionBlock
		}
		if releaseRisk >= 26 || trustScore < 50 {
			return domain.DecisionWarn
		}
		return domain.DecisionAllow
	default:
		if releaseRisk >= 71 || trustScore < 10 {
			return domain.DecisionBlock
		}
		if releaseRisk >= 46 || trustScore < 20 {
			return domain.DecisionWarn
		}
		return domain.DecisionAllow
	}
}

func decisionExitCode(decision PolicyDecision) int {
	switch decision.Status {
	case domain.DecisionAllow:
		return 0
	case domain.DecisionWarn:
		return 1
	case domain.DecisionBlock:
		return 2
	default:
		return 2
	}
}

func hasHardStop(findings []scoring.ScoredFinding) bool {
	for _, f := range findings {
		if f.HardStop {
			return true
		}
	}
	return false
}

func makeDecisionInputs(input EvaluationInput) DecisionInputs {
	scans := make([]ScanInput, 0, len(input.ScanHashes))
	for path, hash := range input.ScanHashes {
		meta := ScanMetadata{}
		if input.ScanMetadata != nil {
			meta = input.ScanMetadata[path]
		}
		sourceScanner := strings.TrimSpace(meta.SourceScanner)
		if sourceScanner == "" {
			sourceScanner = "trivy"
		}
		scans = append(scans, ScanInput{
			SourceScanner: sourceScanner,
			SourceVersion: meta.SourceVersion,
			InputSHA256:   hash,
			ScanTimestamp: meta.ScanTimestamp,
			Path:          path,
		})
	}
	sort.Slice(scans, func(i, j int) bool { return scans[i].Path < scans[j].Path })

	return DecisionInputs{
		Scans:   scans,
		Context: ContextRef{
			InputRef: InputRef{SHA256: input.ContextHash, Source: "context"},
			Payload:  input.ContextPayload,
		},
		Policy:  InputRef{SHA256: input.PolicyHash, Source: "policy"},
		AcceptedRisks: InputRef{
			SHA256: input.AcceptedRiskHash,
			Source: "accepted_risks",
		},
	}
}

func makeFindingsSummary(all, considered []scoring.ScoredFinding) FindingsSummary {
	total := len(all)
	hardStop := 0
	suppressed := 0
	for _, finding := range all {
		if finding.HardStop {
			hardStop++
		}
		if finding.SuppressedByNoiseBudget {
			suppressed++
		}
	}

	return FindingsSummary{
		TotalCount:              total,
		HardStopCount:           hardStop,
		ConsideredCount:         len(considered),
		SuppressedByNoiseBudget: suppressed,
		Items:                   all,
	}
}

func mergeRecommendedSteps(input EvaluationInput, extraSteps []string) []string {
	steps := deterministicRecommendedSteps(input)
	for _, step := range extraSteps {
		steps = appendIfMissing(steps, step)
	}
	if len(steps) == 0 {
		return nil
	}
	return steps
}

func deterministicRecommendedSteps(input EvaluationInput) []string {
	steps := make([]string, 0, 8)
	for _, finding := range input.ScoreResult.Findings {
		domainValue := strings.ToUpper(strings.TrimSpace(finding.Finding.Domain))
		switch domainValue {
		case string(domain.DomainSecret):
			steps = appendIfMissing(steps, "ROTATE_SECRET")
		case string(domain.DomainProvenance):
			steps = appendIfMissing(steps, "VERIFY_PROVENANCE")
		}

		if !strings.EqualFold(finding.Finding.Domain, string(domain.DomainVulnerability)) {
			continue
		}

		rank := severityRank(finding.Finding.Severity)
		if strings.EqualFold(finding.Finding.FixAvailable, "true") && rank >= severityRank(string(domain.SeverityMedium)) {
			steps = appendIfMissing(steps, "FIX_VULN")
		}
		if strings.EqualFold(finding.Finding.FixAvailable, "false") && rank >= severityRank(string(domain.SeverityHigh)) {
			steps = appendIfMissing(steps, "MITIGATE_NO_FIX")
		}
	}

	if input.ScoreResult.TrustSignals.ScannerPinned.Score < 1.0 {
		steps = appendIfMissing(steps, "PIN_SCANNER")
	}
	if input.ScoreResult.TrustSignals.ScanFreshness.Score <= 0.4 {
		steps = appendIfMissing(steps, "REFRESH_SCAN")
	}
	if input.ScoreResult.TrustScore < 40 {
		steps = appendIfMissing(steps, "IMPROVE_TRUST")
	}
	return steps
}

func stageInScope(stage Stage, scope []Stage) bool {
	for _, s := range scope {
		if s == stage {
			return true
		}
	}
	return false
}

func stringInSlice(value string, list []string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, item := range list {
		if strings.ToLower(strings.TrimSpace(item)) == value {
			return true
		}
	}
	return false
}

func toLowerSlice(values []string) []string {
	lower := make([]string, len(values))
	for i, v := range values {
		lower[i] = strings.ToLower(strings.TrimSpace(v))
	}
	return lower
}

func appendIfMissing(slice []string, value string) []string {
	for _, item := range slice {
		if item == value {
			return slice
		}
	}
	return append(slice, value)
}

func takeFirstN(list []string, n int) []string {
	if len(list) <= n {
		return append([]string{}, list...)
	}
	return append([]string{}, list[:n]...)
}

func orderDeterministic(findings []scoring.ScoredFinding) []scoring.ScoredFinding {
	ordered := append([]scoring.ScoredFinding(nil), findings...)
	sort.SliceStable(ordered, func(i, j int) bool {
		left := ordered[i]
		right := ordered[j]
		if left.HardStop != right.HardStop {
			return left.HardStop && !right.HardStop
		}
		if left.RiskScore != right.RiskScore {
			return left.RiskScore > right.RiskScore
		}
		leftSeverity := severityRank(left.Finding.Severity)
		rightSeverity := severityRank(right.Finding.Severity)
		if leftSeverity != rightSeverity {
			return leftSeverity > rightSeverity
		}
		return left.Finding.Fingerprint < right.Finding.Fingerprint
	})
	return ordered
}

func severityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case string(domain.SeverityCritical):
		return 6
	case string(domain.SeverityHigh):
		return 5
	case string(domain.SeverityMedium):
		return 4
	case string(domain.SeverityLow):
		return 3
	case string(domain.SeverityInfo):
		return 2
	case string(domain.SeverityUnknown):
		return 1
	default:
		return 0
	}
}

func clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func newTraceEventID() string {
	return fmt.Sprintf("trace-event-%d", traceEventCounter.Add(1))
}

func newDecisionTraceEvent(eventType string, details map[string]any, timestamp time.Time) DecisionTraceEvent {
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	if len(details) == 0 {
		details = nil
	}
	return DecisionTraceEvent{
		EventID:   newTraceEventID(),
		Timestamp: timestamp,
		Type:      eventType,
		Details:   details,
	}
}
