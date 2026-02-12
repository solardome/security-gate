package policy

import (
	"strings"
	"time"

	"github.com/solardome/security-gate/internal/domain"
	"github.com/solardome/security-gate/internal/ingest/trivy"
	"github.com/solardome/security-gate/internal/scoring"
)

// governanceResult bundles the outputs from accepted risk evaluation.
type governanceResult struct {
	scoringSet          []scoring.ScoredFinding
	coverage            map[string][]string
	appliedRiskIDs      []string
	allowWarnCoverage   map[string]bool
	fingerprintCoverage map[string]bool
	events              []DecisionTraceEvent
	exceptionsApplied   []string
	warnFloor           bool
	expiredWarnFloor    bool
	expiredEscalation   bool
	allFindings         []scoring.ScoredFinding
}

func runGovernance(input EvaluationInput, stage Stage) governanceResult {
	result := governanceResult{
		coverage:            make(map[string][]string),
		allowWarnCoverage:   make(map[string]bool),
		fingerprintCoverage: make(map[string]bool),
	}

	allFindings := append([]scoring.ScoredFinding(nil), input.ScoreResult.Findings...)
	applyAcceptedRisks(input, stage, &result, allFindings, severityByFingerprint(allFindings))

	suppressed := make([]string, 0)
	for _, f := range allFindings {
		if f.SuppressedByAcceptedRisk {
			suppressed = append(suppressed, f.Finding.Fingerprint)
			continue
		}
		result.scoringSet = append(result.scoringSet, f)
	}

	if len(suppressed) > 0 {
		result.events = append(result.events, newDecisionTraceEvent("governance.applied", map[string]any{
			"suppressed_fingerprints": takeFirstN(suppressed, 20),
			"suppressed_count":        len(suppressed),
			"suppressed_by":           "accepted_risk",
		}, input.Now))
	}

	remaining, appliedExceptions, exceptionEvents := applyExceptions(stage, input.Environment, result.scoringSet, input.Policy.Exceptions, input.Now)
	if len(exceptionEvents) > 0 {
		result.events = append(result.events, exceptionEvents...)
	}
	result.exceptionsApplied = appliedExceptions
	result.scoringSet = remaining
	result.allFindings = allFindings

	return result
}

func applyAcceptedRisks(input EvaluationInput, stage Stage, result *governanceResult, allFindings []scoring.ScoredFinding, severityMap map[string]string) {
	for _, ar := range input.AcceptedRisks {
		fingerprint := strings.TrimSpace(ar.FindingSelector.Fingerprint)
		if fingerprint == "" {
			result.events = append(result.events, governanceWarning(ar.RiskID, "missing fingerprint", input.Now))
			continue
		}
		if !acceptedRiskInScope(ar, stage, input.Environment) {
			continue
		}
		if hasHardStopDomain(ar.FindingSelector.Domain) && hasEffect(ar.Effects, "suppress_from_scoring") {
			result.events = append(result.events, governanceWarning(ar.RiskID, "cannot suppress hard-stop domains", input.Now))
			continue
		}

		expiresAt, err := time.Parse(time.RFC3339, ar.ExpiresAt)
		if err != nil {
			result.events = append(result.events, governanceWarning(ar.RiskID, "invalid expires_at", input.Now))
			continue
		}

		status := strings.ToLower(strings.TrimSpace(ar.Status))
		now := input.Now
		matched := []string{fingerprint}
		severity := severityForFingerprint(ar.FindingSelector.Severity, severityMap, fingerprint)

		if status == "revoked" {
			result.events = append(result.events, governanceWarning(ar.RiskID, "revoked", now))
			result.events = append(result.events, acceptedRiskStatusChangeEvent(ar, matched, "revoked", "status=revoked", now))
			continue
		}

		if !now.Before(expiresAt) || status == "expired" {
			reason := "expires_at reached"
			if status == "expired" {
				reason = "status=expired"
			}
			result.events = append(result.events, governanceWarning(ar.RiskID, reason, now))
			result.events = append(result.events, acceptedRiskStatusChangeEvent(ar, matched, "expired", reason, now))
			applyExpiredEscalation(result, stage, severity)
			continue
		}

		if status != "active" {
			result.events = append(result.events, governanceWarning(ar.RiskID, "status must be active/expired/revoked", now))
			continue
		}
		if needsSecurityApproval(stage, ar.StageScope, severity) && !hasSecurityApproval(ar.Approvals) {
			result.events = append(result.events, governanceWarning(ar.RiskID, "missing security approval", now))
			continue
		}

		recordAcceptedRiskCoverage(result, ar, fingerprint, severity)
		if hasEffect(ar.Effects, "suppress_from_scoring") {
			suppressByFingerprint(allFindings, fingerprint)
		}
	}
}

func severityByFingerprint(findings []scoring.ScoredFinding) map[string]string {
	severity := make(map[string]string, len(findings))
	for _, f := range findings {
		severity[f.Finding.Fingerprint] = f.Finding.Severity
	}
	return severity
}

func acceptedRiskInScope(ar AcceptedRisk, stage Stage, environment string) bool {
	if !stageInScope(stage, ar.StageScope) {
		return false
	}
	if len(ar.EnvironmentScope) > 0 && !stringInSlice(environment, ar.EnvironmentScope) {
		return false
	}
	return true
}

func applyExpiredEscalation(result *governanceResult, stage Stage, severity string) {
	if !isHighSeverity(severity) {
		return
	}
	if stage == StageRelease || stage == StageProd {
		result.expiredEscalation = true
		return
	}
	if stage == StagePR || stage == StageMain {
		result.expiredWarnFloor = true
	}
}

func recordAcceptedRiskCoverage(result *governanceResult, ar AcceptedRisk, fingerprint, severity string) {
	result.coverage[ar.RiskID] = append(result.coverage[ar.RiskID], fingerprint)
	result.fingerprintCoverage[fingerprint] = true
	result.appliedRiskIDs = appendIfMissing(result.appliedRiskIDs, ar.RiskID)
	if ar.AllowWarnInProd {
		result.allowWarnCoverage[fingerprint] = true
	}
	if isHighSeverity(severity) {
		result.warnFloor = true
	}
}

func suppressByFingerprint(findings []scoring.ScoredFinding, fingerprint string) {
	for idx := range findings {
		if findings[idx].Finding.Fingerprint == fingerprint && !findings[idx].SuppressedByAcceptedRisk {
			findings[idx].SuppressedByAcceptedRisk = true
		}
	}
}

func applyExceptions(stage Stage, environment string, findings []scoring.ScoredFinding, exceptions []Exception, now time.Time) ([]scoring.ScoredFinding, []string, []DecisionTraceEvent) {
	applied := make([]string, 0)
	events := make([]DecisionTraceEvent, 0)
	if len(exceptions) == 0 {
		return findings, applied, events
	}

	for _, ex := range exceptions {
		if !stageInScope(stage, ex.StageScope) {
			continue
		}
		if len(ex.EnvironmentScope) > 0 && !stringInSlice(environment, ex.EnvironmentScope) {
			continue
		}

		expiresAt, err := time.Parse(time.RFC3339, ex.ExpiresAt)
		if err != nil {
			events = append(events, governanceWarning(ex.ID, "invalid expires_at", now))
			continue
		}
		if !now.Before(expiresAt) {
			events = append(events, governanceWarning(ex.ID, "expired", now))
			continue
		}

		matches := make([]string, 0)
		for idx := range findings {
			f := &findings[idx]
			if f.SuppressedByAcceptedRisk || f.SuppressedByException || f.HardStop {
				continue
			}
			if matchesException(ex.FindingSelector, f.Finding) {
				f.SuppressedByException = true
				matches = append(matches, f.Finding.Fingerprint)
			}
		}
		if len(matches) == 0 {
			continue
		}
		applied = appendIfMissing(applied, ex.ID)
		events = append(events, newDecisionTraceEvent("exception.applied", map[string]any{
			"exception_id":            ex.ID,
			"suppressed_fingerprints": takeFirstN(matches, 20),
			"suppressed_count":        len(matches),
			"suppressed_by":           "exception",
		}, now))
	}

	remaining := make([]scoring.ScoredFinding, 0, len(findings))
	for _, f := range findings {
		if f.SuppressedByAcceptedRisk || f.SuppressedByException {
			continue
		}
		remaining = append(remaining, f)
	}

	return remaining, applied, events
}

func matchesException(selector FindingSelector, finding trivy.CanonicalFinding) bool {
	if hasHardStopDomain(finding.Domain) {
		return false
	}
	if selector.Domain != "" && !strings.EqualFold(selector.Domain, finding.Domain) {
		return false
	}
	if selector.CVE != "" && !strings.EqualFold(selector.CVE, finding.CVE) {
		return false
	}
	if selector.SourceScanner != "" && !strings.EqualFold(selector.SourceScanner, finding.SourceScanner) {
		return false
	}
	if selector.Severity != "" && !strings.EqualFold(selector.Severity, finding.Severity) {
		return false
	}
	if selector.TitleContains != "" && !stringContains(finding.Title, selector.TitleContains) {
		return false
	}
	if selector.LocationContains != "" {
		if !(stringContains(finding.Location.Path, selector.LocationContains) ||
			stringContains(finding.Location.Target, selector.LocationContains) ||
			stringContains(finding.Location.File, selector.LocationContains)) {
			return false
		}
	}
	return true
}

func stringContains(value, needle string) bool {
	if needle == "" {
		return true
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(value)), strings.ToLower(strings.TrimSpace(needle)))
}

func hasHardStopDomain(domainValue string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(domainValue))
	return normalized == string(domain.DomainSecret) || normalized == string(domain.DomainMalware) || normalized == string(domain.DomainProvenance)
}

func hasEffect(effects []string, target string) bool {
	for _, effect := range effects {
		if strings.EqualFold(strings.TrimSpace(effect), target) {
			return true
		}
	}
	return false
}

func severityForFingerprint(selectorSeverity string, actual map[string]string, fingerprint string) string {
	if severity, ok := actual[fingerprint]; ok && severity != "" {
		return severity
	}
	return selectorSeverity
}

func needsSecurityApproval(stage Stage, scope []Stage, severity string) bool {
	if !stageInScope(StageProd, scope) {
		return false
	}
	return isHighSeverity(severity)
}

func hasSecurityApproval(approvals []Approval) bool {
	for _, approval := range approvals {
		if strings.EqualFold(strings.TrimSpace(approval.Role), "security") {
			return true
		}
	}
	return false
}

func governanceWarning(riskID, reason string, timestamp time.Time) DecisionTraceEvent {
	return newDecisionTraceEvent("governance.warning", map[string]any{
		"risk_id": riskID,
		"reason":  reason,
	}, timestamp)
}

func acceptedRiskStatusChangeEvent(ar AcceptedRisk, matched []string, status, reason string, timestamp time.Time) DecisionTraceEvent {
	return newDecisionTraceEvent("accepted_risk.status_change", map[string]any{
		"risk_id":              ar.RiskID,
		"status":               status,
		"reason":               reason,
		"matched_fingerprints": takeFirstN(matched, 20),
		"stage_scope":          ar.StageScope,
		"environment_scope":    ar.EnvironmentScope,
	}, timestamp)
}

func isHighSeverity(raw string) bool {
	severity := strings.ToUpper(strings.TrimSpace(raw))
	return severity == string(domain.SeverityHigh) || severity == string(domain.SeverityCritical)
}
