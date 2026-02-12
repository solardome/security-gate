package policy

import (
	"testing"
	"time"

	"github.com/solardome/security-gate/internal/domain"
	"github.com/solardome/security-gate/internal/ingest/trivy"
	"github.com/solardome/security-gate/internal/scoring"
)

func TestEvaluateHardStopForcesBlock(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	input := EvaluationInput{
		Stage:       StagePR,
		Environment: "dev",
		Exposure:    "private",
		ChangeType:  "low",
		Policy:      Policy{PolicyVersion: "1"},
		ScoreResult: scoring.ScoreResult{
			TrustScore:    100,
			TrustModifier: 0,
			Findings: []scoring.ScoredFinding{{
				Finding: trivy.CanonicalFinding{
					FindingID:     "secret-1",
					Fingerprint:   "fp-secret-1",
					Domain:        string(domain.DomainSecret),
					Severity:      string(domain.SeverityHigh),
					FixAvailable:  "unknown",
					SourceScanner: "trivy",
				},
				RiskScore: 100,
				HardStop:  true,
			}},
		},
		Now: now,
	}

	artifact, err := Evaluate(input)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if artifact.Decision.Status != domain.DecisionBlock {
		t.Fatalf("expected BLOCK, got %s", artifact.Decision.Status)
	}
	if artifact.Decision.ExitCode != 2 {
		t.Fatalf("expected exit_code=2, got %d", artifact.Decision.ExitCode)
	}
}

func TestEvaluateRequireAcceptedRiskMissingBlocksRelease(t *testing.T) {
	t.Parallel()

	zero := 0
	now := time.Now().UTC()
	input := EvaluationInput{
		Stage:       StageRelease,
		Environment: "staging",
		Exposure:    "private",
		ChangeType:  "low",
		Policy: Policy{
			PolicyVersion: "1",
			Rules: []Rule{{
				ID:         "R-REQ-AR",
				StageScope: []Stage{StageRelease},
				When:       RuleCondition{ReleaseRiskGTE: &zero},
				Then:       RuleAction{RequireAcceptedRisk: &RequireAcceptedRisk{Selector: RequireAcceptedRiskSelector{Type: "top_findings"}}},
			}},
		},
		ScoreResult: scoring.ScoreResult{
			TrustScore:    90,
			TrustModifier: 0,
			Findings: []scoring.ScoredFinding{{
				Finding: trivy.CanonicalFinding{
					FindingID:     "vuln-1",
					Fingerprint:   "fp-vuln-1",
					Domain:        string(domain.DomainVulnerability),
					Severity:      string(domain.SeverityHigh),
					FixAvailable:  "false",
					SourceScanner: "trivy",
				},
				RiskScore: 70,
			}},
		},
		Now: now,
	}

	artifact, err := Evaluate(input)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if artifact.Decision.Status != domain.DecisionBlock {
		t.Fatalf("expected BLOCK, got %s", artifact.Decision.Status)
	}
	if !contains(artifact.RecommendedSteps, "ADD_ACCEPTED_RISK") {
		t.Fatalf("expected ADD_ACCEPTED_RISK in recommended_next_steps, got %#v", artifact.RecommendedSteps)
	}

	foundMissingEvent := false
	for _, event := range artifact.Trace.Events {
		if event.Type == "policy.require_accepted_risk.missing" {
			foundMissingEvent = true
			break
		}
	}
	if !foundMissingEvent {
		t.Fatalf("expected policy.require_accepted_risk.missing trace event")
	}
}

func TestEvaluateExpiredAcceptedRiskWarnsMain(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC)
	input := EvaluationInput{
		Stage:       StageMain,
		Environment: "prod",
		Exposure:    "private",
		ChangeType:  "low",
		Policy:      Policy{PolicyVersion: "1"},
		ScoreResult: scoring.ScoreResult{
			TrustScore:    95,
			TrustModifier: 0,
			Findings: []scoring.ScoredFinding{{
				Finding: trivy.CanonicalFinding{
					FindingID:   "vuln-1",
					Fingerprint: "fp-vuln-1",
					Domain:      string(domain.DomainVulnerability),
					Severity:    string(domain.SeverityHigh),
				},
				RiskScore: 20,
			}},
		},
		AcceptedRisks: []AcceptedRisk{{
			RiskID:           "AR-EXPIRED-1",
			StageScope:       []Stage{StageMain},
			EnvironmentScope: []string{"prod"},
			FindingSelector: FindingSelector{
				Fingerprint: "fp-vuln-1",
			},
			ExpiresAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
			Status:    "active",
		}},
		Now: now,
	}

	artifact, err := Evaluate(input)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if artifact.Decision.Status != domain.DecisionWarn {
		t.Fatalf("expected WARN for expired accepted risk on main, got %s", artifact.Decision.Status)
	}
}

func TestEvaluateExpiredAcceptedRiskBlocksRelease(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC)
	input := EvaluationInput{
		Stage:       StageRelease,
		Environment: "prod",
		Exposure:    "private",
		ChangeType:  "low",
		Policy:      Policy{PolicyVersion: "1"},
		ScoreResult: scoring.ScoreResult{
			TrustScore:    95,
			TrustModifier: 0,
			Findings: []scoring.ScoredFinding{{
				Finding: trivy.CanonicalFinding{
					FindingID:   "vuln-1",
					Fingerprint: "fp-vuln-1",
					Domain:      string(domain.DomainVulnerability),
					Severity:    string(domain.SeverityHigh),
				},
				RiskScore: 20,
			}},
		},
		AcceptedRisks: []AcceptedRisk{{
			RiskID:           "AR-EXPIRED-2",
			StageScope:       []Stage{StageRelease},
			EnvironmentScope: []string{"prod"},
			FindingSelector: FindingSelector{
				Fingerprint: "fp-vuln-1",
			},
			ExpiresAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
			Status:    "active",
		}},
		Now: now,
	}

	artifact, err := Evaluate(input)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if artifact.Decision.Status != domain.DecisionBlock {
		t.Fatalf("expected BLOCK for expired accepted risk on release, got %s", artifact.Decision.Status)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
