package policy

import (
	"testing"
	"time"

	"github.com/solardome/security-gate/internal/domain"
	"github.com/solardome/security-gate/internal/ingest/trivy"
	"github.com/solardome/security-gate/internal/scoring"
)

func TestApplyNoiseBudgetKeepsTopKAndSuppressesRemainder(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	findings := []scoring.ScoredFinding{
		{
			Finding: trivy.CanonicalFinding{
				FindingID:   "f-high",
				Fingerprint: "fp-high",
				Severity:    string(domain.SeverityHigh),
			},
			RiskScore: 90,
		},
		{
			Finding: trivy.CanonicalFinding{
				FindingID:   "f-medium",
				Fingerprint: "fp-medium",
				Severity:    string(domain.SeverityMedium),
			},
			RiskScore: 60,
		},
		{
			Finding: trivy.CanonicalFinding{
				FindingID:   "f-low",
				Fingerprint: "fp-low",
				Severity:    string(domain.SeverityLow),
			},
			RiskScore: 25,
		},
	}

	considered, event := applyNoiseBudget(StagePR, findings, 1, nil, now)
	if event == nil {
		t.Fatalf("expected noise_budget.applied event")
	}
	if len(considered) != 1 {
		t.Fatalf("expected exactly 1 considered finding, got %d", len(considered))
	}
	if considered[0].Finding.Fingerprint != "fp-high" {
		t.Fatalf("expected top-risk finding to remain considered, got %s", considered[0].Finding.Fingerprint)
	}
	if !findings[1].SuppressedByNoiseBudget || !findings[2].SuppressedByNoiseBudget {
		t.Fatalf("expected non-top findings to be suppressed by noise budget")
	}
}

func TestMakeDecisionInputsUsesScannerNameAndContextPayload(t *testing.T) {
	t.Parallel()

	input := EvaluationInput{
		ContextHash:      "ctx-hash",
		PolicyHash:       "policy-hash",
		AcceptedRiskHash: "risk-hash",
		ContextPayload: ContextPayload{
			PipelineStage: "main",
			Environment:   "prod",
			Exposure:      "internal",
			ChangeType:    "moderate",
		},
		ScanHashes: map[string]string{
			"scan.json": "scan-hash",
		},
		ScanMetadata: map[string]ScanMetadata{
			"scan.json": {
				SourceScanner: "trivy",
				SourceVersion: "0.60.0",
				ScanTimestamp: "2026-02-10T00:00:00Z",
			},
		},
	}

	decisionInputs := makeDecisionInputs(input)
	if len(decisionInputs.Scans) != 1 {
		t.Fatalf("expected 1 scan, got %d", len(decisionInputs.Scans))
	}
	if decisionInputs.Scans[0].SourceScanner != "trivy" {
		t.Fatalf("expected source_scanner=trivy, got %s", decisionInputs.Scans[0].SourceScanner)
	}
	if decisionInputs.Context.Payload.PipelineStage != "main" {
		t.Fatalf("expected context payload stage main, got %s", decisionInputs.Context.Payload.PipelineStage)
	}
	if decisionInputs.Context.SHA256 != "ctx-hash" {
		t.Fatalf("expected context hash ctx-hash, got %s", decisionInputs.Context.SHA256)
	}
}
