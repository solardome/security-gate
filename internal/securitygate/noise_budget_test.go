package securitygate

import "testing"

func TestComputeNoiseBudgetSummaryActive(t *testing.T) {
	pol := defaultPolicy()
	pol.NoiseBudget.Enabled = true
	pol.NoiseBudget.StageLimits["pr"] = 1
	pol.NoiseBudget.SuppressBelowSeverity = "medium"

	findings := []UnifiedFinding{
		{Class: UnifiedClassification{Severity: "high"}},
		{Class: UnifiedClassification{Severity: "medium"}},
		{Class: UnifiedClassification{Severity: "low"}},
		{Class: UnifiedClassification{Severity: "info"}},
	}
	s := computeNoiseBudgetSummary(findings, pol, "pr", false)
	if !s.Enabled || !s.StageSupported {
		t.Fatalf("expected active noise budget summary, got %+v", s)
	}
	if s.SuppressedBySeverity != 2 || s.SuppressedByLimit != 1 || s.SuppressedTotal != 3 {
		t.Fatalf("unexpected suppression counts: %+v", s)
	}
	if s.DisplayedCount != 1 {
		t.Fatalf("expected one displayed finding, got %d", s.DisplayedCount)
	}
}

func TestComputeNoiseBudgetSummaryHardStopBypass(t *testing.T) {
	pol := defaultPolicy()
	pol.NoiseBudget.Enabled = true
	findings := []UnifiedFinding{
		{HardStop: true, Class: UnifiedClassification{Severity: "low"}},
		{Class: UnifiedClassification{Severity: "low"}},
	}
	s := computeNoiseBudgetSummary(findings, pol, "pr", true)
	if !s.Bypassed {
		t.Fatalf("expected bypassed summary when hard-stop triggered, got %+v", s)
	}
	if s.SuppressedTotal != 0 || s.DisplayedCount != len(findings) {
		t.Fatalf("unexpected bypass counters: %+v", s)
	}
}

func TestComputeNoiseBudgetSummaryUnsupportedStage(t *testing.T) {
	pol := defaultPolicy()
	pol.NoiseBudget.Enabled = true
	findings := []UnifiedFinding{
		{Class: UnifiedClassification{Severity: "low"}},
		{Class: UnifiedClassification{Severity: "info"}},
	}
	s := computeNoiseBudgetSummary(findings, pol, "release", false)
	if s.StageSupported {
		t.Fatalf("release stage should not be supported for noise budget, got %+v", s)
	}
	if s.SuppressedTotal != 0 || s.DisplayedCount != len(findings) {
		t.Fatalf("unsupported stage must not suppress findings, got %+v", s)
	}
}
