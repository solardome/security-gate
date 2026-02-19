package scoring

import (
	"testing"
	"time"
)

func TestTrustScoreFreshnessPenalty(t *testing.T) {
	ctx := Context{
		BranchType:      "feature",
		PipelineStage:   "pr",
		Environment:     "ci",
		RepoCriticality: "high",
		Exposure:        "internet",
		ChangeType:      "application",
		ScannerVersion:  "0.50.0",
		ArtifactSigned:  "yes",
		ProvenanceLevel: "verified",
		BuildIntegrity:  "verified",
	}
	pol := Policy{ScanFreshnessHours: 24}

	t.Run("unknown_detected_at_penalized", func(t *testing.T) {
		res := TrustScore(ctx, pol, []Finding{{DetectedAt: "unknown"}})
		if !hasTrustPenalty(res, "SCAN_FRESHNESS_UNKNOWN_OR_STALE") {
			t.Fatalf("expected freshness penalty, got %+v", res.Penalties)
		}
	})

	t.Run("stale_detected_at_penalized", func(t *testing.T) {
		res := TrustScore(ctx, pol, []Finding{{DetectedAt: "2010-01-01T00:00:00Z"}})
		if !hasTrustPenalty(res, "SCAN_FRESHNESS_UNKNOWN_OR_STALE") {
			t.Fatalf("expected freshness penalty, got %+v", res.Penalties)
		}
	})

	t.Run("fresh_detected_at_not_penalized", func(t *testing.T) {
		res := TrustScore(ctx, pol, []Finding{{DetectedAt: time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)}})
		if hasTrustPenalty(res, "SCAN_FRESHNESS_UNKNOWN_OR_STALE") {
			t.Fatalf("did not expect freshness penalty, got %+v", res.Penalties)
		}
	})

	t.Run("future_detected_at_penalized", func(t *testing.T) {
		res := TrustScore(ctx, pol, []Finding{{DetectedAt: time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)}})
		if !hasTrustPenalty(res, "SCAN_FRESHNESS_UNKNOWN_OR_STALE") {
			t.Fatalf("expected freshness penalty for future timestamp, got %+v", res.Penalties)
		}
	})
}

func hasTrustPenalty(res TrustResult, code string) bool {
	for _, p := range res.Penalties {
		if p.Code == code {
			return true
		}
	}
	return false
}

func TestAggregateOverallNewFindingsOnly(t *testing.T) {
	ctx := Context{
		BranchType:      "feature",
		PipelineStage:   "pr",
		Environment:     "ci",
		RepoCriticality: "high",
		Exposure:        "internet",
		ChangeType:      "application",
	}
	trust := TrustResult{Score: 85, RiskPenalty: 0}
	findings := []Finding{
		{FindingRiskScore: 92, BaselineKnown: true},
		{FindingRiskScore: 41, BaselineKnown: false},
	}

	all := AggregateOverall(findings, ctx, "pr", trust, 0, false)
	if all.MaxFindingScore != 92 {
		t.Fatalf("expected baseline finding to contribute when mode disabled, got %d", all.MaxFindingScore)
	}

	newOnly := AggregateOverall(findings, ctx, "pr", trust, 0, true)
	if newOnly.MaxFindingScore != 41 {
		t.Fatalf("expected only new findings to contribute when mode enabled, got %d", newOnly.MaxFindingScore)
	}
}
