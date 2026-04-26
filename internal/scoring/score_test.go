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
		ArtifactSigned:  "yes",
		ProvenanceLevel: "verified",
		BuildIntegrity:  "verified",
	}
	pol := Policy{ScanFreshnessHours: 24}
	now := time.Now().UTC()

	t.Run("unknown_detected_at_penalized", func(t *testing.T) {
		res := TrustScoreAt(ctx, pol, []Finding{{DetectedAt: "unknown", ScannerVersion: "0.50.0"}}, nil, nil, now)
		if !hasTrustPenalty(res, "SCAN_FRESHNESS_UNKNOWN_OR_STALE") {
			t.Fatalf("expected freshness penalty, got %+v", res.Penalties)
		}
	})

	t.Run("stale_detected_at_penalized", func(t *testing.T) {
		res := TrustScoreAt(ctx, pol, []Finding{{DetectedAt: "2010-01-01T00:00:00Z", ScannerVersion: "0.50.0"}}, nil, nil, now)
		if !hasTrustPenalty(res, "SCAN_FRESHNESS_UNKNOWN_OR_STALE") {
			t.Fatalf("expected freshness penalty, got %+v", res.Penalties)
		}
	})

	t.Run("fresh_detected_at_not_penalized", func(t *testing.T) {
		res := TrustScoreAt(ctx, pol, []Finding{{DetectedAt: now.Add(-1 * time.Hour).Format(time.RFC3339), ScannerVersion: "0.50.0"}}, nil, nil, now)
		if hasTrustPenalty(res, "SCAN_FRESHNESS_UNKNOWN_OR_STALE") {
			t.Fatalf("did not expect freshness penalty, got %+v", res.Penalties)
		}
	})

	t.Run("future_detected_at_penalized", func(t *testing.T) {
		res := TrustScoreAt(ctx, pol, []Finding{{DetectedAt: now.Add(24 * time.Hour).Format(time.RFC3339), ScannerVersion: "0.50.0"}}, nil, nil, now)
		if !hasTrustPenalty(res, "SCAN_FRESHNESS_UNKNOWN_OR_STALE") {
			t.Fatalf("expected freshness penalty for future timestamp, got %+v", res.Penalties)
		}
	})
}

func TestTrustScoreFreshnessUsesScanLevelTimestamp(t *testing.T) {
	now := time.Date(2026, 2, 19, 12, 0, 0, 0, time.UTC)
	ctx := Context{
		BranchType:      "feature",
		PipelineStage:   "pr",
		Environment:     "ci",
		RepoCriticality: "high",
		Exposure:        "internet",
		ChangeType:      "application",
		ArtifactSigned:  "yes",
		ProvenanceLevel: "verified",
		BuildIntegrity:  "verified",
	}
	pol := Policy{ScanFreshnessHours: 24}
	res := TrustScoreAt(ctx, pol, nil, []string{"0.50.0"}, []string{now.Add(-1 * time.Hour).Format(time.RFC3339)}, now)
	if hasTrustPenalty(res, "SCAN_FRESHNESS_UNKNOWN_OR_STALE") {
		t.Fatalf("did not expect freshness penalty from fresh scan-level timestamp, got %+v", res.Penalties)
	}
}

func hasTrustPenalty(res TrustResult, code string) bool {
	for _, p := range res.Penalties {
		if p.Code == code {
			return true
		}
	}
	return false
}

func TestTrustPenaltyBand(t *testing.T) {
	defaultBands := TrustBandPenalties{Trust60to79: 5, Trust40to59: 10, Trust20to39: 15, Trust0to19: 20}
	cases := []struct {
		score int
		want  int
	}{
		{100, 0},
		{80, 0},
		{79, 5},
		{60, 5},
		{59, 10},
		{40, 10},
		{39, 15},
		{20, 15},
		{19, 20},
		{0, 20},
	}
	for _, c := range cases {
		got := TrustPenaltyBand(c.score, defaultBands)
		if got != c.want {
			t.Fatalf("TrustPenaltyBand(%d) = %d, want %d", c.score, got, c.want)
		}
	}
}

func TestTrustPenaltyBandDefaultsWhenZero(t *testing.T) {
	// Zero bands should fall back to built-in defaults.
	got := TrustPenaltyBand(70, TrustBandPenalties{})
	if got != 5 {
		t.Fatalf("expected default band 5 for score 70, got %d", got)
	}
	got = TrustPenaltyBand(10, TrustBandPenalties{})
	if got != 20 {
		t.Fatalf("expected default band 20 for score 10, got %d", got)
	}
}

func TestTrustScoreCanDisableTrustTighteningRiskPenalty(t *testing.T) {
	now := time.Date(2026, 2, 19, 12, 0, 0, 0, time.UTC)
	ctx := Context{
		BranchType:      "feature",
		PipelineStage:   "pr",
		Environment:     "ci",
		RepoCriticality: "high",
		Exposure:        "internet",
		ChangeType:      "application",
		ArtifactSigned:  "yes",
		ProvenanceLevel: "verified",
		BuildIntegrity:  "verified",
	}
	pol := Policy{ScanFreshnessHours: 24, DisableTrustTightening: true}
	res := TrustScoreAt(ctx, pol, []Finding{{DetectedAt: now.Add(-1 * time.Hour).Format(time.RFC3339), ScannerVersion: "unknown"}}, nil, nil, now)
	if !hasTrustPenalty(res, "SCANNER_VERSION_UNKNOWN") {
		t.Fatalf("expected trust score to still record scanner penalty, got %+v", res.Penalties)
	}
	if res.RiskPenalty != 0 {
		t.Fatalf("expected trust-derived risk penalty disabled, got %d", res.RiskPenalty)
	}
}

func TestScoreFindingSeverityDominates(t *testing.T) {
	ctx := Context{RepoCriticality: "low", Exposure: "isolated"}
	pol := Policy{}
	cases := []struct {
		severity string
		minScore int
	}{
		{"critical", 70},
		{"high", 50},
		{"medium", 30},
		{"low", 15},
		{"info", 5},
		{"unknown", 30}, // unknown severity maps to 35 in the map
	}
	for _, c := range cases {
		f := Finding{Severity: c.severity, ExploitMaturity: "none", Reachability: "not_reachable", Confidence: "high"}
		got := ScoreFinding(f, ctx, pol, "pr")
		if got < c.minScore {
			t.Fatalf("ScoreFinding severity=%q: got %d, want >= %d", c.severity, got, c.minScore)
		}
	}
}

func TestScoreFindingExploitBoostsScore(t *testing.T) {
	ctx := Context{RepoCriticality: "low", Exposure: "isolated"}
	pol := Policy{}
	base := ScoreFinding(Finding{Severity: "high", ExploitMaturity: "none", Reachability: "not_reachable", Confidence: "high"}, ctx, pol, "pr")
	boosted := ScoreFinding(Finding{Severity: "high", ExploitMaturity: "known_exploited", Reachability: "reachable", Confidence: "high"}, ctx, pol, "pr")
	if boosted <= base {
		t.Fatalf("exploit+reachability should increase score: base=%d boosted=%d", base, boosted)
	}
}

func TestScoreFindingSeverityBoostByDomain(t *testing.T) {
	ctx := Context{RepoCriticality: "low", Exposure: "isolated"}
	pol := Policy{
		SeverityBoosts: []DomainSeverityBoost{
			{DomainID: "VULN_CRYPTO", AddPoints: 15, Stages: []string{"deploy"}},
		},
	}
	f := Finding{Severity: "medium", DomainID: "VULN_CRYPTO", ExploitMaturity: "none", Reachability: "not_reachable", Confidence: "high"}
	withoutBoost := ScoreFinding(f, ctx, pol, "pr")
	withBoost := ScoreFinding(f, ctx, pol, "deploy")
	if withBoost != withoutBoost+15 {
		t.Fatalf("domain boost at deploy: expected %d got %d", withoutBoost+15, withBoost)
	}
}

func TestScoreFindingClampedTo100(t *testing.T) {
	ctx := Context{RepoCriticality: "mission_critical", Exposure: "internet"}
	pol := Policy{
		SeverityBoosts: []DomainSeverityBoost{
			{DomainID: "HS", AddPoints: 30},
		},
	}
	f := Finding{Severity: "critical", ExploitMaturity: "known_exploited", Reachability: "reachable", Confidence: "high", DomainID: "HS"}
	got := ScoreFinding(f, ctx, pol, "pr")
	if got > 100 {
		t.Fatalf("score must be clamped to 100, got %d", got)
	}
	if got != 100 {
		t.Fatalf("expected 100 (clamped), got %d", got)
	}
}

func TestEffectiveStageResolution(t *testing.T) {
	cases := []struct {
		ctx  Context
		want string
	}{
		{Context{BranchType: "feature", PipelineStage: "pr", Environment: "ci"}, "pr"},
		{Context{BranchType: "main", PipelineStage: "pr", Environment: "ci"}, "merge"},
		{Context{BranchType: "release", PipelineStage: "pr", Environment: "ci"}, "release"},
		{Context{BranchType: "feature", PipelineStage: "deploy", Environment: "ci"}, "deploy"},
		{Context{BranchType: "feature", PipelineStage: "pr", Environment: "prod"}, "deploy"},
		// Pipeline stage wins over branch when it's higher.
		{Context{BranchType: "main", PipelineStage: "release", Environment: "ci"}, "release"},
		// Unknown pipeline_stage falls back to pr rank 0, branch wins.
		{Context{BranchType: "main", PipelineStage: "garbage", Environment: "ci"}, "merge"},
	}
	for _, c := range cases {
		got := EffectiveStage(c.ctx)
		if got != c.want {
			t.Fatalf("EffectiveStage(%+v) = %q, want %q", c.ctx, got, c.want)
		}
	}
}

func TestTrustScorePenaltiesFromScannerVersion(t *testing.T) {
	freshAt := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	base := Context{
		BranchType: "feature", PipelineStage: "pr", Environment: "ci",
		RepoCriticality: "high", Exposure: "internet", ChangeType: "application",
		ArtifactSigned: "yes", ProvenanceLevel: "verified", BuildIntegrity: "verified",
	}
	pol := Policy{ScanFreshnessHours: 24}
	findings := []Finding{{DetectedAt: freshAt}}

	t.Run("missing_version_penalized", func(t *testing.T) {
		res := TrustScore(base, pol, findings)
		if !hasTrustPenalty(res, "SCANNER_VERSION_UNKNOWN") {
			t.Fatalf("expected SCANNER_VERSION_UNKNOWN, got %+v", res.Penalties)
		}
	})

	t.Run("latest_tag_penalized", func(t *testing.T) {
		versionedFindings := []Finding{{DetectedAt: freshAt, ScannerVersion: "latest"}}
		res := TrustScore(base, pol, versionedFindings)
		if !hasTrustPenalty(res, "SCANNER_VERSION_UNPINNED") {
			t.Fatalf("expected SCANNER_VERSION_UNPINNED, got %+v", res.Penalties)
		}
	})

	t.Run("pinned_version_not_penalized", func(t *testing.T) {
		versionedFindings := []Finding{{DetectedAt: freshAt, ScannerVersion: "0.49.1"}}
		res := TrustScore(base, pol, versionedFindings)
		if hasTrustPenalty(res, "SCANNER_VERSION_UNKNOWN") || hasTrustPenalty(res, "SCANNER_VERSION_UNPINNED") {
			t.Fatalf("did not expect version penalty, got %+v", res.Penalties)
		}
	})
}

func TestTrustScoreArtifactSignedPenalty(t *testing.T) {
	freshAt := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	ctx := Context{
		BranchType: "feature", PipelineStage: "pr", Environment: "ci",
		RepoCriticality: "high", Exposure: "internet", ChangeType: "application",
		ProvenanceLevel: "verified", BuildIntegrity: "verified",
	}
	pol := Policy{ScanFreshnessHours: 24}
	findings := []Finding{{DetectedAt: freshAt, ScannerVersion: "1.0.0"}}

	ctx.ArtifactSigned = "no"
	res := TrustScore(ctx, pol, findings)
	if !hasTrustPenalty(res, "ARTIFACT_UNSIGNED") {
		t.Fatalf("expected ARTIFACT_UNSIGNED penalty, got %+v", res.Penalties)
	}

	ctx.ArtifactSigned = "yes"
	res = TrustScore(ctx, pol, findings)
	if hasTrustPenalty(res, "ARTIFACT_UNSIGNED") {
		t.Fatalf("did not expect ARTIFACT_UNSIGNED penalty")
	}
}

func TestTrustScoreProvenancePenalties(t *testing.T) {
	freshAt := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	ctx := Context{
		BranchType: "feature", PipelineStage: "pr", Environment: "ci",
		RepoCriticality: "high", Exposure: "internet", ChangeType: "application",
		ArtifactSigned: "yes", BuildIntegrity: "verified",
	}
	pol := Policy{ScanFreshnessHours: 24}
	findings := []Finding{{DetectedAt: freshAt, ScannerVersion: "1.0.0"}}

	for _, level := range []string{"none", "basic"} {
		ctx.ProvenanceLevel = level
		res := TrustScore(ctx, pol, findings)
		if !hasTrustPenalty(res, "PROVENANCE_BELOW_REQUIRED") {
			t.Fatalf("expected PROVENANCE_BELOW_REQUIRED for level=%q, got %+v", level, res.Penalties)
		}
	}

	ctx.ProvenanceLevel = ""
	res := TrustScore(ctx, pol, findings)
	if !hasTrustPenalty(res, "PROVENANCE_UNKNOWN") {
		t.Fatalf("expected PROVENANCE_UNKNOWN for empty level, got %+v", res.Penalties)
	}
}

func TestTrustScoreMissingContextFieldPenalty(t *testing.T) {
	freshAt := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	pol := Policy{ScanFreshnessHours: 24}
	// All context fields empty → max penalty of 20.
	ctx := Context{
		ArtifactSigned:  "yes",
		ProvenanceLevel: "verified", BuildIntegrity: "verified",
	}
	res := TrustScore(ctx, pol, []Finding{{DetectedAt: freshAt, ScannerVersion: "1.0.0"}})
	if !hasTrustPenalty(res, "MISSING_REQUIRED_CONTEXT_FIELDS") {
		t.Fatalf("expected MISSING_REQUIRED_CONTEXT_FIELDS, got %+v", res.Penalties)
	}
	var penalty int
	for _, p := range res.Penalties {
		if p.Code == "MISSING_REQUIRED_CONTEXT_FIELDS" {
			penalty = p.Value
		}
	}
	if penalty > 20 {
		t.Fatalf("MISSING_REQUIRED_CONTEXT_FIELDS penalty capped at 20, got %d", penalty)
	}
}

func TestAggregateOverallHardStopAndAcceptedExcluded(t *testing.T) {
	ctx := Context{ChangeType: "application", RepoCriticality: "low"}
	trust := TrustResult{Score: 100, RiskPenalty: 0}
	findings := []Finding{
		{FindingRiskScore: 99, HardStop: true},
		{FindingRiskScore: 90, Accepted: true},
		{FindingRiskScore: 40, HardStop: false, Accepted: false},
	}
	res := AggregateOverall(findings, ctx, "pr", trust, 0, false)
	if res.MaxFindingScore != 40 {
		t.Fatalf("hard-stop and accepted findings must be excluded from scoring: got MaxFindingScore=%d", res.MaxFindingScore)
	}
}

func TestAggregateOverallRulePolicyRiskPoints(t *testing.T) {
	ctx := Context{ChangeType: "application"}
	trust := TrustResult{Score: 100, RiskPenalty: 0}
	findings := []Finding{{FindingRiskScore: 30}}
	res := AggregateOverall(findings, ctx, "pr", trust, 20, false)
	found := false
	for _, m := range res.ContextModifiers {
		if m.Code == "POLICY_RULE_RISK_POINTS" && m.Value == 20 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected POLICY_RULE_RISK_POINTS modifier with value 20, got %+v", res.ContextModifiers)
	}
}

func TestClamp(t *testing.T) {
	cases := []struct{ v, min, max, want int }{
		{50, 0, 100, 50},
		{-5, 0, 100, 0},
		{150, 0, 100, 100},
		{0, 0, 100, 0},
		{100, 0, 100, 100},
	}
	for _, c := range cases {
		if got := clamp(c.v, c.min, c.max); got != c.want {
			t.Fatalf("clamp(%d,%d,%d)=%d want %d", c.v, c.min, c.max, got, c.want)
		}
	}
}

func TestContains(t *testing.T) {
	// Empty values list matches everything.
	if !contains(nil, "anything") {
		t.Fatal("empty list should match any target")
	}
	if !contains([]string{"a", "B"}, "b") {
		t.Fatal("contains should be case-insensitive")
	}
	if contains([]string{"a", "b"}, "c") {
		t.Fatal("contains should return false when not found")
	}
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
