package securitygate

import (
	"strings"
	"testing"
	"time"
)

func TestClamp(t *testing.T) {
	cases := []struct{ v, min, max, want int }{
		{50, 0, 100, 50},
		{-1, 0, 100, 0},
		{101, 0, 100, 100},
		{0, 0, 100, 0},
		{100, 0, 100, 100},
	}
	for _, c := range cases {
		if got := clamp(c.v, c.min, c.max); got != c.want {
			t.Fatalf("clamp(%d,%d,%d)=%d want %d", c.v, c.min, c.max, got, c.want)
		}
	}
}

func TestNormalizeToken(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "unknown"},
		{"  ", "unknown"},
		{"Feature", "feature"},
		{" MAIN ", "main"},
		{"prod", "prod"},
	}
	for _, c := range cases {
		if got := normalizeToken(c.in); got != c.want {
			t.Fatalf("normalizeToken(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestCanonicalScannerID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "unknown"},
		{"unknown", "unknown"},
		{"trivy", "trivy"},
		{"TRIVY", "trivy"},
		{"snyk-open-source", "snyk"},
		{"checkmarx-sast", "checkmarx"},
		{"CxSAST", "checkmarx"},
		{"sonarqube", "sonar"},
		{"sarif", "sarif"},
		{"custom-scanner", "custom-scanner"},
	}
	for _, c := range cases {
		if got := canonicalScannerID(c.in); got != c.want {
			t.Fatalf("canonicalScannerID(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "hello"); got != "hello" {
		t.Fatalf("firstNonEmpty()=%q want %q", got, "hello")
	}
	if got := firstNonEmpty("first", "second"); got != "first" {
		t.Fatalf("firstNonEmpty()=%q want %q", got, "first")
	}
	if got := firstNonEmpty("", "  "); got != "" {
		t.Fatalf("firstNonEmpty() with all empty should return empty string, got %q", got)
	}
}

func TestSeverityAtMost(t *testing.T) {
	cases := []struct {
		sev, max string
		want     bool
	}{
		{"low", "high", true},
		{"medium", "medium", true},
		{"high", "high", true},
		{"critical", "high", false},
		{"critical", "critical", true},
		{"info", "low", true},
		{"unknown", "low", true}, // unknown maps to 0, low maps to 2
	}
	for _, c := range cases {
		got := severityAtMost(c.sev, c.max)
		if got != c.want {
			t.Fatalf("severityAtMost(%q,%q)=%v want %v", c.sev, c.max, got, c.want)
		}
	}
}

func TestContainsUtil(t *testing.T) {
	if !contains(nil, "anything") {
		t.Fatal("nil list should match any target")
	}
	if !contains([]string{}, "anything") {
		t.Fatal("empty list should match any target")
	}
	if !contains([]string{"FOO", "bar"}, "foo") {
		t.Fatal("contains must be case-insensitive")
	}
	if contains([]string{"a", "b"}, "c") {
		t.Fatal("expected false for non-member")
	}
}

func TestValidateContext(t *testing.T) {
	valid := Context{
		BranchType:      "feature",
		PipelineStage:   "pr",
		Environment:     "ci",
		RepoCriticality: "high",
		Exposure:        "internet",
		ChangeType:      "application",
	}
	if errs := validateContext(valid); len(errs) != 0 {
		t.Fatalf("expected no errors for valid context, got %v", errs)
	}

	invalid := Context{
		BranchType:      "hotfix",    // invalid
		PipelineStage:   "staging",   // invalid
		Environment:     "staging",   // invalid
		RepoCriticality: "extreme",   // invalid
		Exposure:        "dmz",       // invalid
		ChangeType:      "migration", // invalid
	}
	errs := validateContext(invalid)
	if len(errs) != 6 {
		t.Fatalf("expected 6 errors for fully invalid context, got %d: %v", len(errs), errs)
	}
}

func TestValidateContextUnknownIsValid(t *testing.T) {
	// "unknown" is accepted for criticality and exposure, but NOT for stage/branch/env.
	ctx := Context{
		BranchType:      "feature",
		PipelineStage:   "pr",
		Environment:     "ci",
		RepoCriticality: "unknown",
		Exposure:        "unknown",
		ChangeType:      "unknown",
	}
	errs := validateContext(ctx)
	if len(errs) != 0 {
		t.Fatalf("unknown is valid for non-required enum fields, got %v", errs)
	}
}

func TestShouldBlockReleaseOnUnknownSignals(t *testing.T) {
	pol := Policy{}
	pol.Defaults.UnknownSignalMode = "block_release"
	if !shouldBlockReleaseOnUnknownSignals(pol, "release") {
		t.Fatal("expected true for block_release+release stage")
	}
	if !shouldBlockReleaseOnUnknownSignals(pol, "deploy") {
		t.Fatal("expected true for block_release+deploy stage")
	}
	if shouldBlockReleaseOnUnknownSignals(pol, "pr") {
		t.Fatal("expected false for block_release+pr stage")
	}
	pol.Defaults.UnknownSignalMode = "tighten"
	if shouldBlockReleaseOnUnknownSignals(pol, "release") {
		t.Fatal("expected false for tighten mode")
	}
}

func TestValidateEnumList(t *testing.T) {
	allowed := map[string]bool{"pr": true, "merge": true}
	var errs []string

	validateEnumList("test.field", []string{"pr", "merge"}, allowed, &errs)
	if len(errs) != 0 {
		t.Fatalf("expected no errors for valid values, got %v", errs)
	}

	validateEnumList("test.field", []string{"pr", "deploy"}, allowed, &errs)
	if len(errs) != 1 || !strings.Contains(errs[0], "test.field") {
		t.Fatalf("expected one error for invalid value, got %v", errs)
	}
}

func TestValidateEnumListEmpty(t *testing.T) {
	allowed := map[string]bool{"a": true}
	var errs []string
	validateEnumList("field", []string{}, allowed, &errs)
	if len(errs) != 0 {
		t.Fatal("empty list should produce no errors")
	}
}

func TestSortedStringKeys(t *testing.T) {
	m := map[string]int{"c": 3, "a": 1, "b": 2}
	got := sortedStringKeys(m)
	want := []string{"a", "b", "c"}
	for i, k := range want {
		if got[i] != k {
			t.Fatalf("sortedStringKeys: got %v want %v", got, want)
		}
	}
}

func TestStableRunIDDeterministic(t *testing.T) {
	inputs := []InputDigest{
		{Kind: "scan", Role: "main", Path: "/a.json", SHA256: "abc123"},
		{Kind: "context", Role: "", Path: "/ctx.yaml", SHA256: "def456"},
	}
	id1 := stableRunID(inputs, "pr")
	id2 := stableRunID(inputs, "pr")
	if id1 != id2 {
		t.Fatalf("stableRunID must be deterministic: %q != %q", id1, id2)
	}
	idDiff := stableRunID(inputs, "deploy")
	if idDiff == id1 {
		t.Fatal("different stage must produce different run ID")
	}
}

func TestValidateAcceptedRiskSchema(t *testing.T) {
	if err := validateAcceptedRiskSchema(AcceptedRiskSet{}); err != nil {
		t.Fatalf("empty schema_version should be accepted: %v", err)
	}
	if err := validateAcceptedRiskSchema(AcceptedRiskSet{SchemaVersion: "1.0"}); err != nil {
		t.Fatalf("version 1.0 should be valid: %v", err)
	}
	if err := validateAcceptedRiskSchema(AcceptedRiskSet{SchemaVersion: "2.0"}); err == nil {
		t.Fatal("unsupported schema_version should fail")
	}
}

func TestUnknownSignalValidationErrors(t *testing.T) {
	freshAt := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)

	ctx := Context{
		BranchType:      "feature",
		PipelineStage:   "pr",
		Environment:     "ci",
		RepoCriticality: "high",
		Exposure:        "internet",
		ChangeType:      "application",
		Scanner:         ScannerMeta{Name: "trivy", Version: "0.50.0"},
		Provenance:      Provenance{ArtifactSigned: "yes", Level: "verified", BuildContextIntegrity: "verified"},
	}

	// All signals known → no errors.
	errs := unknownSignalValidationErrors(ctx, []string{freshAt})
	if len(errs) != 0 {
		t.Fatalf("expected no errors with all signals known, got %v", errs)
	}

	// Missing scanner name → error.
	ctx2 := ctx
	ctx2.Scanner = ScannerMeta{Name: "", Version: "0.50.0"}
	errs2 := unknownSignalValidationErrors(ctx2, []string{freshAt})
	found := false
	for _, e := range errs2 {
		if strings.Contains(e, "context.scanner.name") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected error for missing scanner.name, got %v", errs2)
	}

	// No valid detected_at → error.
	errs3 := unknownSignalValidationErrors(ctx, []string{"unknown", "garbage"})
	found3 := false
	for _, e := range errs3 {
		if strings.Contains(e, "scans.detected_at") {
			found3 = true
		}
	}
	if !found3 {
		t.Fatalf("expected error for unknown detected_at, got %v", errs3)
	}
}
