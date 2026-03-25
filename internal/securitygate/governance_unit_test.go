package securitygate

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// scopeTypeAllowedByPolicy
// ---------------------------------------------------------------------------

func TestScopeTypeAllowedByPolicy(t *testing.T) {
	allowed := []string{"finding_id", "cve", "component"}
	if !scopeTypeAllowedByPolicy("finding_id", allowed) {
		t.Fatal("finding_id should be allowed")
	}
	if !scopeTypeAllowedByPolicy("CVE", allowed) {
		t.Fatal("CVE (case-insensitive) should be allowed")
	}
	if scopeTypeAllowedByPolicy("domain", allowed) {
		t.Fatal("domain should not be allowed")
	}
	if scopeTypeAllowedByPolicy("finding_id", nil) {
		t.Fatal("empty allowed list should deny everything")
	}
	if scopeTypeAllowedByPolicy("finding_id", []string{}) {
		t.Fatal("empty allowed list should deny everything")
	}
}

// ---------------------------------------------------------------------------
// scopeScannerMatches
// ---------------------------------------------------------------------------

func TestScopeScannerMatches(t *testing.T) {
	if !scopeScannerMatches("", "trivy") {
		t.Fatal("empty filter should match any scanner")
	}
	if !scopeScannerMatches("*", "trivy") {
		t.Fatal("wildcard filter should match any scanner")
	}
	if !scopeScannerMatches("unknown", "trivy") {
		t.Fatal("unknown filter should match any scanner")
	}
	if !scopeScannerMatches("trivy", "trivy") {
		t.Fatal("exact match should succeed")
	}
	if !scopeScannerMatches("TRIVY", "trivy") {
		t.Fatal("case-insensitive match should succeed")
	}
	if scopeScannerMatches("snyk", "trivy") {
		t.Fatal("mismatched scanners should not match")
	}
}

// ---------------------------------------------------------------------------
// scopeRepositoryMatches
// ---------------------------------------------------------------------------

func TestScopeRepositoryMatches(t *testing.T) {
	if !scopeRepositoryMatches("", "any/repo") {
		t.Fatal("empty filter should match any repo")
	}
	if !scopeRepositoryMatches("*", "any/repo") {
		t.Fatal("wildcard should match any repo")
	}
	if !scopeRepositoryMatches("github.com/org/repo", "github.com/org/repo") {
		t.Fatal("exact match should succeed")
	}
	// Tag suffix stripped.
	if !scopeRepositoryMatches("github.com/org/repo", "github.com/org/repo:latest") {
		t.Fatal("tag suffix should be ignored")
	}
	// Digest stripped.
	if !scopeRepositoryMatches("github.com/org/repo", "github.com/org/repo@sha256:abc") {
		t.Fatal("digest suffix should be ignored")
	}
	if scopeRepositoryMatches("github.com/org/other", "github.com/org/repo") {
		t.Fatal("different repo should not match")
	}
}

// ---------------------------------------------------------------------------
// normalizeRepoIdentity
// ---------------------------------------------------------------------------

func TestNormalizeRepoIdentity(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"unknown", ""},
		{"github.com/org/repo", "github.com/org/repo"},
		{"github.com/org/repo:v1.0", "github.com/org/repo"},
		{"github.com/org/repo@sha256:abc123", "github.com/org/repo"},
		{"GITHUB.COM/ORG/REPO", "github.com/org/repo"},
	}
	for _, c := range cases {
		got := normalizeRepoIdentity(c.in)
		if got != c.want {
			t.Fatalf("normalizeRepoIdentity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// expSoon
// ---------------------------------------------------------------------------

func TestExpSoon(t *testing.T) {
	now := time.Now().UTC()

	// Expires in 3 days → near expiry.
	rec3days := AcceptedRiskRecord{
		Timeline: AcceptedRiskTimeline{ExpiresAt: now.Add(3 * 24 * time.Hour).Format(time.RFC3339)},
	}
	if !expSoon(rec3days, now) {
		t.Fatal("expected expSoon=true for expiry in 3 days")
	}

	// Expires in 10 days → not near expiry.
	rec10days := AcceptedRiskRecord{
		Timeline: AcceptedRiskTimeline{ExpiresAt: now.Add(10 * 24 * time.Hour).Format(time.RFC3339)},
	}
	if expSoon(rec10days, now) {
		t.Fatal("expected expSoon=false for expiry in 10 days")
	}

	// Already expired → not "expiring soon".
	recExpired := AcceptedRiskRecord{
		Timeline: AcceptedRiskTimeline{ExpiresAt: now.Add(-1 * time.Hour).Format(time.RFC3339)},
	}
	if expSoon(recExpired, now) {
		t.Fatal("expired record should not be reported as expiring soon")
	}

	// Bad timestamp → false (no panic).
	recBad := AcceptedRiskRecord{Timeline: AcceptedRiskTimeline{ExpiresAt: "not-a-date"}}
	if expSoon(recBad, now) {
		t.Fatal("bad timestamp should return false")
	}
}

// ---------------------------------------------------------------------------
// hasSecurityApprover
// ---------------------------------------------------------------------------

func TestHasSecurityApproverByID(t *testing.T) {
	rules := ExceptionRules{
		SecurityApproverIDs: []string{"alice", "bob"},
	}
	if !hasSecurityApprover([]string{"alice"}, rules) {
		t.Fatal("alice is a known approver ID")
	}
	if !hasSecurityApprover([]string{"user:alice"}, rules) {
		t.Fatal("user: prefix should be stripped and matched")
	}
	if hasSecurityApprover([]string{"charlie"}, rules) {
		t.Fatal("charlie is not a known approver")
	}
	if hasSecurityApprover(nil, rules) {
		t.Fatal("empty approvers should return false")
	}
}

func TestHasSecurityApproverByGroup(t *testing.T) {
	rules := ExceptionRules{
		SecurityApproverGroups: []string{"security", "platform"},
	}
	if !hasSecurityApprover([]string{"group:security"}, rules) {
		t.Fatal("security is a known approver group")
	}
	if !hasSecurityApprover([]string{"group:SECURITY"}, rules) {
		t.Fatal("group match should be case-insensitive")
	}
	if hasSecurityApprover([]string{"group:ops"}, rules) {
		t.Fatal("ops is not a known approver group")
	}
}

// ---------------------------------------------------------------------------
// applyHardStops
// ---------------------------------------------------------------------------

func TestApplyHardStopsCanonical(t *testing.T) {
	findings := []UnifiedFinding{
		{Class: UnifiedClassification{DomainID: "HS_ACTIVE_RUNTIME_MALWARE", Severity: "critical"}},
		{Class: UnifiedClassification{DomainID: "VULN_GENERIC", Severity: "high"}},
	}
	triggered := applyHardStops(findings, Policy{})
	if len(triggered) != 1 || triggered[0] != "HS_ACTIVE_RUNTIME_MALWARE" {
		t.Fatalf("expected only canonical hard-stop triggered, got %v", triggered)
	}
	if !findings[0].HardStop {
		t.Fatal("canonical hard-stop finding must be marked HardStop=true")
	}
	if findings[1].HardStop {
		t.Fatal("normal finding must not be marked as hard-stop")
	}
}

func TestApplyHardStopsAdditional(t *testing.T) {
	findings := []UnifiedFinding{
		{Class: UnifiedClassification{DomainID: "CUSTOM_STOP", Severity: "high"}},
	}
	pol := Policy{}
	pol.DomainOverrides.AdditionalHardStops = []string{"CUSTOM_STOP"}
	triggered := applyHardStops(findings, pol)
	if len(triggered) != 1 || triggered[0] != "CUSTOM_STOP" {
		t.Fatalf("additional hard-stop should be triggered, got %v", triggered)
	}
	if !findings[0].HardStop {
		t.Fatal("additional hard-stop finding must be marked HardStop=true")
	}
}

func TestApplyHardStopsEmptyIgnored(t *testing.T) {
	pol := Policy{}
	pol.DomainOverrides.AdditionalHardStops = []string{"  ", ""}
	findings := []UnifiedFinding{
		{Class: UnifiedClassification{DomainID: "", Severity: "low"}},
	}
	triggered := applyHardStops(findings, pol)
	if len(triggered) != 0 {
		t.Fatalf("blank additional hard-stops should be ignored, got %v", triggered)
	}
}
