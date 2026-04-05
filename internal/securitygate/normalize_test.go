package securitygate

import (
	"testing"
)

func TestNormalizeFindingsSeverityCoercion(t *testing.T) {
	in := []AdapterFinding{
		{
			RawID:    "f1",
			Severity: "CRITICAL",
			// All other fields valid.
			Confidence:      "high",
			ExploitMaturity: "poc",
			Reachability:    "reachable",
		},
		{
			RawID:    "f2",
			Severity: "garbage", // unknown → coerced to "unknown"
		},
	}
	out := normalizeFindings(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}
	if out[0].Class.Severity != "critical" {
		t.Fatalf("severity should be lowercased, got %q", out[0].Class.Severity)
	}
	if out[1].Class.Severity != "unknown" {
		t.Fatalf("invalid severity should coerce to unknown, got %q", out[1].Class.Severity)
	}
}

func TestNormalizeFindingsConfidenceCoercion(t *testing.T) {
	in := []AdapterFinding{
		{RawID: "f1", Confidence: "HIGH"},
		{RawID: "f2", Confidence: "bogus"},
	}
	out := normalizeFindings(in)
	if out[0].Class.Confidence != "high" {
		t.Fatalf("expected confidence=high, got %q", out[0].Class.Confidence)
	}
	if out[1].Class.Confidence != "unknown" {
		t.Fatalf("invalid confidence should coerce to unknown, got %q", out[1].Class.Confidence)
	}
}

func TestNormalizeFindingsExploitMaturityCoercion(t *testing.T) {
	valid := []string{"known_exploited", "poc", "none"}
	for _, v := range valid {
		out := normalizeFindings([]AdapterFinding{{RawID: "x", ExploitMaturity: v}})
		if out[0].Class.ExploitMaturity != v {
			t.Fatalf("exploit_maturity %q should be preserved, got %q", v, out[0].Class.ExploitMaturity)
		}
	}
	out := normalizeFindings([]AdapterFinding{{RawID: "x", ExploitMaturity: "wild"}})
	if out[0].Class.ExploitMaturity != "unknown" {
		t.Fatalf("invalid exploit_maturity should coerce to unknown, got %q", out[0].Class.ExploitMaturity)
	}
}

func TestNormalizeFindingsReachabilityCoercion(t *testing.T) {
	valid := []string{"reachable", "potentially_reachable", "not_reachable"}
	for _, v := range valid {
		out := normalizeFindings([]AdapterFinding{{RawID: "x", Reachability: v}})
		if out[0].Class.Reachability != v {
			t.Fatalf("reachability %q should be preserved, got %q", v, out[0].Class.Reachability)
		}
	}
	out := normalizeFindings([]AdapterFinding{{RawID: "x", Reachability: "maybe"}})
	if out[0].Class.Reachability != "unknown" {
		t.Fatalf("invalid reachability should coerce to unknown, got %q", out[0].Class.Reachability)
	}
}

func TestNormalizeFindingsFallbackID(t *testing.T) {
	// RawID empty → fallback hash generated.
	in := []AdapterFinding{
		{RawID: "", ScannerName: "trivy", Title: "CVE-2021-0001", Location: "Dockerfile"},
	}
	out := normalizeFindings(in)
	if out[0].FindingID == "" {
		t.Fatal("fallback ID must not be empty")
	}
	if len(out[0].FindingID) != 64 {
		t.Fatalf("fallback ID must be hex SHA-256 (64 chars), got len=%d", len(out[0].FindingID))
	}
}

func TestNormalizeFindingsFallbackIDDeterministic(t *testing.T) {
	in := []AdapterFinding{
		{RawID: "", ScannerName: "trivy", Title: "CVE-2021-0001", Location: "Dockerfile"},
	}
	id1 := normalizeFindings(in)[0].FindingID
	id2 := normalizeFindings(in)[0].FindingID
	if id1 != id2 {
		t.Fatalf("fallback ID must be deterministic: %q != %q", id1, id2)
	}
}

func TestNormalizeFindingsDefaultsForEmptyFields(t *testing.T) {
	in := []AdapterFinding{{RawID: "x"}}
	out := normalizeFindings(in)
	if out[0].Artifact.TargetRef != "unknown" {
		t.Fatalf("empty target_ref should default to unknown, got %q", out[0].Artifact.TargetRef)
	}
	if out[0].Artifact.Component != "unknown" {
		t.Fatalf("empty component should default to unknown, got %q", out[0].Artifact.Component)
	}
	if out[0].Artifact.Location != "unknown" {
		t.Fatalf("empty location should default to unknown, got %q", out[0].Artifact.Location)
	}
	if out[0].DetectedAt != "unknown" {
		t.Fatalf("empty detected_at should default to unknown, got %q", out[0].DetectedAt)
	}
}

func TestSortFindingsDeterministicallyHardStopFirst(t *testing.T) {
	findings := []UnifiedFinding{
		{FindingID: "b", FindingRiskScore: 90, HardStop: false, Class: UnifiedClassification{Severity: "critical"}},
		{FindingID: "a", FindingRiskScore: 10, HardStop: true, Class: UnifiedClassification{Severity: "low"}},
	}
	sortFindingsDeterministically(findings)
	if !findings[0].HardStop {
		t.Fatal("hard-stop finding must sort first")
	}
}

func TestSortFindingsDeterministicallyByRiskScore(t *testing.T) {
	findings := []UnifiedFinding{
		{FindingID: "low", FindingRiskScore: 30, Class: UnifiedClassification{Severity: "low"}},
		{FindingID: "high", FindingRiskScore: 80, Class: UnifiedClassification{Severity: "high"}},
	}
	sortFindingsDeterministically(findings)
	if findings[0].FindingID != "high" {
		t.Fatal("higher risk score should sort first")
	}
}

func TestSortFindingsDeterministicallyStable(t *testing.T) {
	findings1 := []UnifiedFinding{
		{FindingID: "z", FindingRiskScore: 50, Class: UnifiedClassification{Severity: "high", DomainID: "A"}},
		{FindingID: "a", FindingRiskScore: 50, Class: UnifiedClassification{Severity: "high", DomainID: "A"}},
	}
	findings2 := []UnifiedFinding{findings1[1], findings1[0]}
	sortFindingsDeterministically(findings1)
	sortFindingsDeterministically(findings2)
	if findings1[0].FindingID != findings2[0].FindingID {
		t.Fatalf("sort is not deterministic: %q vs %q", findings1[0].FindingID, findings2[0].FindingID)
	}
}

func TestFallbackFindingIDDifferentInputsDifferentHash(t *testing.T) {
	f1 := AdapterFinding{ScannerName: "trivy", Title: "CVE-A", Location: "file1"}
	f2 := AdapterFinding{ScannerName: "trivy", Title: "CVE-B", Location: "file1"}
	id1 := fallbackFindingID(f1)
	id2 := fallbackFindingID(f2)
	if id1 == id2 {
		t.Fatal("different findings must produce different fallback IDs")
	}
}
