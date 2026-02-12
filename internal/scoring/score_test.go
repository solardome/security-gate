package scoring

import (
	"testing"
	"time"

	"github.com/solardome/security-gate/internal/domain"
	"github.com/solardome/security-gate/internal/ingest/trivy"
)

func baseFinding() trivy.CanonicalFinding {
	return trivy.CanonicalFinding{
		FindingID:       "test",
		Domain:          string(domain.DomainVulnerability),
		Severity:        "MEDIUM",
		SourceScanner:   "trivy",
		SourceVersion:   "1.0",
		InputSHA256:     "hash",
		ScanTimestamp:   time.Now().UTC(),
		TimestampSource: "scanner",
		Location:        trivy.Location{Path: "./file"},
	}
}

func TestScoreFindingModifiers(t *testing.T) {
	finding := baseFinding()
	finding.ExploitMaturity = "confirmed"
	finding.Reachability = "reachable"
	finding.FixAvailable = "false"
	finding.DependencyScope = "direct"

	scored := scoreFinding(finding)

	if scored.RiskScore != 90 {
		t.Errorf("expected risk 90 but got %d", scored.RiskScore)
	}
	if scored.BaseScore != 50 {
		t.Errorf("expected base 50 but got %d", scored.BaseScore)
	}
	if scored.Modifiers.LicenseType != 0 {
		t.Errorf("license modifier should not apply for vulnerability domain")
	}
}

func TestLicenseDomainModifier(t *testing.T) {
	finding := baseFinding()
	finding.Domain = string(domain.DomainLicense)
	finding.LicenseType = "weak_copyleft"
	finding.ExploitMaturity = "none"
	finding.Reachability = "unknown"
	finding.FixAvailable = "true"
	finding.DependencyScope = "transitive"

	scored := scoreFinding(finding)

	if scored.Modifiers.LicenseType != 5 {
		t.Fatalf("expected license modifier for weak copyleft, got %d", scored.Modifiers.LicenseType)
	}
}

func TestScoreFindingCVSS(t *testing.T) {
	finding := baseFinding()
	cvss := 7.3
	finding.CVSSv3 = &cvss
	finding.Severity = "LOW"

	scored := scoreFinding(finding)
	if scored.BaseScore != 73 {
		t.Errorf("expected CVSS base 73 but got %d", scored.BaseScore)
	}
}

func TestScoreFindingHardStop(t *testing.T) {
	finding := baseFinding()
	finding.Domain = string(domain.DomainSecret)

	scored := scoreFinding(finding)
	if !scored.HardStop {
		t.Fatalf("expected hard stop")
	}
	if scored.RiskScore != 100 {
		t.Fatalf("hard stop should be 100 risk")
	}
}

func TestTrustSignalsPerfectScore(t *testing.T) {
	now := time.Now().UTC()
	scanTime := now.Add(-1 * time.Hour)
	protected := true
	trustCtx := TrustContext{
		ScannerPinned:         true,
		ScanTimestamp:         &scanTime,
		InputIntegrityStatus:  "verified",
		ArtifactSigningStatus: "verified",
		ProvenanceLevel:       "level3+",
		BuildContextProtected: &protected,
	}

	result := Score(nil, trustCtx, now)
	if result.TrustScore != 100 {
		t.Fatalf("expected perfect trust score, got %d", result.TrustScore)
	}
	if result.TrustModifier != 0 {
		t.Fatalf("expected modifier 0, got %d", result.TrustModifier)
	}
}

func TestTrustSignalsStaleTimestamp(t *testing.T) {
	now := time.Now().UTC()
	stale := now.Add(-40 * 24 * time.Hour)
	trustCtx := TrustContext{ScanTimestamp: &stale}

	result := Score(nil, trustCtx, now)
	if result.TrustSignals.ScanFreshness.Score != 0.2 {
		t.Fatalf("expected stale freshness score of 0.2, got %f", result.TrustSignals.ScanFreshness.Score)
	}
	if len(result.Trace) != 1 {
		t.Fatalf("expected 1 trace event for stale timestamp, got %d", len(result.Trace))
	}
}
