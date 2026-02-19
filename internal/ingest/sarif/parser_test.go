package sarif

import (
	"strings"
	"testing"
)

func TestParseMapsSARIFResultDeterministically(t *testing.T) {
	payload := []byte(`{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "snyk-code",
          "semanticVersion": "1.2.3",
          "rules": [
            {
              "id": "CVE-2026-1111",
              "shortDescription": {"text":"SQL injection"},
              "fullDescription": {"text":"tainted flow reaches sink"},
              "helpUri": "https://example.local/rule",
              "properties": {
                "category": "vuln",
                "cwe": "CWE-89",
                "references": ["https://example.local/rule-ref"]
              }
            }
          ]
        }
      },
      "invocations": [{"endTimeUtc":"2026-02-19T10:00:00Z"}],
      "results": [
        {
          "ruleId": "CVE-2026-1111",
          "level": "error",
          "message": {"text":"user input reaches SQL sink"},
          "locations": [{"physicalLocation":{"artifactLocation":{"uri":"src/app.go"}}}],
          "fingerprints": {"primaryLocationLineHash":"abc123"},
          "properties": {
            "packageName": "github.com/acme/api",
            "cve": "CVE-2026-1111",
            "confidence": "high",
            "reachability": "reachable",
            "exploitMaturity": "proof-of-concept",
            "security-severity": "9.8",
            "domain_id": "VULN_GENERIC",
            "references": ["https://example.local/finding-ref"]
          }
        }
      ]
    }
  ]
}`)
	findings, err := Parse("scan.sarif", payload, "unknown", "unknown")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	got := findings[0]
	if got.ScannerName != "snyk" || got.ScannerVersion != "1.2.3" {
		t.Fatalf("unexpected scanner metadata: %+v", got)
	}
	if got.Severity != "critical" {
		t.Fatalf("expected critical severity from security-severity, got %s", got.Severity)
	}
	if got.Category != "vuln" || got.DomainID != "VULN_GENERIC" {
		t.Fatalf("unexpected category/domain mapping: %+v", got)
	}
	if got.CVE != "CVE-2026-1111" || got.CWE != "CWE-89" {
		t.Fatalf("unexpected cve/cwe mapping: %+v", got)
	}
	if got.Location != "src/app.go" {
		t.Fatalf("unexpected location: %s", got.Location)
	}
	if got.Component != "github.com/acme/api" {
		t.Fatalf("unexpected component: %s", got.Component)
	}
	if got.DetectedAt != "2026-02-19T10:00:00Z" {
		t.Fatalf("unexpected detected_at: %s", got.DetectedAt)
	}
	if got.RawID != "abc123" {
		t.Fatalf("unexpected raw id: %s", got.RawID)
	}
	if len(got.References) != 3 {
		t.Fatalf("unexpected references count: %+v", got.References)
	}
}

func TestParseDetectsSecretCategoryFromTags(t *testing.T) {
	payload := []byte(`{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name":"checkmarx","version":"1.0.0"}},
      "results": [
        {
          "ruleId": "SECRET-1",
          "message": {"text":"secret exposed"},
          "properties": {"tags":["secret","credentials"]}
        }
      ]
    }
  ]
}`)
	findings, err := Parse("scan.sarif", payload, "unknown", "unknown")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Category != "secret" {
		t.Fatalf("expected secret category, got %s", findings[0].Category)
	}
	if findings[0].DomainID != "SECRET_GENERIC" {
		t.Fatalf("expected SECRET_GENERIC domain, got %s", findings[0].DomainID)
	}
}

func TestParseRejectsUnsupportedVersion(t *testing.T) {
	payload := []byte(`{"version":"2.2.0","runs":[]}`)
	_, err := Parse("scan.sarif", payload, "sarif", "unknown")
	if err == nil {
		t.Fatalf("expected version validation error")
	}
	if !strings.Contains(err.Error(), "unsupported version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRejectsMissingRuns(t *testing.T) {
	payload := []byte(`{"version":"2.1.0"}`)
	_, err := Parse("scan.sarif", payload, "sarif", "unknown")
	if err == nil {
		t.Fatalf("expected missing runs error")
	}
	if !strings.Contains(err.Error(), "missing top-level runs") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRejectsRunWithoutResults(t *testing.T) {
	payload := []byte(`{
  "version":"2.1.0",
  "runs":[{"tool":{"driver":{"name":"scanner"}}}]
}`)
	_, err := Parse("scan.sarif", payload, "sarif", "unknown")
	if err == nil {
		t.Fatalf("expected missing results error")
	}
	if !strings.Contains(err.Error(), "missing results") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseCanonicalizesUnknownSARIFDriverToSarif(t *testing.T) {
	payload := []byte(`{
  "version":"2.1.0",
  "runs":[
    {
      "tool":{"driver":{"name":"semgrep"}},
      "results":[{"ruleId":"R1","message":{"text":"x"}}]
    }
  ]
}`)
	findings, err := Parse("scan.sarif", payload, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ScannerName != "sarif" {
		t.Fatalf("expected canonical scanner id sarif, got %s", findings[0].ScannerName)
	}
}

func TestReportDetectedAt(t *testing.T) {
	payload := []byte(`{
  "version":"2.1.0",
  "runs":[
    {
      "tool":{"driver":{"name":"scanner"}},
      "invocations":[{"startTimeUtc":"2026-02-19T08:00:00Z"}],
      "results":[]
    }
  ]
}`)
	if got := ReportDetectedAt(payload); got != "2026-02-19T08:00:00Z" {
		t.Fatalf("unexpected detected_at: %s", got)
	}
}
