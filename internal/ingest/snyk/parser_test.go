package snyk

import (
	"strings"
	"testing"
)

func TestParseMapsVulnerability(t *testing.T) {
	payload := []byte(`{
  "generatedAt":"2026-02-19T14:00:00Z",
  "projectName":"registry.local/payment-api@sha256:8c6d",
  "displayTargetFile":"package.json",
  "vulnerabilities":[
    {
      "id":"SNYK-JS-LODASH-567746",
      "title":"Prototype Pollution",
      "severity":"high",
      "packageName":"lodash",
      "version":"4.17.20",
      "from":["payment-api","lodash@4.17.20"],
      "description":"vuln description",
      "identifiers":{"CVE":["CVE-2024-1111"],"CWE":["CWE-1321"]},
      "links":[{"url":"https://example.local/advisory"}],
      "confidence":"high",
      "exploitMaturity":"proof-of-concept",
      "reachability":"reachable"
    }
  ]
}`)
	findings, err := Parse("snyk.json", payload, "snyk", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	got := findings[0]
	if got.Category != "vuln" || got.DomainID != "VULN_GENERIC" {
		t.Fatalf("unexpected category/domain: %+v", got)
	}
	if got.CVE != "CVE-2024-1111" || got.CWE != "CWE-1321" {
		t.Fatalf("unexpected cve/cwe: %+v", got)
	}
	if got.Component != "lodash@4.17.20" {
		t.Fatalf("unexpected component: %s", got.Component)
	}
	if got.Location != "lodash@4.17.20" {
		t.Fatalf("unexpected location: %s", got.Location)
	}
	if got.DetectedAt != "2026-02-19T14:00:00Z" {
		t.Fatalf("unexpected detected_at: %s", got.DetectedAt)
	}
}

func TestParseDetectsSecretCategory(t *testing.T) {
	payload := []byte(`{
  "vulnerabilities":[
    {
      "id":"SECRET-123",
      "title":"Hardcoded secret in file",
      "severity":"critical",
      "packageName":"src/config.env"
    }
  ]
}`)
	findings, err := Parse("snyk.json", payload, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Category != "secret" || findings[0].DomainID != "SECRET_GENERIC" {
		t.Fatalf("unexpected secret mapping: %+v", findings[0])
	}
}

func TestParseRejectsMissingVulnerabilities(t *testing.T) {
	payload := []byte(`{"ok":true}`)
	_, err := Parse("snyk.json", payload, "", "")
	if err == nil {
		t.Fatalf("expected envelope error")
	}
	if !strings.Contains(err.Error(), "missing top-level vulnerabilities") {
		t.Fatalf("unexpected error: %v", err)
	}
}
