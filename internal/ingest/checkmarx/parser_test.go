package checkmarx

import (
	"strings"
	"testing"
)

func TestParseMapsScanResult(t *testing.T) {
	payload := []byte(`{
  "reportType":"json-v2",
  "scanInfo":{"projectName":"payments-api","finishedAt":"2026-02-19T15:00:00Z"},
  "scanResults":[
    {
      "queryId": 101,
      "queryName":"SQL Injection",
      "severity":"High",
      "state":"Confirmed",
      "type":"vulnerability",
      "similarityId":"cx-abc-1",
      "filePath":"src/app.go",
      "component":"sql-driver",
      "cwe":"CWE-89",
      "description":"tainted input reaches sink",
      "references":["https://example.local/cx/1"]
    }
  ]
}`)
	findings, err := Parse("checkmarx.json", payload, "checkmarx", "3.0.0")
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
	if got.Severity != "high" || got.Confidence != "high" {
		t.Fatalf("unexpected severity/confidence: %+v", got)
	}
	if got.Location != "src/app.go" || got.Component != "sql-driver" {
		t.Fatalf("unexpected location/component: %+v", got)
	}
	if got.RawID != "cx-abc-1" {
		t.Fatalf("unexpected raw id: %s", got.RawID)
	}
	if got.DetectedAt != "2026-02-19T15:00:00Z" {
		t.Fatalf("unexpected detected_at: %s", got.DetectedAt)
	}
}

func TestParseDetectsSecretCategory(t *testing.T) {
	payload := []byte(`{
  "scanResults":[
    {"queryName":"Hardcoded Secret","severity":"Critical","filePath":"app.env"}
  ]
}`)
	findings, err := Parse("checkmarx.json", payload, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Category != "secret" || findings[0].DomainID != "SECRET_GENERIC" {
		t.Fatalf("unexpected secret mapping: %+v", findings[0])
	}
}

func TestParseRejectsMissingScanResults(t *testing.T) {
	payload := []byte(`{"reportType":"json-v2"}`)
	_, err := Parse("checkmarx.json", payload, "", "")
	if err == nil {
		t.Fatalf("expected envelope error")
	}
	if !strings.Contains(err.Error(), "missing top-level scanResults") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRejectsUnsupportedReportType(t *testing.T) {
	payload := []byte(`{"reportType":"json-v1","scanResults":[]}`)
	_, err := Parse("checkmarx.json", payload, "", "")
	if err == nil {
		t.Fatalf("expected reportType error")
	}
	if !strings.Contains(err.Error(), "unsupported reportType") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRejectsNonStringReportType(t *testing.T) {
	payload := []byte(`{"reportType":2,"scanResults":[]}`)
	_, err := Parse("checkmarx.json", payload, "", "")
	if err == nil {
		t.Fatalf("expected reportType type error")
	}
	if !strings.Contains(err.Error(), "reportType must be a string") {
		t.Fatalf("unexpected error: %v", err)
	}
}
