package sonar

import (
	"strings"
	"testing"
)

func TestParseMapsGenericIssue(t *testing.T) {
	payload := []byte(`{
  "generatedAt":"2026-02-19T16:00:00Z",
  "projectKey":"payments-api",
  "rules":[
    {
      "id":"sql-injection",
      "name":"SQL injection",
      "description":"Unsanitized SQL",
      "engineId":"sonar-security",
      "severity":"CRITICAL",
      "type":"VULNERABILITY",
      "helpUri":"https://example.local/sonar/sql"
    }
  ],
  "issues":[
    {
      "ruleId":"sql-injection",
      "type":"VULNERABILITY",
      "primaryLocation":{"message":"User input reaches SQL sink","filePath":"src/app.go","textRange":{"startLine":42}}
    }
  ]
}`)
	findings, err := Parse("sonar.json", payload, "", "")
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
	if got.Severity != "critical" {
		t.Fatalf("unexpected severity: %s", got.Severity)
	}
	if got.Location != "src/app.go" {
		t.Fatalf("unexpected location: %s", got.Location)
	}
	if got.DetectedAt != "2026-02-19T16:00:00Z" {
		t.Fatalf("unexpected detected_at: %s", got.DetectedAt)
	}
	if len(got.References) != 1 {
		t.Fatalf("expected one reference, got %+v", got.References)
	}
}

func TestParseDetectsSecretCategory(t *testing.T) {
	payload := []byte(`{
  "issues":[
    {"ruleId":"hardcoded-secret","primaryLocation":{"message":"Secret token found","filePath":"app.env"}}
  ]
}`)
	findings, err := Parse("sonar.json", payload, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Category != "secret" || findings[0].DomainID != "SECRET_GENERIC" {
		t.Fatalf("unexpected secret mapping: %+v", findings[0])
	}
}

func TestParseRejectsMissingIssues(t *testing.T) {
	payload := []byte(`{"rules":[]}`)
	_, err := Parse("sonar.json", payload, "", "")
	if err == nil {
		t.Fatalf("expected missing issues error")
	}
	if !strings.Contains(err.Error(), "missing top-level issues") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRejectsIssueWithoutRuleID(t *testing.T) {
	payload := []byte(`{"issues":[{"primaryLocation":{"message":"x","filePath":"a"}}]}`)
	_, err := Parse("sonar.json", payload, "", "")
	if err == nil {
		t.Fatalf("expected missing ruleId error")
	}
	if !strings.Contains(err.Error(), "missing ruleId") {
		t.Fatalf("unexpected error: %v", err)
	}
}
