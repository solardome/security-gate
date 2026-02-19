package trivy

import (
	"strings"
	"testing"
)

func TestParseUsesReportGeneratedAtForDetectedAt(t *testing.T) {
	payload := []byte(`{
  "ArtifactName":"registry.local/payment-api@sha256:abc",
  "GeneratedAt":"2026-02-18T10:00:00Z",
  "Results":[
    {
      "Target":"payment-api",
      "Vulnerabilities":[
        {"VulnerabilityID":"CVE-2026-0001","PkgName":"openssl","Severity":"HIGH","Title":"issue"}
      ]
    }
  ]
}`)
	findings, err := Parse("scan.json", payload, "trivy", "0.50.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].DetectedAt != "2026-02-18T10:00:00Z" {
		t.Fatalf("unexpected detected_at: %s", findings[0].DetectedAt)
	}
}

func TestParseWithoutReportTimestampUsesUnknownDetectedAt(t *testing.T) {
	payload := []byte(`{
  "ArtifactName":"registry.local/payment-api@sha256:abc",
  "Results":[
    {
      "Target":"payment-api",
      "Vulnerabilities":[
        {
          "VulnerabilityID":"CVE-2026-0001",
          "PkgName":"openssl",
          "Severity":"HIGH",
          "Title":"issue",
          "PublishedDate":"2010-01-01T00:00:00Z"
        }
      ]
    }
  ]
}`)
	findings, err := Parse("scan.json", payload, "trivy", "0.50.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].DetectedAt != "unknown" {
		t.Fatalf("expected unknown detected_at, got %s", findings[0].DetectedAt)
	}
}

func TestParseRejectsMissingResultsEnvelope(t *testing.T) {
	payload := []byte(`{"ArtifactName":"registry.local/payment-api@sha256:abc"}`)
	_, err := Parse("scan.json", payload, "trivy", "0.50.0")
	if err == nil {
		t.Fatalf("expected missing Results error")
	}
	if !strings.Contains(err.Error(), "missing top-level Results") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRejectsUnsupportedSchemaVersion(t *testing.T) {
	payload := []byte(`{
  "SchemaVersion": 9,
  "ArtifactName":"registry.local/payment-api@sha256:abc",
  "Results":[]
}`)
	_, err := Parse("scan.json", payload, "trivy", "0.50.0")
	if err == nil {
		t.Fatalf("expected unsupported schema version error")
	}
	if !strings.Contains(err.Error(), "unsupported SchemaVersion") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseIncludesMisconfigAndSecretFindings(t *testing.T) {
	payload := []byte(`{
  "SchemaVersion": 2,
  "ArtifactName":"registry.local/payment-api@sha256:abc",
  "GeneratedAt":"2026-02-18T10:00:00Z",
  "Results":[
    {
      "Target":"payment-api",
      "Misconfigurations":[
        {"ID":"AVD-KSV-1","Type":"kubernetes","Title":"privileged pod","Severity":"HIGH"}
      ],
      "Secrets":[
        {"RuleID":"GITLAB-PAT","Category":"token","Title":"token detected","Severity":"CRITICAL"}
      ]
    }
  ]
}`)
	findings, err := Parse("scan.json", payload, "trivy", "0.50.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Category != "misconfig" || findings[0].DomainID != "MISCONFIG_GENERIC" {
		t.Fatalf("unexpected misconfig mapping: %+v", findings[0])
	}
	if findings[1].Category != "secret" || findings[1].DomainID != "SECRET_GENERIC" {
		t.Fatalf("unexpected secret mapping: %+v", findings[1])
	}
}

func TestParseCanonicalizesScannerNameToTrivy(t *testing.T) {
	payload := []byte(`{
  "ArtifactName":"registry.local/payment-api@sha256:abc",
  "GeneratedAt":"2026-02-18T10:00:00Z",
  "Results":[
    {
      "Target":"payment-api",
      "Vulnerabilities":[
        {"VulnerabilityID":"CVE-2026-0001","PkgName":"openssl","Severity":"HIGH","Title":"issue"}
      ]
    }
  ]
}`)
	findings, err := Parse("scan.json", payload, "grype", "0.50.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].ScannerName != "trivy" {
		t.Fatalf("expected canonical scanner name trivy, got %s", findings[0].ScannerName)
	}
}

func TestParseUsesReportScannerVersionWhenPresent(t *testing.T) {
	payload := []byte(`{
  "Scanner":{"Name":"Trivy","Version":"0.59.1"},
  "ArtifactName":"registry.local/payment-api@sha256:abc",
  "GeneratedAt":"2026-02-18T10:00:00Z",
  "Results":[
    {
      "Target":"payment-api",
      "Vulnerabilities":[
        {"VulnerabilityID":"CVE-2026-0001","PkgName":"openssl","Severity":"HIGH","Title":"issue"}
      ]
    }
  ]
}`)
	findings, err := Parse("scan.json", payload, "trivy", "0.50.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].ScannerVersion != "0.59.1" {
		t.Fatalf("expected scanner version from report, got %s", findings[0].ScannerVersion)
	}
}

func TestParseUsesUnknownScannerVersionWhenReportLacksVersion(t *testing.T) {
	payload := []byte(`{
  "ArtifactName":"registry.local/payment-api@sha256:abc",
  "GeneratedAt":"2026-02-18T10:00:00Z",
  "Results":[
    {
      "Target":"payment-api",
      "Vulnerabilities":[
        {"VulnerabilityID":"CVE-2026-0001","PkgName":"openssl","Severity":"HIGH","Title":"issue"}
      ]
    }
  ]
}`)
	findings, err := Parse("scan.json", payload, "trivy", "0.50.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].ScannerVersion != "unknown" {
		t.Fatalf("expected unknown scanner version when report lacks version, got %s", findings[0].ScannerVersion)
	}
}
