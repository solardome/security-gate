package trivy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIngestNormalizesMissingTimestampAndSourceVersion(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "trivy.json")

	payload := `{
  "SchemaVersion": 2,
  "Results": [
    {
      "Target": "alpine:3.20",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2026-0001",
          "PkgName": "openssl",
          "InstalledVersion": "1.0.0",
          "Severity": "HIGH",
          "Title": "openssl vuln",
          "Description": "example"
        }
      ]
    }
  ]
}`
	if err := os.WriteFile(inputPath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	result, err := Ingest(context.Background(), StagePR, []string{inputPath})
	if err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.TimestampSource != "ingest" {
		t.Fatalf("expected timestamp_source=ingest, got %q", finding.TimestampSource)
	}
	if finding.SourceVersion != "unknown" {
		t.Fatalf("expected source_version=unknown, got %q", finding.SourceVersion)
	}

	hasTimestampEvent := false
	hasVersionEvent := false
	for _, event := range result.Trace {
		if event.Type == "ingest.scan_timestamp_missing" {
			hasTimestampEvent = true
		}
		if event.Type == "context.source_version_missing" {
			hasVersionEvent = true
		}
	}
	if !hasTimestampEvent {
		t.Fatalf("expected ingest.scan_timestamp_missing event")
	}
	if !hasVersionEvent {
		t.Fatalf("expected context.source_version_missing event")
	}
}

func TestIngestReturnsFatalForInvalidJSON(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "broken.json")
	if err := os.WriteFile(inputPath, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	_, err := Ingest(context.Background(), StageMain, []string{inputPath})
	if err == nil {
		t.Fatalf("expected error")
	}
	if _, ok := err.(FatalError); !ok {
		t.Fatalf("expected FatalError, got %T", err)
	}
}

func TestIngestReturnsFatalForFindingCountExceeded(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "too-many-findings.json")

	var b strings.Builder
	b.WriteString(`{"SchemaVersion":2,"Results":[{"Target":"app","Vulnerabilities":[`)
	for i := 0; i < 10001; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(fmt.Sprintf(`{"VulnerabilityID":"CVE-2026-%05d","PkgName":"pkg","InstalledVersion":"1.0.0","Severity":"HIGH","Title":"v","Description":"d"}`, i))
	}
	b.WriteString(`]}]}`)

	if err := os.WriteFile(inputPath, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	_, err := Ingest(context.Background(), StageMain, []string{inputPath})
	if err == nil {
		t.Fatalf("expected error")
	}
	if _, ok := err.(FatalError); !ok {
		t.Fatalf("expected FatalError, got %T", err)
	}
	type codeCarrier interface {
		ErrorCode() string
	}
	var coded codeCarrier
	if !errors.As(err, &coded) {
		t.Fatalf("expected coded error")
	}
	if coded.ErrorCode() != "FINDING_COUNT_EXCEEDED" {
		t.Fatalf("expected FINDING_COUNT_EXCEEDED, got %s", coded.ErrorCode())
	}
}
