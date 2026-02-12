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

func fixturePath(name string) string {
	return filepath.Join("..", "..", "..", "testdata", name)
}

func TestIngestNormalizesMissingTimestampAndSourceVersion(t *testing.T) {
	t.Parallel()

	inputPath := fixturePath("trivy-missing-meta.json")

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

	inputPath := fixturePath("trivy-invalid.json")

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

func TestIngestParsesSampleFixture(t *testing.T) {
	t.Parallel()

	inputPath := fixturePath("trivy-report-sample.json")
	result, err := Ingest(context.Background(), StagePR, []string{inputPath})
	if err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings from sample fixture, got %d", len(result.Findings))
	}

	seenVuln := false
	seenMisconfig := false
	for _, finding := range result.Findings {
		switch finding.FindingID {
		case "CVE-2026-12345":
			seenVuln = true
			if finding.SourceVersion != "0.58.1" {
				t.Fatalf("expected source_version=0.58.1 for vuln finding, got %q", finding.SourceVersion)
			}
			if finding.TimestampSource != "scanner" {
				t.Fatalf("expected timestamp_source=scanner for vuln finding, got %q", finding.TimestampSource)
			}
		case "AVD-AWS-0001":
			seenMisconfig = true
		}
	}

	if !seenVuln || !seenMisconfig {
		t.Fatalf("expected vuln and misconfiguration findings, got vuln=%v misconfig=%v", seenVuln, seenMisconfig)
	}
}
