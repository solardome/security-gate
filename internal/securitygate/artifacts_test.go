package securitygate

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWritesChecksumsAndRunLog(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
	})

	outJSON := filepath.Join(dir, "result.report.json")
	outHTML := filepath.Join(dir, "result.report.html")
	outChecksums := filepath.Join(dir, "result.checksums.sha256")
	outRunLog := filepath.Join(dir, "result.run.log")

	_, err := Run(Config{
		ScanPaths:     []string{paths.Scan},
		ContextPath:   paths.Context,
		PolicyPath:    paths.Policy,
		OutJSONPath:   outJSON,
		OutHTMLPath:   outHTML,
		ChecksumsPath: outChecksums,
		RunLogPath:    outRunLog,
		WriteHTML:     true,
	})
	if err != nil {
		t.Fatal(err)
	}

	rawChecksums, err := os.ReadFile(outChecksums)
	if err != nil {
		t.Fatalf("checksums file missing: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(rawChecksums)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 checksum lines, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], filepath.Base(outHTML)) && !strings.Contains(lines[1], filepath.Base(outHTML)) {
		t.Fatalf("missing html checksum line: %v", lines)
	}
	if !strings.Contains(lines[0], filepath.Base(outJSON)) && !strings.Contains(lines[1], filepath.Base(outJSON)) {
		t.Fatalf("missing json checksum line: %v", lines)
	}

	f, err := os.Open(outRunLog)
	if err != nil {
		t.Fatalf("run log missing: %v", err)
	}
	defer f.Close()
	var sawStart bool
	var sawComplete bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var evt struct {
			Event  string                 `json:"event"`
			Fields map[string]interface{} `json:"fields"`
		}
		if err := json.Unmarshal(sc.Bytes(), &evt); err != nil {
			t.Fatalf("invalid run log json line: %v", err)
		}
		if evt.Event == "run.start" {
			sawStart = true
		}
		if evt.Event == "run.complete" {
			sawComplete = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if !sawStart || !sawComplete {
		t.Fatalf("expected run.start and run.complete events, got start=%v complete=%v", sawStart, sawComplete)
	}
}

func TestRunNoHTMLChecksumsContainOnlyJSON(t *testing.T) {
	dir := t.TempDir()
	paths := writeScenario(t, dir, scenarioConfig{
		BranchType:    "feature",
		PipelineStage: "pr",
		Environment:   "ci",
		Severity:      "low",
		DomainID:      "VULN_GENERIC",
	})

	outJSON := filepath.Join(dir, "only-json.report.json")
	outChecksums := filepath.Join(dir, "only-json.checksums.sha256")
	_, err := Run(Config{
		ScanPaths:     []string{paths.Scan},
		ContextPath:   paths.Context,
		PolicyPath:    paths.Policy,
		OutJSONPath:   outJSON,
		ChecksumsPath: outChecksums,
		RunLogPath:    filepath.Join(dir, "only-json.run.log"),
		WriteHTML:     false,
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(outChecksums)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 checksum line, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], filepath.Base(outJSON)) {
		t.Fatalf("checksum does not point to json file: %s", lines[0])
	}
}

func TestDefaultArtifactPaths(t *testing.T) {
	gotChecksums := DefaultChecksumsPath("out/report.json")
	if gotChecksums != filepath.Join("out", "checksums.sha256") {
		t.Fatalf("unexpected checksums default path: %s", gotChecksums)
	}
	gotLog := DefaultRunLogPath("out/report.json")
	if gotLog != filepath.Join("out", "security-gate.run.log") {
		t.Fatalf("unexpected run log default path: %s", gotLog)
	}
}
