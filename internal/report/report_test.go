package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDefaultPathsUseReportDirectory(t *testing.T) {
	if got := DefaultChecksumsPath(""); got != "checksums.sha256" {
		t.Fatalf("DefaultChecksumsPath(\"\") = %q, want %q", got, "checksums.sha256")
	}
	if got := DefaultRunLogPath(""); got != "security-gate.run.log" {
		t.Fatalf("DefaultRunLogPath(\"\") = %q, want %q", got, "security-gate.run.log")
	}
	if got := DefaultChecksumsPath("out/report.json"); got != filepath.Join("out", "checksums.sha256") {
		t.Fatalf("DefaultChecksumsPath() = %q", got)
	}
	if got := DefaultRunLogPath("out/report.json"); got != filepath.Join("out", "security-gate.run.log") {
		t.Fatalf("DefaultRunLogPath() = %q", got)
	}
}

func TestWriteChecksumsSortsArtifactsAndSkipsBlankPaths(t *testing.T) {
	dir := t.TempDir()
	pathB := filepath.Join(dir, "b.txt")
	pathA := filepath.Join(dir, "a.txt")
	checksumsPath := filepath.Join(dir, "out", "checksums.sha256")

	mustWriteFile(t, pathB, []byte("beta"))
	mustWriteFile(t, pathA, []byte("alpha"))

	if err := WriteChecksums(checksumsPath, []string{pathB, "", "   ", pathA}); err != nil {
		t.Fatalf("WriteChecksums() error = %v", err)
	}

	got := string(mustReadFile(t, checksumsPath))
	want := checksumLine("alpha", "a.txt") + "\n" + checksumLine("beta", "b.txt") + "\n"
	if got != want {
		t.Fatalf("WriteChecksums() content = %q, want %q", got, want)
	}
}

func TestWriteJSONCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "report.json")
	value := struct {
		Decision string `json:"decision"`
		Score    int    `json:"score"`
	}{
		Decision: "WARN",
		Score:    45,
	}

	if err := WriteJSON(path, value); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}

	var got struct {
		Decision string `json:"decision"`
		Score    int    `json:"score"`
	}
	if err := json.Unmarshal(mustReadFile(t, path), &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !reflect.DeepEqual(got, value) {
		t.Fatalf("WriteJSON() wrote %+v, want %+v", got, value)
	}
}

func TestAuditLoggerWritesJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	defer logger.Close()

	logger.Info("scan.started", map[string]any{"count": 1})
	logger.Warn("scan.failed", map[string]any{"reason": "invalid"})
	logger.Close()

	lines := strings.Split(strings.TrimSpace(string(mustReadFile(t, path))), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit log lines = %d, want 2", len(lines))
	}

	var infoEvent AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &infoEvent); err != nil {
		t.Fatalf("json.Unmarshal(info) error = %v", err)
	}
	if infoEvent.Level != "INFO" || infoEvent.Event != "scan.started" {
		t.Fatalf("info event = %+v", infoEvent)
	}
	if infoEvent.Fields["count"] != float64(1) {
		t.Fatalf("info fields = %#v, want count=1", infoEvent.Fields)
	}
	if _, err := time.Parse(time.RFC3339Nano, infoEvent.Timestamp); err != nil {
		t.Fatalf("info timestamp %q parse error = %v", infoEvent.Timestamp, err)
	}

	var warnEvent AuditEvent
	if err := json.Unmarshal([]byte(lines[1]), &warnEvent); err != nil {
		t.Fatalf("json.Unmarshal(warn) error = %v", err)
	}
	if warnEvent.Level != "WARN" || warnEvent.Event != "scan.failed" {
		t.Fatalf("warn event = %+v", warnEvent)
	}
	if warnEvent.Fields["reason"] != "invalid" {
		t.Fatalf("warn fields = %#v, want reason=invalid", warnEvent.Fields)
	}
}

func checksumLine(content, base string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:]) + "  " + base
}

func mustWriteFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", path, err)
	}
	return b
}
