package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
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
	logger, closer, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	defer func() {
		_ = closer.Close()
	}()

	logger.Info("scan.started", "count", 1)
	logger.Warn("scan.failed", "reason", "invalid")
	if err := closer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(mustReadFile(t, path))), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit log lines = %d, want 2", len(lines))
	}

	var infoEvent map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &infoEvent); err != nil {
		t.Fatalf("json.Unmarshal(info) error = %v", err)
	}
	if infoEvent[slog.LevelKey] != "INFO" || infoEvent[slog.MessageKey] != "scan.started" {
		t.Fatalf("info event = %+v", infoEvent)
	}
	if infoEvent["count"] != float64(1) {
		t.Fatalf("info fields = %#v, want count=1", infoEvent)
	}
	timestamp, ok := infoEvent[slog.TimeKey].(string)
	if !ok {
		t.Fatalf("info time = %#v, want string", infoEvent[slog.TimeKey])
	}
	if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
		t.Fatalf("info timestamp %q parse error = %v", timestamp, err)
	}

	var warnEvent map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &warnEvent); err != nil {
		t.Fatalf("json.Unmarshal(warn) error = %v", err)
	}
	if warnEvent[slog.LevelKey] != "WARN" || warnEvent[slog.MessageKey] != "scan.failed" {
		t.Fatalf("warn event = %+v", warnEvent)
	}
	if warnEvent["reason"] != "invalid" {
		t.Fatalf("warn fields = %#v, want reason=invalid", warnEvent)
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
