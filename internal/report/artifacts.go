package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func DefaultChecksumsPath(outJSONPath string) string {
	if strings.TrimSpace(outJSONPath) == "" {
		outJSONPath = "report.json"
	}
	return filepath.Join(filepath.Dir(outJSONPath), "checksums.sha256")
}

func DefaultRunLogPath(outJSONPath string) string {
	if strings.TrimSpace(outJSONPath) == "" {
		outJSONPath = "report.json"
	}
	return filepath.Join(filepath.Dir(outJSONPath), "security-gate.run.log")
}

func WriteChecksums(checksumsPath string, artifactPaths []string) error {
	clean := make([]string, 0, len(artifactPaths))
	for _, p := range artifactPaths {
		if strings.TrimSpace(p) != "" {
			clean = append(clean, p)
		}
	}
	sort.Strings(clean)

	lines := make([]string, 0, len(clean))
	for _, p := range clean {
		sum, err := fileSHA256(p)
		if err != nil {
			return fmt.Errorf("checksum read failed for %s: %w", p, err)
		}
		lines = append(lines, fmt.Sprintf("%s  %s", sum, filepath.Base(p)))
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}

	dir := filepath.Dir(checksumsPath)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	return os.WriteFile(checksumsPath, []byte(content), 0o644)
}

func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
