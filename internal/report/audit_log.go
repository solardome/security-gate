package report

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// NewAuditLogger opens path in append mode and returns a JSON slog logger plus
// the underlying file closer used to flush and close the log file.
func NewAuditLogger(path string) (*slog.Logger, io.Closer, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil && dir != "." {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- log path is a user-supplied CLI argument, intentional
	if err != nil {
		return nil, nil, err
	}
	return slog.New(slog.NewJSONHandler(f, nil)), f, nil
}
