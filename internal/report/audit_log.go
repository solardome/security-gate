package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type AuditLogger struct {
	file *os.File
	enc  *json.Encoder
}

type AuditEvent struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Event     string                 `json:"event"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

func NewAuditLogger(path string) (*AuditLogger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &AuditLogger{
		file: f,
		enc:  json.NewEncoder(f),
	}, nil
}

func (l *AuditLogger) Close() {
	if l == nil || l.file == nil {
		return
	}
	_ = l.file.Close()
}

func (l *AuditLogger) Info(event string, fields map[string]interface{}) {
	l.log("INFO", event, fields)
}

func (l *AuditLogger) Warn(event string, fields map[string]interface{}) {
	l.log("WARN", event, fields)
}

func (l *AuditLogger) log(level, event string, fields map[string]interface{}) {
	if l == nil || l.enc == nil {
		return
	}
	_ = l.enc.Encode(AuditEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Event:     event,
		Fields:    fields,
	})
}
