package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAcceptedRisksValidFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "accepted-risks.json")
	payload := `[
  {
    "risk_id": "AR-1",
    "title": "Temp risk",
    "rationale": "Justified",
    "owner": "platform-security",
    "ticket": "SEC-1",
    "stage_scope": ["prod"],
    "environment_scope": ["prod"],
    "finding_selector": {"fingerprint": "fp-1"},
    "effects": ["suppress_from_scoring"],
    "allow_warn_in_prod": true,
    "approvals": [{"name": "Sec Lead", "role": "security", "approved_at": "2026-02-01T00:00:00Z"}],
    "created_at": "2026-02-01T00:00:00Z",
    "updated_at": "2026-02-01T00:00:00Z",
    "expires_at": "2026-03-01T00:00:00Z",
    "status": "active"
  }
]`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	risks, hash, err := LoadAcceptedRisks(path)
	if err != nil {
		t.Fatalf("load accepted risks: %v", err)
	}
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}
	if hash == "" {
		t.Fatalf("expected non-empty hash")
	}
}

func TestLoadAcceptedRisksInvalidSchema(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "accepted-risks.json")
	payload := `[
  {
    "risk_id": "AR-2",
    "title": "Broken",
    "rationale": "Missing fingerprint",
    "owner": "platform-security",
    "ticket": "SEC-2",
    "stage_scope": ["prod"],
    "environment_scope": ["prod"],
    "finding_selector": {},
    "effects": [],
    "allow_warn_in_prod": false,
    "approvals": [{"name": "Sec Lead", "role": "security", "approved_at": "2026-02-01T00:00:00Z"}],
    "created_at": "2026-02-01T00:00:00Z",
    "updated_at": "2026-02-01T00:00:00Z",
    "expires_at": "2026-03-01T00:00:00Z",
    "status": "active"
  }
]`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, _, err := LoadAcceptedRisks(path)
	if err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestLoadAcceptedRisksTooLarge(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "accepted-risks-large.json")
	oversized := strings.Repeat("x", maxAcceptedRiskBytes+1)
	if err := os.WriteFile(path, []byte(oversized), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, _, err := LoadAcceptedRisks(path)
	if err == nil {
		t.Fatalf("expected size error")
	}

	type codeCarrier interface {
		ErrorCode() string
	}
	var coded codeCarrier
	if !errors.As(err, &coded) {
		t.Fatalf("expected coded guardrail error")
	}
	if coded.ErrorCode() != "ACCEPTED_RISK_TOO_LARGE" {
		t.Fatalf("expected ACCEPTED_RISK_TOO_LARGE, got %s", coded.ErrorCode())
	}
}
