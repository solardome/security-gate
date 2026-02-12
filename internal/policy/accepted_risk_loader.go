package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const maxAcceptedRiskBytes = 1 * 1024 * 1024

type guardrailError struct {
	code    string
	message string
}

func (e guardrailError) Error() string {
	return e.message
}

func (e guardrailError) ErrorCode() string {
	return e.code
}

// LoadAcceptedRisks reads the repo-local accepted risk file and returns the parsed
// records plus the SHA-256 hash of the file contents. The loader enforces the
// schema described in docs/md/governance-accepted-risk.md and reports any fatal
// validation failures so the CLI can treat them as fatal errors.
func LoadAcceptedRisks(path string) ([]AcceptedRisk, string, error) {
	if stat, err := os.Stat(path); err == nil && stat.Size() > maxAcceptedRiskBytes {
		return nil, "", guardrailError{
			code:    "ACCEPTED_RISK_TOO_LARGE",
			message: fmt.Sprintf("accepted risk file too large: %d bytes (max %d)", stat.Size(), maxAcceptedRiskBytes),
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read accepted risk file %s: %w", path, err)
	}

	hashed := sha256.Sum256(raw)

	risks, err := decodeAcceptedRiskData(raw)
	if err != nil {
		return nil, "", fmt.Errorf("parse accepted risk file %s: %w", path, err)
	}

	for idx := range risks {
		if err := validateAcceptedRiskSchema(&risks[idx]); err != nil {
			return nil, "", fmt.Errorf("accepted risk validation failed for record %d: %w", idx, err)
		}
	}

	return risks, hex.EncodeToString(hashed[:]), nil
}

func decodeAcceptedRiskData(raw []byte) ([]AcceptedRisk, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return []AcceptedRisk{}, nil
	}

	var risks []AcceptedRisk
	if err := json.Unmarshal(raw, &risks); err == nil {
		return risks, nil
	}

	return nil, fmt.Errorf("accepted risk file must be valid JSON")
}

func validateAcceptedRiskSchema(ar *AcceptedRisk) error {
	if strings.TrimSpace(ar.RiskID) == "" {
		return fmt.Errorf("missing risk_id")
	}
	if strings.TrimSpace(ar.Title) == "" {
		return fmt.Errorf("risk_id=%s: missing title", ar.RiskID)
	}
	if strings.TrimSpace(ar.Rationale) == "" {
		return fmt.Errorf("risk_id=%s: missing rationale", ar.RiskID)
	}
	if strings.TrimSpace(ar.Owner) == "" {
		return fmt.Errorf("risk_id=%s: missing owner", ar.RiskID)
	}
	if strings.TrimSpace(ar.Ticket) == "" {
		return fmt.Errorf("risk_id=%s: missing ticket", ar.RiskID)
	}
	if len(ar.StageScope) == 0 {
		return fmt.Errorf("risk_id=%s: stage_scope must not be empty", ar.RiskID)
	}
	for _, stage := range ar.StageScope {
		if !isCanonicalStage(stage) {
			return fmt.Errorf("risk_id=%s: invalid stage_scope value %s", ar.RiskID, stage)
		}
	}
	if len(ar.EnvironmentScope) == 0 {
		return fmt.Errorf("risk_id=%s: environment_scope must not be empty", ar.RiskID)
	}
	if strings.TrimSpace(ar.FindingSelector.Fingerprint) == "" {
		return fmt.Errorf("risk_id=%s: finding_selector.fingerprint is required", ar.RiskID)
	}
	if err := validateEffects(ar.Effects, ar.RiskID); err != nil {
		return err
	}
	if len(ar.Approvals) == 0 {
		return fmt.Errorf("risk_id=%s: at least one approval is required", ar.RiskID)
	}
	for i, approval := range ar.Approvals {
		if strings.TrimSpace(approval.Name) == "" {
			return fmt.Errorf("risk_id=%s: approval[%d] missing name", ar.RiskID, i)
		}
		if strings.TrimSpace(approval.Role) == "" {
			return fmt.Errorf("risk_id=%s: approval[%d] missing role", ar.RiskID, i)
		}
		if strings.TrimSpace(approval.ApprovedAt) == "" {
			return fmt.Errorf("risk_id=%s: approval[%d] missing approved_at", ar.RiskID, i)
		}
		if _, err := time.Parse(time.RFC3339, approval.ApprovedAt); err != nil {
			return fmt.Errorf("risk_id=%s: approval[%d] approved_at invalid: %w", ar.RiskID, i, err)
		}
	}
	if strings.TrimSpace(ar.CreatedAt) == "" {
		return fmt.Errorf("risk_id=%s: missing created_at", ar.RiskID)
	}
	if strings.TrimSpace(ar.UpdatedAt) == "" {
		return fmt.Errorf("risk_id=%s: missing updated_at", ar.RiskID)
	}
	if strings.TrimSpace(ar.ExpiresAt) == "" {
		return fmt.Errorf("risk_id=%s: missing expires_at", ar.RiskID)
	}
	if _, err := time.Parse(time.RFC3339, ar.CreatedAt); err != nil {
		return fmt.Errorf("risk_id=%s: created_at invalid: %w", ar.RiskID, err)
	}
	if _, err := time.Parse(time.RFC3339, ar.UpdatedAt); err != nil {
		return fmt.Errorf("risk_id=%s: updated_at invalid: %w", ar.RiskID, err)
	}
	if _, err := time.Parse(time.RFC3339, ar.ExpiresAt); err != nil {
		return fmt.Errorf("risk_id=%s: expires_at invalid: %w", ar.RiskID, err)
	}
	status := strings.ToLower(strings.TrimSpace(ar.Status))
	if status != "active" && status != "expired" && status != "revoked" {
		return fmt.Errorf("risk_id=%s: invalid status %s", ar.RiskID, ar.Status)
	}
	return nil
}

func validateEffects(effects []string, riskID string) error {
	for i, effect := range effects {
		normalized := strings.TrimSpace(effect)
		if normalized == "" {
			continue
		}
		if normalized != "suppress_from_scoring" {
			return fmt.Errorf("risk_id=%s: unsupported effect[%d] %s", riskID, i, normalized)
		}
	}
	return nil
}

func isCanonicalStage(stage Stage) bool {
	switch stage {
	case StagePR, StageMain, StageRelease, StageProd:
		return true
	}
	return false
}
