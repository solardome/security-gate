package policy

import (
	"fmt"
	"strings"

	"github.com/solardome/security-gate/internal/domain"
	"github.com/solardome/security-gate/internal/ingest/trivy"
	"github.com/solardome/security-gate/internal/scoring"
)

func applyProvenanceHardStops(input *EvaluationInput) []trivy.TraceEvent {
	var events []trivy.TraceEvent
	signingStatus := normalizeSigningStatus(input.ScoreResult.TrustSignals.ArtifactSigning.Raw)
	provenanceLevel := parseProvenanceLevel(input.ScoreResult.TrustSignals.ProvenanceLevel.Raw)

	if signingStatus == "invalid" {
		events = append(events, appendProvenanceFinding(input, "PROVENANCE_INVALID_SIGNATURE", "artifact signature invalid"))
	} else if input.Policy.RequiresSignedArtifact && signingStatus != "verified" {
		events = append(events, appendProvenanceFinding(input, "PROVENANCE_UNSIGNED_ARTIFACT", fmt.Sprintf("policy requires signed artifact (status=%s)", signingStatus)))
	}

	if reqLevel := parseLevelRequirement(input.Policy.RequiresProvenanceLevel); reqLevel > 0 && provenanceLevel < reqLevel {
		events = append(events, appendProvenanceFinding(input, "PROVENANCE_INSUFFICIENT_LEVEL", fmt.Sprintf("provenance level %s below required level", input.ScoreResult.TrustSignals.ProvenanceLevel.Raw)))
	}

	return events
}

func appendProvenanceFinding(input *EvaluationInput, token, reason string) trivy.TraceEvent {
	hash := provenanceInputHash(input)
	locationPath := fmt.Sprintf("policy:%s", token)
	canonical := trivy.CanonicalFinding{
		FindingID:       token,
		Domain:          string(domain.DomainProvenance),
		Severity:        string(domain.SeverityCritical),
		Title:           token,
		Description:     reason,
		SourceScanner:   "policy",
		SourceVersion:   input.Policy.PolicyVersion,
		InputSHA256:     hash,
		ScanTimestamp:   input.Now,
		TimestampSource: "ingest",
		Location: trivy.Location{
			Path: locationPath,
			File: "policy",
		},
		EvidenceRef: locationPath,
	}
	fp, err := trivy.BuildFingerprint(trivy.FingerprintParts{
		Domain:        canonical.Domain,
		Location:      canonical.Location.Path,
		EvidenceRef:   canonical.EvidenceRef,
		Title:         canonical.Title,
		Severity:      canonical.Severity,
		SourceScanner: canonical.SourceScanner,
		SourceVersion: canonical.SourceVersion,
		CVE:           canonical.CVE,
		InputSHA256:   canonical.InputSHA256,
	})
	if err == nil {
		canonical.Fingerprint = fp
	}

	sf := scoring.ScoredFinding{
		Finding:        canonical,
		RiskScore:      100,
		BaseScore:      100,
		HardStop:       true,
		HardStopReason: fmt.Sprintf("provenance=%s", token),
	}
	input.ScoreResult.Findings = append(input.ScoreResult.Findings, sf)

	return trivy.TraceEvent{
		Timestamp: input.Now,
		Type:      "provenance.hard_stop",
		Message:   reason,
		Details: map[string]any{
			"token":       token,
			"fingerprint": canonical.Fingerprint,
			"reason":      reason,
		},
	}
}

func provenanceInputHash(input *EvaluationInput) string {
	for _, hash := range input.ScanHashes {
		if strings.TrimSpace(hash) != "" {
			return hash
		}
	}
	if input.PolicyHash != "" {
		return input.PolicyHash
	}
	return "synthetic"
}

func normalizeSigningStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "verified":
		return "verified"
	case "invalid":
		return "invalid"
	case "unsigned":
		return "unsigned"
	default:
		return "unknown"
	}
}

func parseProvenanceLevel(raw string) int {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "level3+", "level3", "l3":
		return 3
	case "level2", "l2":
		return 2
	case "level1", "l1":
		return 1
	default:
		return 0
	}
}

func parseLevelRequirement(raw string) int {
	clean := strings.TrimSpace(raw)
	if strings.HasPrefix(clean, ">=") {
		clean = strings.TrimSpace(strings.TrimPrefix(clean, ">="))
	}
	return parseProvenanceLevel(clean)
}
