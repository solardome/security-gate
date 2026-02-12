package trivy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// FingerprintParts contains the canonical components used to build a finding fingerprint.
type FingerprintParts struct {
	Domain        string
	Location      string
	EvidenceRef   string
	Title         string
	Severity      string
	SourceScanner string
	SourceVersion string
	CVE           string
	InputSHA256   string
}

// BuildFingerprint produces the deterministic fingerprint for a normalized finding.
func BuildFingerprint(parts FingerprintParts) (string, error) {
	const sep = "|"

	location := strings.ToLower(strings.TrimSpace(parts.Location))
	if location == "" {
		return "", errors.New("fingerprint requires a location value")
	}

	values := []string{
		strings.ToLower(strings.TrimSpace(parts.Domain)),
		location,
		strings.ToLower(strings.TrimSpace(parts.EvidenceRef)),
		strings.ToLower(strings.TrimSpace(parts.Title)),
		strings.ToLower(strings.TrimSpace(parts.Severity)),
		strings.ToLower(strings.TrimSpace(parts.SourceScanner)),
		strings.ToLower(strings.TrimSpace(parts.SourceVersion)),
		strings.ToLower(strings.TrimSpace(parts.CVE)),
		strings.ToLower(strings.TrimSpace(parts.InputSHA256)),
	}

	seed := strings.Join(values, sep)
	hash := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(hash[:]), nil
}

func canonicalLocation(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func assignFingerprint(finding *CanonicalFinding) error {
	path := canonicalLocation(finding.Location.Path, finding.Location.Target, finding.Location.Package)
	if path == "" {
		return errors.New("unable to derive fingerprint without location")
	}

	fingerprint, err := BuildFingerprint(FingerprintParts{
		Domain:        finding.Domain,
		Location:      path,
		EvidenceRef:   finding.EvidenceRef,
		Title:         finding.Title,
		Severity:      finding.Severity,
		SourceScanner: finding.SourceScanner,
		SourceVersion: finding.SourceVersion,
		CVE:           strings.ToLower(strings.TrimSpace(finding.CVE)),
		InputSHA256:   finding.InputSHA256,
	})
	if err != nil {
		return err
	}
	finding.Fingerprint = fingerprint
	return nil
}
