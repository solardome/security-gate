package securitygate

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/solardome/security-gate/internal/ingest/checkmarx"
	"github.com/solardome/security-gate/internal/ingest/sarif"
	"github.com/solardome/security-gate/internal/ingest/snyk"
	"github.com/solardome/security-gate/internal/ingest/sonar"
	"github.com/solardome/security-gate/internal/ingest/trivy"
)

func parseScan(path string, payload []byte, scannerName, scannerVersion string) ([]AdapterFinding, string, error) {
	format, err := detectScanFormat(payload)
	if err != nil {
		return nil, "unknown", err
	}
	switch format {
	case "trivy":
		reportDetectedAt := trivy.ReportDetectedAt(payload)
		findings, err := trivy.Parse(path, payload, scannerName, scannerVersion)
		if err != nil {
			return nil, "", err
		}
		return fromTrivyFindings(findings), reportDetectedAt, nil
	case "sarif":
		reportDetectedAt := sarif.ReportDetectedAt(payload)
		// Keep scanner identity adapter-native for non-Trivy formats.
		findings, err := sarif.Parse(path, payload, "", "")
		if err != nil {
			return nil, "", err
		}
		return fromSARIFFindings(findings), reportDetectedAt, nil
	case "snyk":
		reportDetectedAt := snyk.ReportDetectedAt(payload)
		findings, err := snyk.Parse(path, payload, "", "")
		if err != nil {
			return nil, "", err
		}
		return fromSnykFindings(findings), reportDetectedAt, nil
	case "checkmarx":
		reportDetectedAt := checkmarx.ReportDetectedAt(payload)
		findings, err := checkmarx.Parse(path, payload, "", "")
		if err != nil {
			return nil, "", err
		}
		return fromCheckmarxFindings(findings), reportDetectedAt, nil
	case "sonar":
		reportDetectedAt := sonar.ReportDetectedAt(payload)
		findings, err := sonar.Parse(path, payload, "", "")
		if err != nil {
			return nil, "", err
		}
		return fromSonarFindings(findings), reportDetectedAt, nil
	default:
		return nil, "unknown", fmt.Errorf("unsupported scan format %q", format)
	}
}

func detectScanFormat(payload []byte) (string, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(payload, &root); err != nil {
		return "", fmt.Errorf("parse scan json: %w", err)
	}
	// Deterministic format precedence for ambiguous payloads:
	// SARIF -> Trivy -> Checkmarx -> Snyk -> Sonar.
	// This tie-break order is fixed to keep output stable across runs.
	if _, ok := root["runs"]; ok {
		// Strict SARIF version validation is enforced inside the adapter.
		return "sarif", nil
	}
	if _, ok := root["Results"]; ok {
		return "trivy", nil
	}
	if _, ok := root["scanResults"]; ok {
		if looksLikeCheckmarx(root) {
			return "checkmarx", nil
		}
		return "", errors.New("unsupported scan format: scanResults key present but payload does not match expected Checkmarx JSON v2 envelope")
	}
	if _, ok := root["vulnerabilities"]; ok {
		if looksLikeSnyk(root) {
			return "snyk", nil
		}
		return "", errors.New("unsupported scan format: vulnerabilities key present but payload does not match expected Snyk JSON envelope")
	}
	if _, ok := root["issues"]; ok {
		if looksLikeSonar(root) {
			return "sonar", nil
		}
		return "", errors.New("unsupported scan format: issues key present but payload does not match expected Sonar Generic Issues envelope")
	}
	return "", errors.New("unsupported scan format: expected Trivy JSON, SARIF 2.1.0, Snyk JSON, Checkmarx JSON v2, or Sonar Generic Issues JSON")
}

func looksLikeSnyk(root map[string]json.RawMessage) bool {
	return hasTopLevelArray(root, "vulnerabilities")
}

func looksLikeCheckmarx(root map[string]json.RawMessage) bool {
	return hasTopLevelArray(root, "scanResults")
}

func looksLikeSonar(root map[string]json.RawMessage) bool {
	return hasTopLevelArray(root, "issues")
}

func hasTopLevelArray(root map[string]json.RawMessage, key string) bool {
	raw, ok := root[key]
	if !ok {
		return false
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return false
	}
	return true
}

func fromTrivyFindings(findings []trivy.Finding) []AdapterFinding {
	out := make([]AdapterFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, AdapterFinding{
			ScannerName:       f.ScannerName,
			ScannerVersion:    f.ScannerVersion,
			ArtifactTargetRef: f.ArtifactTargetRef,
			Component:         f.Component,
			Location:          f.Location,
			DomainID:          f.DomainID,
			Category:          f.Category,
			CVE:               f.CVE,
			CWE:               f.CWE,
			Severity:          f.Severity,
			Confidence:        f.Confidence,
			ExploitMaturity:   f.ExploitMaturity,
			Reachability:      f.Reachability,
			Title:             f.Title,
			Description:       f.Description,
			References:        f.References,
			DetectedAt:        f.DetectedAt,
			SourceFile:        f.SourceFile,
			SourceIndex:       f.SourceIndex,
			RawID:             f.RawID,
		})
	}
	return out
}

func fromSARIFFindings(findings []sarif.Finding) []AdapterFinding {
	out := make([]AdapterFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, AdapterFinding{
			ScannerName:       f.ScannerName,
			ScannerVersion:    f.ScannerVersion,
			ArtifactTargetRef: f.ArtifactTargetRef,
			Component:         f.Component,
			Location:          f.Location,
			DomainID:          f.DomainID,
			Category:          f.Category,
			CVE:               f.CVE,
			CWE:               f.CWE,
			Severity:          f.Severity,
			Confidence:        f.Confidence,
			ExploitMaturity:   f.ExploitMaturity,
			Reachability:      f.Reachability,
			Title:             f.Title,
			Description:       f.Description,
			References:        f.References,
			DetectedAt:        f.DetectedAt,
			SourceFile:        f.SourceFile,
			SourceIndex:       f.SourceIndex,
			RawID:             f.RawID,
		})
	}
	return out
}

func fromSnykFindings(findings []snyk.Finding) []AdapterFinding {
	out := make([]AdapterFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, AdapterFinding{
			ScannerName:       f.ScannerName,
			ScannerVersion:    f.ScannerVersion,
			ArtifactTargetRef: f.ArtifactTargetRef,
			Component:         f.Component,
			Location:          f.Location,
			DomainID:          f.DomainID,
			Category:          f.Category,
			CVE:               f.CVE,
			CWE:               f.CWE,
			Severity:          f.Severity,
			Confidence:        f.Confidence,
			ExploitMaturity:   f.ExploitMaturity,
			Reachability:      f.Reachability,
			Title:             f.Title,
			Description:       f.Description,
			References:        f.References,
			DetectedAt:        f.DetectedAt,
			SourceFile:        f.SourceFile,
			SourceIndex:       f.SourceIndex,
			RawID:             f.RawID,
		})
	}
	return out
}

func fromCheckmarxFindings(findings []checkmarx.Finding) []AdapterFinding {
	out := make([]AdapterFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, AdapterFinding{
			ScannerName:       f.ScannerName,
			ScannerVersion:    f.ScannerVersion,
			ArtifactTargetRef: f.ArtifactTargetRef,
			Component:         f.Component,
			Location:          f.Location,
			DomainID:          f.DomainID,
			Category:          f.Category,
			CVE:               f.CVE,
			CWE:               f.CWE,
			Severity:          f.Severity,
			Confidence:        f.Confidence,
			ExploitMaturity:   f.ExploitMaturity,
			Reachability:      f.Reachability,
			Title:             f.Title,
			Description:       f.Description,
			References:        f.References,
			DetectedAt:        f.DetectedAt,
			SourceFile:        f.SourceFile,
			SourceIndex:       f.SourceIndex,
			RawID:             f.RawID,
		})
	}
	return out
}

func fromSonarFindings(findings []sonar.Finding) []AdapterFinding {
	out := make([]AdapterFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, AdapterFinding{
			ScannerName:       f.ScannerName,
			ScannerVersion:    f.ScannerVersion,
			ArtifactTargetRef: f.ArtifactTargetRef,
			Component:         f.Component,
			Location:          f.Location,
			DomainID:          f.DomainID,
			Category:          f.Category,
			CVE:               f.CVE,
			CWE:               f.CWE,
			Severity:          f.Severity,
			Confidence:        f.Confidence,
			ExploitMaturity:   f.ExploitMaturity,
			Reachability:      f.Reachability,
			Title:             f.Title,
			Description:       f.Description,
			References:        f.References,
			DetectedAt:        f.DetectedAt,
			SourceFile:        f.SourceFile,
			SourceIndex:       f.SourceIndex,
			RawID:             f.RawID,
		})
	}
	return out
}
