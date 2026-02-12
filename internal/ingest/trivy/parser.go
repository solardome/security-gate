package trivy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/solardome/security-gate/internal/domain"
)

const canonicalScannerName = "trivy"

const (
	maxScannerInputBytes      = 50 * 1024 * 1024
	maxTotalScannerInputBytes = 100 * 1024 * 1024
	maxFindingsPerScan        = 10000
)

// Ingest reads Trivy JSON files or stdin, normalizes findings, and records trace events.
func Ingest(ctx context.Context, stage Stage, paths []string) (*IngestResult, error) {
	if len(paths) == 0 {
		return nil, FatalError{Stage: stage, Err: errors.New("no input paths provided")}
	}

	result := &IngestResult{
		Findings:    make([]CanonicalFinding, 0, 16),
		Trace:       make([]TraceEvent, 0, 8),
		InputHashes: map[string]string{},
	}
	totalBytes := 0

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		payload, err := readInput(path)
		if err != nil {
			return nil, wrapFatal(stage, err, result.Trace)
		}
		totalBytes += len(payload.Data)
		if totalBytes > maxTotalScannerInputBytes {
			return nil, wrapFatal(stage, GuardrailError{
				Code:    "SCANNER_TOTAL_TOO_LARGE",
				Message: fmt.Sprintf("total scanner input too large: %d bytes (max %d)", totalBytes, maxTotalScannerInputBytes),
			}, result.Trace)
		}

		report, err := parseReport(payload.Data)
		if err != nil {
			result.Trace = append(result.Trace, traceEvent("ingest.parse_error", fmt.Sprintf("failed to parse %s", payload.Path), map[string]any{"error": err.Error()}))
			return nil, wrapFatal(stage, err, result.Trace)
		}

		findings, traceEvents, err := normalizeReport(report, payload)
		result.Trace = append(result.Trace, traceEvents...)
		if err != nil {
			return nil, wrapFatal(stage, err, result.Trace)
		}
		if len(findings) > maxFindingsPerScan {
			return nil, wrapFatal(stage, GuardrailError{
				Code:    "FINDING_COUNT_EXCEEDED",
				Message: fmt.Sprintf("finding count exceeded for %s: %d (max %d)", payload.Path, len(findings), maxFindingsPerScan),
			}, result.Trace)
		}

		result.Findings = append(result.Findings, findings...)
		hashKey := payload.Path
		if hashKey == "-" {
			hashKey = "stdin"
		}
		result.InputHashes[hashKey] = payload.Hash
	}

	return result, nil
}

func wrapFatal(stage Stage, err error, trace []TraceEvent) error {
	return FatalError{Stage: stage, Err: err}
}

func readInput(path string) (inputPayload, error) {
	payload := inputPayload{Path: path}
	var reader io.ReadCloser
	if path == "-" {
		reader = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return payload, fmt.Errorf("open input %s: %w", path, err)
		}
		reader = f
	}

	defer func() {
		if path != "-" && reader != nil {
			reader.Close()
		}
	}()

	data, err := io.ReadAll(io.LimitReader(reader, maxScannerInputBytes+1))
	if err != nil {
		return payload, fmt.Errorf("read input %s: %w", path, err)
	}
	if len(data) > maxScannerInputBytes {
		return payload, GuardrailError{
			Code:    "SCANNER_INPUT_TOO_LARGE",
			Message: fmt.Sprintf("scanner input %s too large: %d bytes (max %d)", path, len(data), maxScannerInputBytes),
		}
	}

	hash := sha256.Sum256(data)
	payload.Data = data
	payload.Hash = hex.EncodeToString(hash[:])
	return payload, nil
}

func parseReport(data []byte) (*trivyReport, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("unmarshal trivy report: %w", err)
	}
	return &report, nil
}

func normalizeReport(report *trivyReport, payload inputPayload) ([]CanonicalFinding, []TraceEvent, error) {
	trace := make([]TraceEvent, 0, 8)
	scanTimestamp, timestampSource, tsEvents := deriveScanTimestamp(report.Metadata)
	trace = append(trace, tsEvents...)

	sourceVersion, versionEvents := deriveSourceVersion(report)
	trace = append(trace, versionEvents...)

	ctx := normalizationContext{
		payload:         payload,
		scanTimestamp:   scanTimestamp,
		timestampSource: timestampSource,
		sourceVersion:   sourceVersion,
	}

	var findings []CanonicalFinding
	for _, result := range report.Results {
		normalized, err := normalizeResult(result, ctx, &trace)
		if err != nil {
			return nil, trace, err
		}
		findings = append(findings, normalized...)
	}

	return findings, trace, nil
}

type normalizationContext struct {
	payload         inputPayload
	scanTimestamp   time.Time
	timestampSource string
	sourceVersion   string
}

func deriveScanTimestamp(metadata trivyMetadata) (time.Time, string, []TraceEvent) {
	trace := make([]TraceEvent, 0, 2)
	candidate := firstNonEmpty(metadata.Timestamp, metadata.ScanTime, metadata.LastScannedAt, metadata.ScanTimestamp)
	if candidate == "" {
		event := traceEvent("ingest.scan_timestamp_missing", "scanner timestamp missing; substituting ingest time", nil)
		trace = append(trace, event)
		return time.Now().UTC(), "ingest", trace
	}

	parsed, err := time.Parse(time.RFC3339, candidate)
	if err != nil {
		event := traceEvent("ingest.scan_timestamp_invalid", "scanner timestamp invalid; substituting ingest time", map[string]any{"timestamp": candidate, "error": err.Error()})
		trace = append(trace, event)
		return time.Now().UTC(), "ingest", trace
	}

	return parsed.UTC(), "scanner", trace
}

func deriveSourceVersion(report *trivyReport) (string, []TraceEvent) {
	trace := make([]TraceEvent, 0, 1)
	version := firstNonEmpty(report.Scanner.Version, report.Metadata.Scanner.Version, report.Metadata.ScannerVersion)
	if version == "" {
		trace = append(trace, traceEvent("context.source_version_missing", "scanner version missing, using sentinel", nil))
		return "unknown", trace
	}
	return version, trace
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func normalizeResult(result trivyResult, ctx normalizationContext, trace *[]TraceEvent) ([]CanonicalFinding, error) {
	var normalized []CanonicalFinding
	if len(result.Vulnerabilities) > 0 {
		for _, vuln := range result.Vulnerabilities {
			finding, err := buildVulnerabilityFinding(vuln, result, ctx)
			if err != nil {
				*trace = append(*trace, traceEvent("ingest.normalization_error", err.Error(), map[string]any{"target": result.Target}))
				return nil, err
			}
			normalized = append(normalized, finding)
		}
	}
	if len(result.Misconfigurations) > 0 {
		for _, mis := range result.Misconfigurations {
			finding, err := buildMisconfigurationFinding(mis, result, ctx)
			if err != nil {
				*trace = append(*trace, traceEvent("ingest.normalization_error", err.Error(), map[string]any{"target": result.Target}))
				return nil, err
			}
			normalized = append(normalized, finding)
		}
	}
	return normalized, nil
}

func buildVulnerabilityFinding(vuln trivyVulnerability, result trivyResult, ctx normalizationContext) (CanonicalFinding, error) {
	locationPath := canonicalLocation(result.Target, vuln.PkgName, vuln.InstalledVersion)
	if locationPath == "" {
		return CanonicalFinding{}, errors.New("required location path missing")
	}

	title := strings.TrimSpace(vuln.Title)
	if title == "" {
		title = vuln.VulnerabilityID
	}

	description := strings.TrimSpace(vuln.Description)
	if description == "" {
		description = title
	}

	severity := canonicalSeverity(vuln.Severity)
	if severity == "" {
		return CanonicalFinding{}, fmt.Errorf("severity missing for %s", vuln.VulnerabilityID)
	}

	evidenceRef := fmt.Sprintf("%s:%s", locationPath, vuln.VulnerabilityID)

	fixAvailable := "false"
	if strings.TrimSpace(vuln.FixedVersion) != "" {
		fixAvailable = "true"
	}

	cvss := pickCVSS(vuln.CVSS)

	canonical := CanonicalFinding{
		FindingID:       vuln.VulnerabilityID,
		Domain:          string(domain.DomainVulnerability),
		Severity:        severity,
		Title:           title,
		Description:     description,
		SourceScanner:   canonicalScannerName,
		SourceVersion:   ctx.sourceVersion,
		InputSHA256:     ctx.payload.Hash,
		ScanTimestamp:   ctx.scanTimestamp,
		TimestampSource: ctx.timestampSource,
		Location: Location{
			Path:    result.Target,
			Package: vuln.PkgName,
			File:    result.Target,
		},
		EvidenceRef:     evidenceRef,
		CVE:             vuln.VulnerabilityID,
		FixAvailable:    fixAvailable,
		FixVersion:      vuln.FixedVersion,
		RemediationHint: vuln.PrimaryURL,
	}
	if cvss != nil {
		canonical.CVSSv3 = cvss
	}

	if err := assignFingerprint(&canonical); err != nil {
		return CanonicalFinding{}, err
	}
	return canonical, nil
}

func buildMisconfigurationFinding(mis trivyMisconfiguration, result trivyResult, ctx normalizationContext) (CanonicalFinding, error) {
	locationPath := canonicalLocation(result.Target, mis.Target, "")
	if locationPath == "" {
		return CanonicalFinding{}, errors.New("required location path missing for misconfiguration")
	}

	title := strings.TrimSpace(mis.Title)
	if title == "" {
		title = mis.ID
	}

	description := strings.TrimSpace(mis.Description)
	if description == "" {
		description = mis.Message
	}
	if description == "" {
		description = title
	}

	severity := canonicalSeverity(mis.Severity)
	if severity == "" {
		return CanonicalFinding{}, fmt.Errorf("severity missing for misconfiguration %s", mis.ID)
	}

	evidenceRef := fmt.Sprintf("%s:%s", locationPath, mis.ID)

	canonical := CanonicalFinding{
		FindingID:       mis.ID,
		Domain:          string(domain.DomainConfig),
		Severity:        severity,
		Title:           title,
		Description:     description,
		SourceScanner:   canonicalScannerName,
		SourceVersion:   ctx.sourceVersion,
		InputSHA256:     ctx.payload.Hash,
		ScanTimestamp:   ctx.scanTimestamp,
		TimestampSource: ctx.timestampSource,
		Location: Location{
			Path: result.Target,
			File: result.Target,
		},
		EvidenceRef:     evidenceRef,
		RemediationHint: mis.Message,
	}
	if err := assignFingerprint(&canonical); err != nil {
		return CanonicalFinding{}, err
	}
	return canonical, nil
}

func canonicalSeverity(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "UNKNOWN", "INFO":
		return "UNKNOWN"
	default:
		return "UNKNOWN"
	}
}

func pickCVSS(list []trivyCVSS) *float64 {
	for _, entry := range list {
		if strings.HasPrefix(strings.TrimSpace(entry.Version), "3") {
			return floatPtr(entry.BaseScore)
		}
	}
	if len(list) > 0 {
		return floatPtr(list[0].BaseScore)
	}
	return nil
}

func floatPtr(value float64) *float64 {
	return &value
}

func traceEvent(typ, message string, details map[string]any) TraceEvent {
	return TraceEvent{
		Timestamp: time.Now().UTC(),
		Type:      typ,
		Message:   message,
		Details:   details,
	}
}

type inputPayload struct {
	Path string
	Data []byte
	Hash string
}
