package checkmarx

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Finding struct {
	ScannerName       string
	ScannerVersion    string
	ArtifactTargetRef string
	Component         string
	Location          string
	DomainID          string
	Category          string
	CVE               string
	CWE               string
	Severity          string
	Confidence        string
	ExploitMaturity   string
	Reachability      string
	Title             string
	Description       string
	References        []string
	DetectedAt        string
	SourceFile        string
	SourceIndex       int
	RawID             string
}

type report struct {
	ReportType  string       `json:"reportType"`
	GeneratedAt string       `json:"generatedAt"`
	CreatedAt   string       `json:"createdAt"`
	ProjectName string       `json:"projectName"`
	ScanInfo    scanInfo     `json:"scanInfo"`
	ScanResults []scanResult `json:"scanResults"`
}

type scanInfo struct {
	ProjectName string `json:"projectName"`
	CreatedAt   string `json:"createdAt"`
	FinishedAt  string `json:"finishedAt"`
}

type scanResult struct {
	QueryID          interface{}            `json:"queryId"`
	QueryName        string                 `json:"queryName"`
	Severity         string                 `json:"severity"`
	State            string                 `json:"state"`
	Type             string                 `json:"type"`
	Group            string                 `json:"group"`
	SimilarityID     string                 `json:"similarityId"`
	FilePath         string                 `json:"filePath"`
	Path             string                 `json:"path"`
	FileName         string                 `json:"fileName"`
	PackageName      string                 `json:"packageName"`
	Component        string                 `json:"component"`
	DomainID         string                 `json:"domain_id"`
	Category         string                 `json:"category"`
	CVE              string                 `json:"cve"`
	CWE              string                 `json:"cwe"`
	Confidence       string                 `json:"confidence"`
	Reachability     string                 `json:"reachability"`
	ExploitMaturity  string                 `json:"exploitMaturity"`
	Description      string                 `json:"description"`
	References       []string               `json:"references"`
	Reference        string                 `json:"reference"`
	URL              string                 `json:"url"`
	Data             map[string]interface{} `json:"data"`
	Nodes            []node                 `json:"nodes"`
	DetectionDateRaw string                 `json:"detectionDate"`
}

type node struct {
	FileName string `json:"fileName"`
	FilePath string `json:"filePath"`
	Name     string `json:"name"`
}

func Parse(path string, payload []byte, scannerName, scannerVersion string) ([]Finding, error) {
	if err := validateReportEnvelope(payload); err != nil {
		return nil, err
	}
	var r report
	if err := json.Unmarshal(payload, &r); err != nil {
		return nil, fmt.Errorf("parse checkmarx json: %w", err)
	}
	detectedAt := reportDetectedAt(r)
	targetRef := firstNonEmpty(r.ScanInfo.ProjectName, r.ProjectName, "unknown")
	out := make([]Finding, 0, len(r.ScanResults))
	for idx, rs := range r.ScanResults {
		category := resolveCategory(rs)
		domainID := firstNonEmpty(strings.TrimSpace(rs.DomainID))
		if domainID == "" {
			switch category {
			case "secret":
				domainID = "SECRET_GENERIC"
			case "misconfig":
				domainID = "MISCONFIG_GENERIC"
			default:
				domainID = "VULN_GENERIC"
			}
		}
		location := resolveLocation(rs)
		component := resolveComponent(rs)
		title := firstNonEmpty(rs.QueryName, rs.Type, "unknown title")
		description := firstNonEmpty(rs.Description, propertyString(rs.Data, "description", "details"))
		cve := firstNonEmpty(rs.CVE, propertyString(rs.Data, "cve", "cve_id"))
		cwe := firstNonEmpty(rs.CWE, propertyString(rs.Data, "cwe", "cwe_id"))
		findingDetectedAt := normalizeRFC3339(rs.DetectionDateRaw)
		if findingDetectedAt == "unknown" {
			findingDetectedAt = detectedAt
		}
		rawID := firstNonEmpty(
			rs.SimilarityID,
			interfaceToString(rs.QueryID),
			rs.QueryName,
			"checkmarx-"+strconv.Itoa(idx),
		)

		out = append(out, Finding{
			ScannerName:       "checkmarx",
			ScannerVersion:    firstNonEmpty(strings.TrimSpace(scannerVersion), "unknown"),
			ArtifactTargetRef: targetRef,
			Component:         component,
			Location:          location,
			DomainID:          domainID,
			Category:          category,
			CVE:               strings.ToUpper(strings.TrimSpace(cve)),
			CWE:               strings.ToUpper(strings.TrimSpace(cwe)),
			Severity:          normalizeSeverity(rs.Severity),
			Confidence:        resolveConfidence(rs),
			ExploitMaturity:   normalizeExploitMaturity(rs.ExploitMaturity),
			Reachability:      normalizeReachability(rs.Reachability),
			Title:             title,
			Description:       description,
			References:        resolveReferences(rs),
			DetectedAt:        findingDetectedAt,
			SourceFile:        path,
			SourceIndex:       idx,
			RawID:             rawID,
		})
	}
	return out, nil
}

func ReportDetectedAt(payload []byte) string {
	var r report
	if err := json.Unmarshal(payload, &r); err != nil {
		return "unknown"
	}
	return reportDetectedAt(r)
}

func validateReportEnvelope(payload []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(payload, &root); err != nil {
		return fmt.Errorf("parse checkmarx json: %w", err)
	}
	rawScanResults, ok := root["scanResults"]
	if !ok {
		return errors.New("parse checkmarx json: missing top-level scanResults")
	}
	var scanResults []json.RawMessage
	if err := json.Unmarshal(rawScanResults, &scanResults); err != nil {
		return errors.New("parse checkmarx json: scanResults must be an array")
	}
	if rawReportType, ok := root["reportType"]; ok {
		var reportType string
		if err := json.Unmarshal(rawReportType, &reportType); err != nil {
			return errors.New("parse checkmarx json: reportType must be a string")
		}
		n := normalizeToken(reportType)
		n = strings.ReplaceAll(n, "-", "")
		n = strings.ReplaceAll(n, "_", "")
		if n != "jsonv2" {
			return fmt.Errorf("parse checkmarx json: unsupported reportType %q", reportType)
		}
	}
	return nil
}

func reportDetectedAt(r report) string {
	for _, raw := range []string{
		r.ScanInfo.FinishedAt,
		r.ScanInfo.CreatedAt,
		r.GeneratedAt,
		r.CreatedAt,
	} {
		if ts := normalizeRFC3339(raw); ts != "unknown" {
			return ts
		}
	}
	return "unknown"
}

func resolveCategory(rs scanResult) string {
	candidates := []string{
		normalizeToken(rs.Category),
		normalizeToken(rs.Type),
		normalizeToken(rs.Group),
		normalizeToken(rs.QueryName),
	}
	for _, c := range candidates {
		switch {
		case strings.Contains(c, "secret"), strings.Contains(c, "token"), strings.Contains(c, "password"):
			return "secret"
		case strings.Contains(c, "misconfig"), strings.Contains(c, "config"), strings.Contains(c, "iac"), strings.Contains(c, "infrastructure"):
			return "misconfig"
		}
	}
	return "vuln"
}

func resolveLocation(rs scanResult) string {
	location := firstNonEmpty(
		rs.FilePath,
		rs.Path,
		rs.FileName,
		propertyString(rs.Data, "file_path", "filepath", "fileName", "path"),
	)
	if location != "" {
		return location
	}
	for _, n := range rs.Nodes {
		if s := firstNonEmpty(n.FilePath, n.FileName); s != "" {
			return s
		}
	}
	return "unknown"
}

func resolveComponent(rs scanResult) string {
	component := firstNonEmpty(
		rs.Component,
		rs.PackageName,
		propertyString(rs.Data, "component", "package", "package_name", "packageName"),
	)
	if component != "" {
		return component
	}
	for _, n := range rs.Nodes {
		if s := strings.TrimSpace(n.Name); s != "" {
			return s
		}
	}
	return "unknown"
}

func resolveConfidence(rs scanResult) string {
	if c := normalizeConfidence(rs.Confidence); c != "unknown" {
		return c
	}
	state := normalizeToken(rs.State)
	switch {
	case strings.Contains(state, "confirmed"), strings.Contains(state, "urgent"):
		return "high"
	case strings.Contains(state, "verify"), strings.Contains(state, "triage"):
		return "medium"
	case strings.Contains(state, "notexploitable"), strings.Contains(state, "falsepositive"):
		return "low"
	default:
		return "unknown"
	}
}

func resolveReferences(rs scanResult) []string {
	out := []string{}
	out = append(out, strings.TrimSpace(rs.Reference), strings.TrimSpace(rs.URL))
	out = append(out, rs.References...)
	out = append(out,
		propertyString(rs.Data, "reference", "url", "helpUri", "help_uri"),
	)
	return dedup(out)
}

func propertyString(m map[string]interface{}, keys ...string) string {
	if m == nil {
		return ""
	}
	for _, key := range keys {
		for k, v := range m {
			if normalizeKey(k) != normalizeKey(key) {
				continue
			}
			if s := strings.TrimSpace(interfaceToString(v)); s != "" {
				return s
			}
		}
	}
	return ""
}

func normalizeKey(raw string) string {
	n := normalizeToken(raw)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	return n
}

func interfaceToString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func normalizeRFC3339(raw string) string {
	ts := strings.TrimSpace(raw)
	if ts == "" {
		return "unknown"
	}
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "unknown"
	}
	return parsed.UTC().Format(time.RFC3339)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func normalizeToken(raw string) string {
	t := strings.TrimSpace(strings.ToLower(raw))
	if t == "" {
		return "unknown"
	}
	return t
}

func normalizeSeverity(raw string) string {
	switch normalizeToken(raw) {
	case "critical", "high", "medium", "low", "info":
		return normalizeToken(raw)
	case "major":
		return "high"
	case "minor":
		return "medium"
	default:
		return "unknown"
	}
}

func normalizeConfidence(raw string) string {
	switch normalizeToken(raw) {
	case "high", "medium", "low":
		return normalizeToken(raw)
	default:
		return "unknown"
	}
}

func normalizeExploitMaturity(raw string) string {
	switch normalizeToken(raw) {
	case "known_exploited":
		return "known_exploited"
	case "poc", "proof_of_concept", "proof-of-concept":
		return "poc"
	case "none", "no_known_exploit", "no-known-exploit":
		return "none"
	default:
		return "unknown"
	}
}

func normalizeReachability(raw string) string {
	switch normalizeToken(raw) {
	case "reachable":
		return "reachable"
	case "potentially_reachable", "potentially-reachable":
		return "potentially_reachable"
	case "not_reachable", "not-reachable", "unreachable":
		return "not_reachable"
	default:
		return "unknown"
	}
}

func dedup(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range values {
		s := strings.TrimSpace(v)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
