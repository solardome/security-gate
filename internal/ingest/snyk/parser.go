package snyk

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
	GeneratedAt       string          `json:"generatedAt"`
	CreatedAt         string          `json:"createdAt"`
	ProjectName       string          `json:"projectName"`
	DisplayTargetFile string          `json:"displayTargetFile"`
	PackageManager    string          `json:"packageManager"`
	Vulnerabilities   []vulnerability `json:"vulnerabilities"`
}

type vulnerability struct {
	ID              string            `json:"id"`
	Title           string            `json:"title"`
	Severity        string            `json:"severity"`
	PackageName     string            `json:"packageName"`
	Version         string            `json:"version"`
	From            []string          `json:"from"`
	Description     string            `json:"description"`
	Identifiers     identifiers       `json:"identifiers"`
	CVEs            []string          `json:"CVEs"`
	CVEsLower       []string          `json:"cves"`
	References      []string          `json:"references"`
	Links           []link            `json:"links"`
	Type            string            `json:"type"`
	DomainID        string            `json:"domain_id"`
	Category        string            `json:"category"`
	Confidence      string            `json:"confidence"`
	Reachability    string            `json:"reachability"`
	ExploitMaturity string            `json:"exploitMaturity"`
	AdditionalData  map[string]string `json:"-"`
}

type identifiers struct {
	CVE []string `json:"CVE"`
	CWE []string `json:"CWE"`
}

type link struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

func Parse(path string, payload []byte, scannerName, scannerVersion string) ([]Finding, error) {
	if err := validateReportEnvelope(payload); err != nil {
		return nil, err
	}
	var r report
	if err := json.Unmarshal(payload, &r); err != nil {
		return nil, fmt.Errorf("parse snyk json: %w", err)
	}
	detectedAt := reportDetectedAt(r)
	out := make([]Finding, 0, len(r.Vulnerabilities))
	for idx, v := range r.Vulnerabilities {
		category := resolveCategory(v)
		domainID := strings.TrimSpace(v.DomainID)
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
		title := firstNonEmpty(v.Title, v.ID, "unknown title")
		cve := firstNonEmpty(firstSlice(v.Identifiers.CVE), firstSlice(v.CVEs), firstSlice(v.CVEsLower))
		cwe := firstNonEmpty(firstSlice(v.Identifiers.CWE))
		refs := collectReferences(v)
		component := firstNonEmpty(v.PackageName, "unknown")
		if strings.TrimSpace(v.Version) != "" {
			component = component + "@" + strings.TrimSpace(v.Version)
		}
		location := firstNonEmpty(lastSlice(v.From), r.DisplayTargetFile, "unknown")
		targetRef := firstNonEmpty(r.ProjectName, r.DisplayTargetFile, "unknown")
		rawID := firstNonEmpty(strings.TrimSpace(v.ID), title, "snyk-"+strconv.Itoa(idx))

		out = append(out, Finding{
			ScannerName:       "snyk",
			ScannerVersion:    firstNonEmpty(strings.TrimSpace(scannerVersion), "unknown"),
			ArtifactTargetRef: targetRef,
			Component:         component,
			Location:          location,
			DomainID:          domainID,
			Category:          category,
			CVE:               strings.ToUpper(strings.TrimSpace(cve)),
			CWE:               strings.ToUpper(strings.TrimSpace(cwe)),
			Severity:          normalizeSeverity(v.Severity),
			Confidence:        normalizeConfidence(v.Confidence),
			ExploitMaturity:   normalizeExploitMaturity(v.ExploitMaturity),
			Reachability:      normalizeReachability(v.Reachability),
			Title:             title,
			Description:       strings.TrimSpace(v.Description),
			References:        refs,
			DetectedAt:        detectedAt,
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
		return fmt.Errorf("parse snyk json: %w", err)
	}
	rawVulns, ok := root["vulnerabilities"]
	if !ok {
		return errors.New("parse snyk json: missing top-level vulnerabilities")
	}
	var vulns []json.RawMessage
	if err := json.Unmarshal(rawVulns, &vulns); err != nil {
		return errors.New("parse snyk json: vulnerabilities must be an array")
	}
	return nil
}

func reportDetectedAt(r report) string {
	for _, raw := range []string{r.GeneratedAt, r.CreatedAt} {
		ts := strings.TrimSpace(raw)
		if ts == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		return parsed.UTC().Format(time.RFC3339)
	}
	return "unknown"
}

func resolveCategory(v vulnerability) string {
	candidates := []string{
		normalizeToken(v.Category),
		normalizeToken(v.Type),
		normalizeToken(v.ID),
		normalizeToken(v.Title),
	}
	for _, c := range candidates {
		switch {
		case strings.Contains(c, "secret"), strings.Contains(c, "token"), strings.Contains(c, "password"):
			return "secret"
		case strings.Contains(c, "misconfig"), strings.Contains(c, "config"), strings.Contains(c, "iac"):
			return "misconfig"
		case strings.Contains(c, "license"):
			return "misconfig"
		}
	}
	return "vuln"
}

func collectReferences(v vulnerability) []string {
	out := []string{}
	for _, r := range v.References {
		if s := strings.TrimSpace(r); s != "" {
			out = append(out, s)
		}
	}
	for _, l := range v.Links {
		if s := strings.TrimSpace(l.URL); s != "" {
			out = append(out, s)
		}
	}
	return dedup(out)
}

func firstSlice(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func lastSlice(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[len(values)-1])
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
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
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
