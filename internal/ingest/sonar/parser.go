package sonar

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
	GeneratedAt string  `json:"generatedAt"`
	ProjectKey  string  `json:"projectKey"`
	Rules       []rule  `json:"rules"`
	Issues      []issue `json:"issues"`
}

type rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	EngineID    string   `json:"engineId"`
	Severity    string   `json:"severity"`
	Type        string   `json:"type"`
	HelpURI     string   `json:"helpUri"`
	Impacts     []impact `json:"impacts"`
}

type impact struct {
	SoftwareQuality string `json:"softwareQuality"`
	Severity        string `json:"severity"`
}

type issue struct {
	RuleID          string          `json:"ruleId"`
	EngineID        string          `json:"engineId"`
	Severity        string          `json:"severity"`
	Type            string          `json:"type"`
	PrimaryLocation primaryLocation `json:"primaryLocation"`
}

type primaryLocation struct {
	Message   string    `json:"message"`
	FilePath  string    `json:"filePath"`
	TextRange textRange `json:"textRange"`
}

type textRange struct {
	StartLine int `json:"startLine"`
}

func Parse(path string, payload []byte, scannerName, scannerVersion string) ([]Finding, error) {
	if err := validateReportEnvelope(payload); err != nil {
		return nil, err
	}
	var r report
	if err := json.Unmarshal(payload, &r); err != nil {
		return nil, fmt.Errorf("parse sonar json: %w", err)
	}
	rules := map[string]rule{}
	for _, rl := range r.Rules {
		if id := strings.TrimSpace(rl.ID); id != "" {
			rules[id] = rl
		}
	}
	detectedAt := reportDetectedAt(r)
	out := make([]Finding, 0, len(r.Issues))
	for idx, is := range r.Issues {
		rl := rules[strings.TrimSpace(is.RuleID)]
		category := resolveCategory(is, rl)
		domainID := resolveDomainID(category)
		title := firstNonEmpty(is.PrimaryLocation.Message, rl.Name, is.RuleID, "unknown title")
		description := strings.TrimSpace(rl.Description)
		location := firstNonEmpty(is.PrimaryLocation.FilePath, "unknown")
		rawID := firstNonEmpty(
			is.RuleID+"|"+location+"|"+strconv.Itoa(is.PrimaryLocation.TextRange.StartLine),
			"sonar-"+strconv.Itoa(idx),
		)
		refs := []string{}
		if s := strings.TrimSpace(rl.HelpURI); s != "" {
			refs = append(refs, s)
		}
		refs = dedup(refs)
		out = append(out, Finding{
			ScannerName:       "sonar",
			ScannerVersion:    firstNonEmpty(strings.TrimSpace(scannerVersion), "unknown"),
			ArtifactTargetRef: firstNonEmpty(strings.TrimSpace(r.ProjectKey), "unknown"),
			Component:         "unknown",
			Location:          location,
			DomainID:          domainID,
			Category:          category,
			CVE:               "",
			CWE:               "",
			Severity:          resolveSeverity(is, rl),
			Confidence:        "unknown",
			ExploitMaturity:   "unknown",
			Reachability:      "unknown",
			Title:             title,
			Description:       description,
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
		return fmt.Errorf("parse sonar json: %w", err)
	}
	rawIssues, ok := root["issues"]
	if !ok {
		return errors.New("parse sonar json: missing top-level issues")
	}
	var issues []json.RawMessage
	if err := json.Unmarshal(rawIssues, &issues); err != nil {
		return errors.New("parse sonar json: issues must be an array")
	}
	if rawRules, ok := root["rules"]; ok {
		var rules []json.RawMessage
		if err := json.Unmarshal(rawRules, &rules); err != nil {
			return errors.New("parse sonar json: rules must be an array")
		}
	}
	for i, rawIssue := range issues {
		var issueRoot map[string]json.RawMessage
		if err := json.Unmarshal(rawIssue, &issueRoot); err != nil {
			return fmt.Errorf("parse sonar json: issues[%d] must be an object", i)
		}
		rawRuleID, ok := issueRoot["ruleId"]
		if !ok {
			return fmt.Errorf("parse sonar json: issues[%d] missing ruleId", i)
		}
		var ruleID string
		if err := json.Unmarshal(rawRuleID, &ruleID); err != nil || strings.TrimSpace(ruleID) == "" {
			return fmt.Errorf("parse sonar json: issues[%d].ruleId must be a non-empty string", i)
		}
	}
	return nil
}

func reportDetectedAt(r report) string {
	ts := strings.TrimSpace(r.GeneratedAt)
	if ts == "" {
		return "unknown"
	}
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "unknown"
	}
	return parsed.UTC().Format(time.RFC3339)
}

func resolveCategory(is issue, rl rule) string {
	candidates := []string{
		normalizeToken(is.Type),
		normalizeToken(rl.Type),
		normalizeToken(is.RuleID),
		normalizeToken(is.PrimaryLocation.Message),
		normalizeToken(rl.Name),
	}
	for _, c := range candidates {
		switch {
		case strings.Contains(c, "secret"), strings.Contains(c, "token"), strings.Contains(c, "password"), strings.Contains(c, "credential"):
			return "secret"
		case strings.Contains(c, "vulnerability"), strings.Contains(c, "security_hotspot"), strings.Contains(c, "securityhotspot"):
			return "vuln"
		case strings.Contains(c, "bug"), strings.Contains(c, "code_smell"), strings.Contains(c, "codesmell"):
			return "misconfig"
		}
	}
	return "misconfig"
}

func resolveDomainID(category string) string {
	switch category {
	case "secret":
		return "SECRET_GENERIC"
	case "misconfig":
		return "MISCONFIG_GENERIC"
	default:
		return "VULN_GENERIC"
	}
}

func resolveSeverity(is issue, rl rule) string {
	for _, raw := range []string{is.Severity, rl.Severity} {
		if sev := mapSeverity(raw); sev != "unknown" {
			return sev
		}
	}
	for _, imp := range rl.Impacts {
		if sev := mapSeverity(imp.Severity); sev != "unknown" {
			return sev
		}
	}
	return "unknown"
}

func mapSeverity(raw string) string {
	switch normalizeToken(raw) {
	case "blocker", "critical":
		return "critical"
	case "major", "high":
		return "high"
	case "minor", "medium":
		return "medium"
	case "info", "informational", "low":
		return "low"
	default:
		return "unknown"
	}
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
