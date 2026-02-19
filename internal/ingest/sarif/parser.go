package sarif

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
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
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool        tool         `json:"tool"`
	Results     []result     `json:"results"`
	Invocations []invocation `json:"invocations"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	SemanticVersion string `json:"semanticVersion"`
	Rules           []rule `json:"rules"`
}

type rule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription message                `json:"shortDescription"`
	FullDescription  message                `json:"fullDescription"`
	HelpURI          string                 `json:"helpUri"`
	Properties       map[string]interface{} `json:"properties"`
}

type result struct {
	RuleID              string                 `json:"ruleId"`
	RuleIndex           *int                   `json:"ruleIndex"`
	Level               string                 `json:"level"`
	Message             message                `json:"message"`
	Locations           []location             `json:"locations"`
	Fingerprints        map[string]string      `json:"fingerprints"`
	PartialFingerprints map[string]string      `json:"partialFingerprints"`
	Properties          map[string]interface{} `json:"properties"`
}

type message struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type invocation struct {
	EndTimeUTC   string `json:"endTimeUtc"`
	StartTimeUTC string `json:"startTimeUtc"`
}

var cvePattern = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
var cwePattern = regexp.MustCompile(`(?i)\bCWE-\d+\b`)

func Parse(path string, payload []byte, scannerName, scannerVersion string) ([]Finding, error) {
	if err := validateReportEnvelope(payload); err != nil {
		return nil, err
	}
	var r report
	if err := json.Unmarshal(payload, &r); err != nil {
		return nil, fmt.Errorf("parse sarif json: %w", err)
	}
	out := []Finding{}
	sourceIndex := 0
	for runIndex, ru := range r.Runs {
		runDetectedAt := runDetectedAt(ru)
		rulesByID := map[string]rule{}
		for _, rl := range ru.Tool.Driver.Rules {
			id := strings.TrimSpace(rl.ID)
			if id != "" {
				rulesByID[id] = rl
			}
		}
		detectedScanner := firstNonEmpty(
			strings.TrimSpace(ru.Tool.Driver.Name),
			strings.TrimSpace(scannerName),
			"sarif",
		)
		detectedScanner = canonicalScannerName(detectedScanner)
		detectedScannerVersion := firstNonEmpty(
			strings.TrimSpace(ru.Tool.Driver.SemanticVersion),
			strings.TrimSpace(ru.Tool.Driver.Version),
			strings.TrimSpace(scannerVersion),
			"unknown",
		)
		for _, rs := range ru.Results {
			rl := resolveRule(ru.Tool.Driver.Rules, rulesByID, rs)
			category := resolveCategory(rs.Properties, rl.Properties)
			domainID := resolveDomainID(rs.Properties, rl.Properties, category)
			location := resolveLocation(rs)
			title := firstNonEmpty(
				strings.TrimSpace(rs.Message.Text),
				strings.TrimSpace(rl.ShortDescription.Text),
				strings.TrimSpace(rl.Name),
				strings.TrimSpace(rs.RuleID),
				"unknown title",
			)
			description := firstNonEmpty(
				strings.TrimSpace(rs.Message.Markdown),
				strings.TrimSpace(rl.FullDescription.Text),
			)
			references := collectReferences(rs, rl)
			cve := resolveCVE(rs, rl, title, description)
			cwe := resolveCWE(rs, rl, title, description)
			rawID := firstNonEmpty(
				fingerprintID(rs),
				strings.TrimSpace(rs.RuleID),
				fmt.Sprintf("sarif-run-%d-result-%d", runIndex, sourceIndex),
			)
			component := firstNonEmpty(
				propertyString(rs.Properties, "component", "package", "package_name", "packageName", "dependency"),
				propertyString(rl.Properties, "component", "package", "package_name", "packageName", "dependency"),
				"unknown",
			)
			artifactTargetRef := firstNonEmpty(
				propertyString(rs.Properties, "target_ref", "targetRef", "repository", "project", "image", "artifact"),
				location,
				"unknown",
			)
			confidence := normalizeConfidence(firstNonEmpty(
				propertyString(rs.Properties, "confidence", "precision"),
				propertyString(rl.Properties, "confidence", "precision"),
				"unknown",
			))
			exploit := normalizeExploitMaturity(firstNonEmpty(
				propertyString(rs.Properties, "exploit_maturity", "exploitMaturity"),
				propertyString(rl.Properties, "exploit_maturity", "exploitMaturity"),
				"unknown",
			))
			reachability := normalizeReachability(firstNonEmpty(
				propertyString(rs.Properties, "reachability"),
				propertyString(rl.Properties, "reachability"),
				"unknown",
			))

			out = append(out, Finding{
				ScannerName:       detectedScanner,
				ScannerVersion:    detectedScannerVersion,
				ArtifactTargetRef: artifactTargetRef,
				Component:         component,
				Location:          location,
				DomainID:          domainID,
				Category:          category,
				CVE:               cve,
				CWE:               cwe,
				Severity:          resolveSeverity(rs.Level, rs.Properties, rl.Properties),
				Confidence:        confidence,
				ExploitMaturity:   exploit,
				Reachability:      reachability,
				Title:             title,
				Description:       description,
				References:        references,
				DetectedAt:        runDetectedAt,
				SourceFile:        path,
				SourceIndex:       sourceIndex,
				RawID:             rawID,
			})
			sourceIndex++
		}
	}
	return out, nil
}

func ReportDetectedAt(payload []byte) string {
	var r report
	if err := json.Unmarshal(payload, &r); err != nil {
		return "unknown"
	}
	for _, ru := range r.Runs {
		if at := runDetectedAt(ru); at != "unknown" {
			return at
		}
	}
	return "unknown"
}

func validateReportEnvelope(payload []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(payload, &root); err != nil {
		return fmt.Errorf("parse sarif json: %w", err)
	}
	rawVersion, ok := root["version"]
	if !ok {
		return errors.New("parse sarif json: missing top-level version")
	}
	var version string
	if err := json.Unmarshal(rawVersion, &version); err != nil {
		return errors.New("parse sarif json: version must be a string")
	}
	if strings.TrimSpace(version) != "2.1.0" {
		return fmt.Errorf("parse sarif json: unsupported version %q", version)
	}
	rawRuns, ok := root["runs"]
	if !ok {
		return errors.New("parse sarif json: missing top-level runs")
	}
	var runs []json.RawMessage
	if err := json.Unmarshal(rawRuns, &runs); err != nil {
		return errors.New("parse sarif json: runs must be an array")
	}
	for i, rawRun := range runs {
		if err := validateRunEnvelope(rawRun, i); err != nil {
			return err
		}
	}
	return nil
}

func validateRunEnvelope(rawRun json.RawMessage, index int) error {
	var runRoot map[string]json.RawMessage
	if err := json.Unmarshal(rawRun, &runRoot); err != nil {
		return fmt.Errorf("parse sarif json: runs[%d] must be an object", index)
	}
	rawTool, ok := runRoot["tool"]
	if !ok {
		return fmt.Errorf("parse sarif json: runs[%d] missing tool", index)
	}
	var toolRoot map[string]json.RawMessage
	if err := json.Unmarshal(rawTool, &toolRoot); err != nil {
		return fmt.Errorf("parse sarif json: runs[%d].tool must be an object", index)
	}
	rawDriver, ok := toolRoot["driver"]
	if !ok {
		return fmt.Errorf("parse sarif json: runs[%d].tool missing driver", index)
	}
	var driverRoot map[string]json.RawMessage
	if err := json.Unmarshal(rawDriver, &driverRoot); err != nil {
		return fmt.Errorf("parse sarif json: runs[%d].tool.driver must be an object", index)
	}
	rawName, ok := driverRoot["name"]
	if !ok {
		return fmt.Errorf("parse sarif json: runs[%d].tool.driver missing name", index)
	}
	var name string
	if err := json.Unmarshal(rawName, &name); err != nil {
		return fmt.Errorf("parse sarif json: runs[%d].tool.driver.name must be a string", index)
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("parse sarif json: runs[%d].tool.driver.name must be non-empty", index)
	}
	rawResults, ok := runRoot["results"]
	if !ok {
		return fmt.Errorf("parse sarif json: runs[%d] missing results", index)
	}
	var results []json.RawMessage
	if err := json.Unmarshal(rawResults, &results); err != nil {
		return fmt.Errorf("parse sarif json: runs[%d].results must be an array", index)
	}
	return nil
}

func runDetectedAt(ru run) string {
	for _, inv := range ru.Invocations {
		for _, raw := range []string{inv.EndTimeUTC, inv.StartTimeUTC} {
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
	}
	return "unknown"
}

func resolveRule(rules []rule, rulesByID map[string]rule, rs result) rule {
	if id := strings.TrimSpace(rs.RuleID); id != "" {
		if found, ok := rulesByID[id]; ok {
			return found
		}
	}
	if rs.RuleIndex != nil && *rs.RuleIndex >= 0 && *rs.RuleIndex < len(rules) {
		return rules[*rs.RuleIndex]
	}
	return rule{}
}

func resolveLocation(rs result) string {
	for _, loc := range rs.Locations {
		uri := strings.TrimSpace(loc.PhysicalLocation.ArtifactLocation.URI)
		if uri != "" {
			return uri
		}
	}
	return "unknown"
}

func resolveSeverity(level string, resultProps, ruleProps map[string]interface{}) string {
	for _, props := range []map[string]interface{}{resultProps, ruleProps} {
		if props == nil {
			continue
		}
		securitySeverity := propertyString(props, "security-severity", "security_severity")
		if securitySeverity != "" {
			if score, err := strconv.ParseFloat(securitySeverity, 64); err == nil {
				switch {
				case score >= 9.0:
					return "critical"
				case score >= 7.0:
					return "high"
				case score >= 4.0:
					return "medium"
				case score > 0:
					return "low"
				default:
					return "info"
				}
			}
		}
		if sev := normalizeSeverity(propertyString(props, "severity")); sev != "unknown" {
			return sev
		}
	}
	return normalizeSeverity(level)
}

func normalizeSeverity(raw string) string {
	n := normalizeToken(raw)
	switch n {
	case "critical", "high", "medium", "low", "info":
		return n
	case "error":
		return "high"
	case "warning", "warn":
		return "medium"
	case "note":
		return "low"
	case "none":
		return "info"
	default:
		return "unknown"
	}
}

func resolveCategory(resultProps, ruleProps map[string]interface{}) string {
	for _, props := range []map[string]interface{}{resultProps, ruleProps} {
		category := normalizeToken(propertyString(props, "category", "finding_type", "type"))
		switch category {
		case "vuln", "vulnerability":
			return "vuln"
		case "misconfig", "misconfiguration", "configuration", "iac":
			return "misconfig"
		case "secret", "secrets":
			return "secret"
		}
	}
	tags := append(propertyStrings(resultProps, "tags"), propertyStrings(ruleProps, "tags")...)
	joined := " " + strings.Join(tags, " ") + " "
	switch {
	case strings.Contains(joined, " secret "),
		strings.Contains(joined, " secrets "),
		strings.Contains(joined, " credential "),
		strings.Contains(joined, " token "),
		strings.Contains(joined, " password "):
		return "secret"
	case strings.Contains(joined, " misconfig "),
		strings.Contains(joined, " configuration "),
		strings.Contains(joined, " config "),
		strings.Contains(joined, " iac "),
		strings.Contains(joined, " terraform "),
		strings.Contains(joined, " kubernetes "):
		return "misconfig"
	default:
		return "vuln"
	}
}

func resolveDomainID(resultProps, ruleProps map[string]interface{}, category string) string {
	domainID := firstNonEmpty(
		propertyString(resultProps, "domain_id", "domainId"),
		propertyString(ruleProps, "domain_id", "domainId"),
	)
	if domainID != "" {
		return domainID
	}
	switch category {
	case "secret":
		return "SECRET_GENERIC"
	case "misconfig":
		return "MISCONFIG_GENERIC"
	default:
		return "VULN_GENERIC"
	}
}

func resolveCVE(rs result, rl rule, title, description string) string {
	cve := firstNonEmpty(
		propertyString(rs.Properties, "cve", "cve_id", "vulnerability_id"),
		propertyString(rl.Properties, "cve", "cve_id", "vulnerability_id"),
		findPattern(rs.RuleID, cvePattern),
		findPattern(title, cvePattern),
		findPattern(description, cvePattern),
	)
	return strings.ToUpper(strings.TrimSpace(cve))
}

func resolveCWE(rs result, rl rule, title, description string) string {
	cwe := firstNonEmpty(
		propertyString(rs.Properties, "cwe", "cwe_id"),
		propertyString(rl.Properties, "cwe", "cwe_id"),
		findPattern(rs.RuleID, cwePattern),
		findPattern(title, cwePattern),
		findPattern(description, cwePattern),
	)
	return strings.ToUpper(strings.TrimSpace(cwe))
}

func findPattern(raw string, re *regexp.Regexp) string {
	match := re.FindString(raw)
	return strings.TrimSpace(match)
}

func collectReferences(rs result, rl rule) []string {
	candidates := []string{}
	if strings.TrimSpace(rl.HelpURI) != "" {
		candidates = append(candidates, strings.TrimSpace(rl.HelpURI))
	}
	candidates = append(candidates, propertyStrings(rs.Properties, "references")...)
	candidates = append(candidates, propertyStrings(rl.Properties, "references")...)
	candidates = append(candidates,
		propertyString(rs.Properties, "reference", "url", "help_uri"),
		propertyString(rl.Properties, "reference", "url", "help_uri"),
	)
	return dedupStrings(candidates)
}

func fingerprintID(rs result) string {
	orderedKeys := []string{
		"primaryLocationLineHash",
		"instanceGuid",
		"fingerprintGuid",
		"sha256",
		"id",
	}
	for _, key := range orderedKeys {
		if v := strings.TrimSpace(rs.Fingerprints[key]); v != "" {
			return v
		}
		if v := strings.TrimSpace(rs.PartialFingerprints[key]); v != "" {
			return v
		}
	}
	if len(rs.Fingerprints) > 0 {
		keys := sortedKeys(rs.Fingerprints)
		for _, key := range keys {
			if v := strings.TrimSpace(rs.Fingerprints[key]); v != "" {
				return v
			}
		}
	}
	if len(rs.PartialFingerprints) > 0 {
		keys := sortedKeys(rs.PartialFingerprints)
		for _, key := range keys {
			if v := strings.TrimSpace(rs.PartialFingerprints[key]); v != "" {
				return v
			}
		}
	}
	return ""
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func propertyString(props map[string]interface{}, keys ...string) string {
	if props == nil {
		return ""
	}
	for _, key := range keys {
		if v, ok := findProperty(props, key); ok {
			if s := valueToString(v); strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func propertyStrings(props map[string]interface{}, key string) []string {
	if props == nil {
		return nil
	}
	v, ok := findProperty(props, key)
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s := strings.TrimSpace(valueToString(item)); s != "" {
				out = append(out, normalizeToken(s))
			}
		}
		return out
	case string:
		items := strings.Split(t, ",")
		out := make([]string, 0, len(items))
		for _, item := range items {
			if s := strings.TrimSpace(item); s != "" {
				out = append(out, normalizeToken(s))
			}
		}
		return out
	default:
		if s := strings.TrimSpace(valueToString(t)); s != "" {
			return []string{normalizeToken(s)}
		}
	}
	return nil
}

func findProperty(props map[string]interface{}, key string) (interface{}, bool) {
	keyNorm := normalizeKey(key)
	for k, v := range props {
		if normalizeKey(k) == keyNorm {
			return v, true
		}
	}
	return nil, false
}

func normalizeKey(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.ReplaceAll(raw, "-", "")
	raw = strings.ReplaceAll(raw, "_", "")
	return raw
}

func valueToString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case []interface{}:
		for _, item := range t {
			if s := strings.TrimSpace(valueToString(item)); s != "" {
				return s
			}
		}
		return ""
	case map[string]interface{}:
		if s := strings.TrimSpace(valueToString(t["text"])); s != "" {
			return s
		}
		if s := strings.TrimSpace(valueToString(t["id"])); s != "" {
			return s
		}
	}
	return ""
}

func normalizeToken(raw string) string {
	trimmed := strings.TrimSpace(strings.ToLower(raw))
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}

func canonicalScannerName(raw string) string {
	token := normalizeToken(raw)
	switch {
	case token == "unknown", token == "sarif", strings.Contains(token, "sarif"):
		return "sarif"
	case token == "trivy":
		return "trivy"
	case strings.Contains(token, "snyk"):
		return "snyk"
	case strings.Contains(token, "checkmarx"), strings.HasPrefix(token, "cx"):
		return "checkmarx"
	case strings.HasPrefix(token, "sonar"):
		return "sonar"
	default:
		// Non-native SARIF producers map to generic canonical SARIF scanner id.
		return "sarif"
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
	case "poc", "proof_of_concept", "proof-of-concept", "functional":
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func dedupStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		v := strings.TrimSpace(value)
		if v == "" {
			continue
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
