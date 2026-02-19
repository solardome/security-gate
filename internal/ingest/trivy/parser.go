package trivy

import (
	"encoding/json"
	"errors"
	"fmt"
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
	SchemaVersion interface{} `json:"SchemaVersion"`
	ArtifactName  string      `json:"ArtifactName"`
	GeneratedAt   string      `json:"GeneratedAt"`
	Scanner       scannerMeta `json:"Scanner"`
	Metadata      metadata    `json:"Metadata"`
	Results       []result    `json:"Results"`
}

type scannerMeta struct {
	Name    string `json:"Name"`
	Version string `json:"Version"`
}

type metadata struct {
	GeneratedAt    string      `json:"GeneratedAt"`
	Timestamp      string      `json:"Timestamp"`
	Date           string      `json:"Date"`
	Scanner        scannerMeta `json:"Scanner"`
	ScannerVersion string      `json:"ScannerVersion"`
	ToolVersion    string      `json:"ToolVersion"`
}

type result struct {
	Target            string             `json:"Target"`
	Vulnerabilities   []vulnerability    `json:"Vulnerabilities"`
	Misconfigurations []misconfiguration `json:"Misconfigurations"`
	Secrets           []secretFinding    `json:"Secrets"`
}

type vulnerability struct {
	VulnerabilityID string   `json:"VulnerabilityID"`
	PkgName         string   `json:"PkgName"`
	Severity        string   `json:"Severity"`
	Title           string   `json:"Title"`
	Description     string   `json:"Description"`
	PrimaryURL      string   `json:"PrimaryURL"`
	References      []string `json:"References"`
	CweIDs          []string `json:"CweIDs"`
	PublishedDate   string   `json:"PublishedDate"`
	DomainID        string   `json:"DomainID"`
	Category        string   `json:"Category"`
	Confidence      string   `json:"Confidence"`
	ExploitMaturity string   `json:"ExploitMaturity"`
	Reachability    string   `json:"Reachability"`
	KnownExploited  bool     `json:"KnownExploited"`
}

type misconfiguration struct {
	ID          string   `json:"ID"`
	AVDID       string   `json:"AVDID"`
	Type        string   `json:"Type"`
	Title       string   `json:"Title"`
	Description string   `json:"Description"`
	Message     string   `json:"Message"`
	Resolution  string   `json:"Resolution"`
	Severity    string   `json:"Severity"`
	PrimaryURL  string   `json:"PrimaryURL"`
	References  []string `json:"References"`
	DomainID    string   `json:"DomainID"`
	Confidence  string   `json:"Confidence"`
}

type secretFinding struct {
	RuleID      string   `json:"RuleID"`
	Category    string   `json:"Category"`
	Severity    string   `json:"Severity"`
	Title       string   `json:"Title"`
	Match       string   `json:"Match"`
	Description string   `json:"Description"`
	PrimaryURL  string   `json:"PrimaryURL"`
	References  []string `json:"References"`
	DomainID    string   `json:"DomainID"`
	Confidence  string   `json:"Confidence"`
}

func Parse(path string, payload []byte, scannerName, scannerVersion string) ([]Finding, error) {
	if err := validateReportEnvelope(payload); err != nil {
		return nil, err
	}
	var r report
	if err := json.Unmarshal(payload, &r); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}
	detectedAt := reportDetectedAt(r)
	detectedScannerVersion := reportScannerVersion(r)
	var out []Finding
	sourceIndex := 0
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			domain := strings.TrimSpace(v.DomainID)
			if domain == "" {
				domain = "VULN_GENERIC"
			}
			cat := normalizeToken(v.Category)
			if cat == "unknown" {
				cat = "vuln"
			}
			exploit := normalizeToken(v.ExploitMaturity)
			if exploit == "unknown" {
				if v.KnownExploited {
					exploit = "known_exploited"
				} else {
					exploit = "unknown"
				}
			}
			refs := append([]string{}, v.References...)
			if v.PrimaryURL != "" {
				refs = append(refs, v.PrimaryURL)
			}
			cwe := ""
			if len(v.CweIDs) > 0 {
				cwe = v.CweIDs[0]
			}
			out = append(out, Finding{
				ScannerName:       "trivy",
				ScannerVersion:    detectedScannerVersion,
				ArtifactTargetRef: firstNonEmpty(r.ArtifactName, res.Target, "unknown"),
				Component:         firstNonEmpty(v.PkgName, "unknown"),
				Location:          firstNonEmpty(res.Target, "unknown"),
				DomainID:          domain,
				Category:          cat,
				CVE:               firstNonEmpty(v.VulnerabilityID, ""),
				CWE:               cwe,
				Severity:          normalizeToken(v.Severity),
				Confidence:        normalizeToken(v.Confidence),
				ExploitMaturity:   exploit,
				Reachability:      normalizeToken(v.Reachability),
				Title:             firstNonEmpty(v.Title, v.VulnerabilityID, "unknown title"),
				Description:       v.Description,
				References:        refs,
				DetectedAt:        detectedAt,
				SourceFile:        path,
				SourceIndex:       sourceIndex,
				RawID:             firstNonEmpty(v.VulnerabilityID, ""),
			})
			sourceIndex++
		}
		for _, m := range res.Misconfigurations {
			domain := strings.TrimSpace(m.DomainID)
			if domain == "" {
				domain = "MISCONFIG_GENERIC"
			}
			refs := append([]string{}, m.References...)
			if m.PrimaryURL != "" {
				refs = append(refs, m.PrimaryURL)
			}
			out = append(out, Finding{
				ScannerName:       "trivy",
				ScannerVersion:    detectedScannerVersion,
				ArtifactTargetRef: firstNonEmpty(r.ArtifactName, res.Target, "unknown"),
				Component:         firstNonEmpty(m.Type, "unknown"),
				Location:          firstNonEmpty(res.Target, "unknown"),
				DomainID:          domain,
				Category:          "misconfig",
				CVE:               "",
				CWE:               "",
				Severity:          normalizeToken(m.Severity),
				Confidence:        normalizeToken(m.Confidence),
				ExploitMaturity:   "none",
				Reachability:      "unknown",
				Title:             firstNonEmpty(m.Title, m.ID, m.AVDID, "unknown title"),
				Description:       firstNonEmpty(m.Description, m.Message, m.Resolution),
				References:        refs,
				DetectedAt:        detectedAt,
				SourceFile:        path,
				SourceIndex:       sourceIndex,
				RawID:             firstNonEmpty(m.ID, m.AVDID, ""),
			})
			sourceIndex++
		}
		for _, s := range res.Secrets {
			domain := strings.TrimSpace(s.DomainID)
			if domain == "" {
				domain = "SECRET_GENERIC"
			}
			refs := append([]string{}, s.References...)
			if s.PrimaryURL != "" {
				refs = append(refs, s.PrimaryURL)
			}
			out = append(out, Finding{
				ScannerName:       "trivy",
				ScannerVersion:    detectedScannerVersion,
				ArtifactTargetRef: firstNonEmpty(r.ArtifactName, res.Target, "unknown"),
				Component:         firstNonEmpty(s.Category, "unknown"),
				Location:          firstNonEmpty(res.Target, "unknown"),
				DomainID:          domain,
				Category:          "secret",
				CVE:               "",
				CWE:               "",
				Severity:          normalizeToken(s.Severity),
				Confidence:        normalizeToken(s.Confidence),
				ExploitMaturity:   "none",
				Reachability:      "unknown",
				Title:             firstNonEmpty(s.Title, s.RuleID, "unknown title"),
				Description:       firstNonEmpty(s.Description, s.Match),
				References:        refs,
				DetectedAt:        detectedAt,
				SourceFile:        path,
				SourceIndex:       sourceIndex,
				RawID:             firstNonEmpty(s.RuleID, ""),
			})
			sourceIndex++
		}
	}
	return out, nil
}

func reportScannerVersion(r report) string {
	candidates := []string{
		r.Scanner.Version,
		r.Metadata.Scanner.Version,
		r.Metadata.ScannerVersion,
		r.Metadata.ToolVersion,
	}
	for _, c := range candidates {
		if s := strings.TrimSpace(c); s != "" {
			return s
		}
	}
	return "unknown"
}

func ReportDetectedAt(payload []byte) string {
	var r report
	if err := json.Unmarshal(payload, &r); err != nil {
		return "unknown"
	}
	return reportDetectedAt(r)
}

func normalizeToken(s string) string {
	t := strings.TrimSpace(strings.ToLower(s))
	if t == "" {
		return "unknown"
	}
	return t
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func reportDetectedAt(r report) string {
	candidates := []string{
		r.GeneratedAt,
		r.Metadata.GeneratedAt,
		r.Metadata.Timestamp,
		r.Metadata.Date,
	}
	for _, c := range candidates {
		raw := strings.TrimSpace(c)
		if raw == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			continue
		}
		return parsed.UTC().Format(time.RFC3339)
	}
	return "unknown"
}

func validateReportEnvelope(payload []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(payload, &root); err != nil {
		return fmt.Errorf("parse trivy json: %w", err)
	}
	if err := validateSchemaVersion(root); err != nil {
		return err
	}
	rawResults, ok := root["Results"]
	if !ok {
		return errors.New("parse trivy json: missing top-level Results")
	}
	var results []json.RawMessage
	if err := json.Unmarshal(rawResults, &results); err != nil {
		return errors.New("parse trivy json: Results must be an array")
	}
	return nil
}

func validateSchemaVersion(root map[string]json.RawMessage) error {
	rawSchemaVersion, ok := root["SchemaVersion"]
	if !ok {
		return nil
	}
	var num int
	if err := json.Unmarshal(rawSchemaVersion, &num); err == nil {
		if num == 1 || num == 2 {
			return nil
		}
		return fmt.Errorf("parse trivy json: unsupported SchemaVersion %d", num)
	}
	var str string
	if err := json.Unmarshal(rawSchemaVersion, &str); err == nil {
		switch strings.TrimSpace(str) {
		case "1", "2":
			return nil
		default:
			return fmt.Errorf("parse trivy json: unsupported SchemaVersion %q", str)
		}
	}
	return errors.New("parse trivy json: SchemaVersion must be a number or string")
}
