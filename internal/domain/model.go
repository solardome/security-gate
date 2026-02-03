package domain

import "time"

// Severity levels consistent with CVSS/Trivy but normalized
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
	SeverityUnknown  Severity = "UNKNOWN"
)

// Decision outcomes
type DecisionType string

const (
	DecisionAllow DecisionType = "ALLOW"
	DecisionWarn  DecisionType = "WARN"
	DecisionBlock DecisionType = "BLOCK"
)

// Domain categories for findings (canonical enum from docs/core-decision-engine.md)
type FindingDomain string

const (
	DomainVulnerability FindingDomain = "VULNERABILITY"
	DomainSecret        FindingDomain = "SECRET"
	DomainMalware       FindingDomain = "MALWARE"
	DomainLicense       FindingDomain = "LICENSE"
	DomainConfig        FindingDomain = "CONFIG"
	DomainProvenance    FindingDomain = "PROVENANCE" // Synthetic findings for trust issues
)

// UnifiedFinding is the normalized schema from docs/core-decision-engine.md
type UnifiedFinding struct {
	ID          string        `json:"id"` // Unique hash or scanner ID
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Domain      FindingDomain `json:"domain"`
	Severity    Severity      `json:"severity"`

	// Modifiers (Normalized)
	HasFix        bool `json:"has_fix"`
	IsExploitable bool `json:"is_exploitable"`
	IsReachable   bool `json:"is_reachable"` // Optional, false if unknown

	// Location
	PkgName    string `json:"pkg_name,omitempty"`
	PkgVersion string `json:"pkg_version,omitempty"`
	FilePath   string `json:"file_path,omitempty"`
	LineStart  int    `json:"line_start,omitempty"`

	// Original scanner data for traceability
	ScannerName string `json:"scanner_name"`
	OriginalID  string `json:"original_id"` // e.g. CVE-2023-1234
}

// RiskScore represents the calculated risk (0-100)
type RiskScore struct {
	TotalScore      int `json:"total_score"`      // 0-100
	BaseScore       int `json:"base_score"`       // Derived from Severity
	TrustModifier   int `json:"trust_modifier"`   // Penalty for low trust
	ContextModifier int `json:"context_modifier"` // Modifiers for exploitability etc.
}

// Decision is the final authoritative artifact
type Decision struct {
	Status    DecisionType `json:"status"` // ALLOW, WARN, BLOCK
	RiskScore int          `json:"risk_score"`

	// Traceability
	TraceID   string    `json:"trace_id"`
	Timestamp time.Time `json:"timestamp"`

	// Why?
	HardStopBreached bool     `json:"hard_stop_breached"`
	PolicyViolations []string `json:"policy_violations,omitempty"`

	// Determining logic
	PrimaryFinding *UnifiedFinding `json:"primary_finding,omitempty"` // The finding that drove the max score
}
