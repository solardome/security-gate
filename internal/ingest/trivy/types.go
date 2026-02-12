package trivy

import "time"

// Stage represents the canonical pipeline stages from docs/core-decision-engine.md.
type Stage string

const (
	StagePR      Stage = "pr"
	StageMain    Stage = "main"
	StageRelease Stage = "release"
	StageProd    Stage = "prod"
)

// Location mirrors the canonical location object from docs/core-decision-engine.md.
type Location struct {
	Path    string `json:"path,omitempty"`
	Package string `json:"package,omitempty"`
	Target  string `json:"target,omitempty"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
}

// CanonicalFinding represents a single normalized finding according to the unified schema.
type CanonicalFinding struct {
	FindingID       string    `json:"finding_id"`
	Fingerprint     string    `json:"fingerprint"`
	Domain          string    `json:"domain"`
	Severity        string    `json:"severity"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	SourceScanner   string    `json:"source_scanner"`
	SourceVersion   string    `json:"source_version"`
	InputSHA256     string    `json:"input_sha256"`
	ScanTimestamp   time.Time `json:"scan_timestamp"`
	TimestampSource string    `json:"timestamp_source"`
	Location        Location  `json:"location"`
	EvidenceRef     string    `json:"evidence_ref"`

	CVE             string   `json:"cve_id,omitempty"`
	CVSSv3          *float64 `json:"cvss_v3,omitempty"`
	FixAvailable    string   `json:"fix_available,omitempty"`
	FixVersion      string   `json:"fix_version,omitempty"`
	ExploitMaturity string   `json:"exploit_maturity,omitempty"`
	Reachability    string   `json:"reachability,omitempty"`
	DependencyScope string   `json:"dependency_scope,omitempty"`
	LicenseType     string   `json:"license_type,omitempty"`
	Confidence      string   `json:"confidence,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	VendorStatus    string   `json:"vendor_status,omitempty"`
	RemediationHint string   `json:"remediation_hint,omitempty"`
}

// TraceEvent captures decision-trace-style events emitted during ingestion.
type TraceEvent struct {
	Timestamp time.Time      `json:"timestamp"`
	Type      string         `json:"type"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
}

// IngestResult is the output of ingesting one or more Trivy reports.
type IngestResult struct {
	Findings    []CanonicalFinding `json:"findings"`
	Trace       []TraceEvent       `json:"trace"`
	InputHashes map[string]string  `json:"input_hashes"`
}

// FatalError marks ingest failures that are considered fatal per docs/modules.md.
type FatalError struct {
	Stage Stage `json:"stage"`
	Err   error `json:"error"`
}

func (f FatalError) Error() string {
	if f.Err == nil {
		return "fatal error"
	}
	return f.Err.Error()
}

func (f FatalError) Unwrap() error {
	return f.Err
}

// GuardrailError carries a stable machine-readable code for ingest guardrails.
type GuardrailError struct {
	Code    string
	Message string
}

func (e GuardrailError) Error() string {
	return e.Message
}

func (e GuardrailError) ErrorCode() string {
	return e.Code
}
