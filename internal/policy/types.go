package policy

import (
	"time"

	"github.com/solardome/security-gate/internal/domain"
	"github.com/solardome/security-gate/internal/scoring"
)

// Stage mirrors the canonical stage enum.
type Stage string

const (
	StagePR      Stage = "pr"
	StageMain    Stage = "main"
	StageRelease Stage = "release"
	StageProd    Stage = "prod"
)

// EvaluationInput captures everything the policy evaluator needs.
type EvaluationInput struct {
	Stage            Stage
	Environment      string
	Exposure         string
	ChangeType       string
	ContextPayload   ContextPayload
	ContextHash      string
	PolicyHash       string
	AcceptedRiskHash string
	ScanHashes       map[string]string
	ScanMetadata     map[string]ScanMetadata
	Policy           Policy
	ScoreResult      scoring.ScoreResult
	AcceptedRisks    []AcceptedRisk
	Now              time.Time
	LLMEnabled       bool
}

type ScanMetadata struct {
	SourceScanner string
	SourceVersion string
	ScanTimestamp string
}

// DecisionArtifact holds the resulting decision.json material.
type DecisionArtifact struct {
	Inputs           DecisionInputs   `json:"inputs"`
	Trust            TrustResult      `json:"trust"`
	Findings         FindingsSummary  `json:"findings"`
	Scoring          ScoringSummary   `json:"scoring"`
	Decision         PolicyDecision   `json:"decision"`
	Policy           PolicyEvaluation `json:"policy"`
	RecommendedSteps []string         `json:"recommended_next_steps"`
	Trace            DecisionTrace    `json:"decision_trace"`
	LLMExplanation   LLMExplanation   `json:"llm_explanation"`
}

// DecisionInputs summarizes the hashed inputs that influenced the decision.
type DecisionInputs struct {
	Scans         []ScanInput `json:"scans"`
	Context       ContextRef  `json:"context"`
	Policy        InputRef    `json:"policy"`
	AcceptedRisks InputRef    `json:"accepted_risks"`
}

// ContextPayload records the effective context used for evaluation.
type ContextPayload struct {
	PipelineStage         string `json:"pipeline_stage"`
	Environment           string `json:"environment"`
	Exposure              string `json:"exposure"`
	ChangeType            string `json:"change_type"`
	ScannerVersion        string `json:"scanner_version,omitempty"`
	ArtifactSigningStatus string `json:"artifact_signing_status,omitempty"`
	ProvenanceLevel       string `json:"provenance_level,omitempty"`
	BranchProtected       *bool  `json:"branch_protected,omitempty"`
}

// ContextRef is the hashed context input with effective payload.
type ContextRef struct {
	InputRef
	Payload ContextPayload `json:"payload"`
}

// ScanInput records a single scan artifact.
type ScanInput struct {
	SourceScanner string `json:"source_scanner"`
	SourceVersion string `json:"source_version"`
	InputSHA256   string `json:"input_sha256"`
	ScanTimestamp string `json:"scan_timestamp"`
	Path          string `json:"path"`
}

// InputRef is the hash/source reference for a contextual file.
type InputRef struct {
	SHA256 string `json:"sha256"`
	Source string `json:"source"`
}

// TrustResult exposes trust summary data.
type TrustResult struct {
	TrustScore    int                  `json:"trust_score"`
	TrustSignals  scoring.TrustSignals `json:"trust_signals"`
	TrustModifier int                  `json:"trust_modifier"`
}

// FindingsSummary aggregates the finding counts and suppressed data.
type FindingsSummary struct {
	TotalCount              int                     `json:"total_count"`
	HardStopCount           int                     `json:"hard_stop_count"`
	ConsideredCount         int                     `json:"considered_count"`
	SuppressedByNoiseBudget int                     `json:"suppressed_by_noise_budget"`
	Items                   []scoring.ScoredFinding `json:"items"`
}

// ScoringSummary captures release risk and modifiers.
type ScoringSummary struct {
	ReleaseRisk int       `json:"release_risk"`
	Modifiers   Modifiers `json:"modifiers"`
}

// Modifiers lists the contextual contributions to release risk.
type Modifiers struct {
	StageModifier    int `json:"stage_modifier"`
	ExposureModifier int `json:"exposure_modifier"`
	ChangeModifier   int `json:"change_modifier"`
	TrustModifier    int `json:"trust_modifier"`
}

// PolicyDecision records the final decision status.
type PolicyDecision struct {
	Status    domain.DecisionType `json:"status"`
	ExitCode  int                 `json:"exit_code"`
	Rationale string              `json:"rationale"`
}

// PolicyEvaluation stores metadata about applied rules and risks.
type PolicyEvaluation struct {
	EvaluatedRules         []string            `json:"evaluated_rules"`
	ExceptionsApplied      []string            `json:"exceptions_applied"`
	AcceptedRisksApplied   []string            `json:"accepted_risks_applied"`
	AcceptedRisksCoverage  map[string][]string `json:"accepted_risks_coverage"`
	AllowWarnInProdApplied bool                `json:"allow_warn_in_prod_applied"`
	PolicyVersion          string              `json:"policy_version"`
}

// DecisionTraceEvent mirrors the trace array in decision.json.
type DecisionTraceEvent struct {
	EventID   string         `json:"event_id"`
	Timestamp time.Time      `json:"timestamp"`
	Type      string         `json:"type"`
	Details   map[string]any `json:"details,omitempty"`
}

// DecisionTrace collects both the core events and redaction metadata.
type DecisionTrace struct {
	Events    []DecisionTraceEvent    `json:"events"`
	Redaction *DecisionTraceRedaction `json:"redaction,omitempty"`
}

// DecisionTraceRedaction holds the redaction events for LLM sanitization.
type DecisionTraceRedaction struct {
	Events []DecisionTraceRedactionEvent `json:"events"`
}

// DecisionTraceRedactionEvent captures LLM redaction metadata required by governance.
type DecisionTraceRedactionEvent struct {
	EventID       string    `json:"event_id"`
	Timestamp     time.Time `json:"timestamp"`
	RedactedField string    `json:"redacted_field"`
	Reason        string    `json:"reason"`
	SanitizedRef  string    `json:"sanitized_ref"`
	OriginalHash  string    `json:"original_hash,omitempty"`
}

// LLMExplanation records LLM artifact metadata without letting outputs influence decisions.
type LLMExplanation struct {
	Enabled          bool     `json:"enabled"`
	NonAuthoritative bool     `json:"non_authoritative"`
	ContentRef       string   `json:"content_ref"`
	SanitizedPrompt  string   `json:"sanitized_prompt,omitempty"`
	References       []string `json:"references,omitempty"`
}
