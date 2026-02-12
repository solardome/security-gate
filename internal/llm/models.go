package llm

import "time"

// LLMCounts captures aggregated counts that are safe to include in LLM prompts.
type LLMCounts struct {
	Total          int
	HardStop       int
	MaxFindingRisk int
}

// LLMContext defines stage and exposure inputs exposed to the LLM.
type LLMContext struct {
	Stage      string
	Exposure   string
	ChangeType string
}

// LLMFindingSummary describes a non-sensitive finding summary allowed in the prompt.
type LLMFindingSummary struct {
	FindingID   string
	Fingerprint string
	Title       string
	Domain      string
	Severity    string
}

// LLMInputParams bundles the sanitized inputs required to build the prompt.
type LLMInputParams struct {
	DecisionStatus    string
	DecisionRationale string
	Counts            LLMCounts
	RecommendedSteps  []string
	Context           LLMContext
	FindingSummaries  []LLMFindingSummary
	TraceEventIDs     []string
	Timestamp         time.Time
}

// LLMSanitizationResult contains the prompt, references, and any redactions performed.
type LLMSanitizationResult struct {
	Prompt     string
	ContentRef string
	References []string
	Redactions []RedactionRecord
}

// RedactionRecord captures metadata for every redaction applied to the LLM input.
type RedactionRecord struct {
	EventID       string
	Timestamp     time.Time
	RedactedField string
	Reason        string
	SanitizedRef  string
	OriginalHash  string
}
