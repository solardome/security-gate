package policy

import (
	"github.com/solardome/security-gate/internal/domain"
)

// Policy defines the rule-based configuration that tightens the deterministic engine.
type Policy struct {
	PolicyVersion string      `json:"policy_version"`
	Rules         []Rule      `json:"rules"`
	Exceptions    []Exception `json:"exceptions"`
	RequiresSignedArtifact bool   `json:"requires_signed_artifact,omitempty"`
	RequiresProvenanceLevel string `json:"requires_provenance_level,omitempty"`
}

// Rule represents a deterministic policy rule.
type Rule struct {
	ID          string        `json:"id"`
	Description string        `json:"description"`
	Enabled     *bool         `json:"enabled,omitempty"`
	StageScope  []Stage       `json:"stage_scope"`
	When        RuleCondition `json:"when"`
	Then        RuleAction    `json:"then"`
	Tags        []string      `json:"tags,omitempty"`
}

// RuleCondition enumerates the supported condition keys.
type RuleCondition struct {
	ReleaseRiskGTE *int     `json:"release_risk_gte,omitempty"`
	ReleaseRiskLTE *int     `json:"release_risk_lte,omitempty"`
	TrustScoreGTE  *int     `json:"trust_score_gte,omitempty"`
	TrustScoreLT   *int     `json:"trust_score_lt,omitempty"`
	MaxRiskGTE     *int     `json:"max_finding_risk_gte,omitempty"`
	MaxRiskLTE     *int     `json:"max_finding_risk_lte,omitempty"`
	DomainIn       []string `json:"domain_in,omitempty"`
	SeverityIn     []string `json:"severity_in,omitempty"`
	ChangeTypeIn   []string `json:"change_type_in,omitempty"`
	ExposureIn     []string `json:"exposure_in,omitempty"`
	FixAvailableIn []string `json:"fix_available_in,omitempty"`
	HasHardStop    *bool    `json:"has_hard_stop,omitempty"`
}

// RuleAction defines deterministic tightening actions for matching rules.
type RuleAction struct {
	Decision            domain.DecisionType  `json:"decision,omitempty"`
	WarnToBlock         *bool                `json:"warn_to_block,omitempty"`
	NoiseBudgetTopK     *int                 `json:"noise_budget_top_k,omitempty"`
	AddRequiredSteps    []string             `json:"add_required_steps,omitempty"`
	RequireAcceptedRisk *RequireAcceptedRisk `json:"require_accepted_risk,omitempty"`
}

// RequireAcceptedRisk selects deterministic findings needing an accepted risk.
type RequireAcceptedRisk struct {
	Selector RequireAcceptedRiskSelector `json:"selector"`
	Scope    SelectorScope               `json:"scope,omitempty"`
}

// RequireAcceptedRiskSelector chooses findings from the scoring or considered set.
type RequireAcceptedRiskSelector struct {
	Type string `json:"type"`
	TopN *int   `json:"top_n,omitempty"`
}

// SelectorScope determines whether selectors run before or after PR noise budget.
type SelectorScope string

const (
	ScopeScoringSet    SelectorScope = "scoring_set"
	ScopeConsideredSet SelectorScope = "considered_set"
)

// Exception suppresses false positives deterministically.
type Exception struct {
	ID               string          `json:"id"`
	Description      string          `json:"description"`
	StageScope       []Stage         `json:"stage_scope"`
	EnvironmentScope []string        `json:"environment_scope"`
	FindingSelector  FindingSelector `json:"finding_selector"`
	ExpiresAt        string          `json:"expires_at"`
	Owner            string          `json:"owner"`
	Rationale        string          `json:"rationale"`
}

// AcceptedRisk defines governance-approved risk acceptance.
type AcceptedRisk struct {
	RiskID           string          `json:"risk_id"`
	Title            string          `json:"title"`
	Rationale        string          `json:"rationale"`
	Owner            string          `json:"owner"`
	Ticket           string          `json:"ticket"`
	StageScope       []Stage         `json:"stage_scope"`
	EnvironmentScope []string        `json:"environment_scope"`
	FindingSelector  FindingSelector `json:"finding_selector"`
	Effects          []string        `json:"effects"`
	AllowWarnInProd  bool            `json:"allow_warn_in_prod"`
	Approvals        []Approval      `json:"approvals"`
	CreatedAt        string          `json:"created_at"`
	UpdatedAt        string          `json:"updated_at"`
	ExpiresAt        string          `json:"expires_at"`
	Status           string          `json:"status"`
	Audit            []AuditEvent    `json:"audit,omitempty"`
}

// FindingSelector matches findings deterministically.
type FindingSelector struct {
	Fingerprint      string `json:"fingerprint"`
	Domain           string `json:"domain,omitempty"`
	CVE              string `json:"cve_id,omitempty"`
	TitleContains    string `json:"title_contains,omitempty"`
	LocationContains string `json:"location_contains,omitempty"`
	SourceScanner    string `json:"source_scanner,omitempty"`
	Severity         string `json:"severity,omitempty"`
}

// Approval records approver metadata.
type Approval struct {
	Name       string `json:"name"`
	Role       string `json:"role"`
	ApprovedAt string `json:"approved_at"`
}

// AuditEvent is an optional append-only record on accepted risks.
type AuditEvent struct {
	Timestamp string `json:"timestamp"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Details   string `json:"details,omitempty"`
}
