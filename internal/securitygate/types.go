package securitygate

import "time"

const (
	DecisionAllow = "ALLOW"
	DecisionWarn  = "WARN"
	DecisionBlock = "BLOCK"
)

var stageRank = map[string]int{
	"pr":      0,
	"merge":   1,
	"release": 2,
	"deploy":  3,
}

var severityRank = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
	"unknown":  5,
}

var canonicalHardStops = []string{
	"HS_SECRET_IN_PROD_PATH",
	"HS_ACTIVE_RUNTIME_MALWARE",
	"HS_UNSIGNED_PROD_ARTIFACT",
	"HS_PROVENANCE_TAMPERED",
	"HS_POLICY_INTEGRITY_BROKEN",
	"HS_KNOWN_EXPLOITED_UNPATCHED",
}

type Config struct {
	ScanPaths         []string
	BaselineScanPaths []string
	NewFindingsOnly   bool
	ContextPath       string
	AutoContext       bool
	PolicyPath        string
	AcceptedRiskPath  string
	OutJSONPath       string
	OutHTMLPath       string
	ChecksumsPath     string
	RunLogPath        string
	WriteHTML         bool
}

type Context struct {
	BranchType      string      `json:"branch_type"`
	PipelineStage   string      `json:"pipeline_stage"`
	Environment     string      `json:"environment"`
	RepoCriticality string      `json:"repo_criticality"`
	Exposure        string      `json:"exposure"`
	ChangeType      string      `json:"change_type"`
	Scanner         ScannerMeta `json:"scanner"`
	Provenance      Provenance  `json:"provenance"`
}

type ScannerMeta struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Provenance struct {
	ArtifactSigned        string `json:"artifact_signed"`
	Level                 string `json:"level"`
	BuildContextIntegrity string `json:"build_context_integrity"`
}

type Policy struct {
	SchemaVersion   string          `json:"schema_version"`
	PolicyID        string          `json:"policy_id"`
	PolicyName      string          `json:"policy_name"`
	Defaults        PolicyDefaults  `json:"defaults"`
	StageOverrides  StageOverrides  `json:"stage_overrides"`
	TrustTightening TrustTightening `json:"trust_tightening"`
	DomainOverrides DomainOverrides `json:"domain_overrides"`
	NoiseBudget     NoiseBudget     `json:"noise_budget"`
	ExceptionRules  ExceptionRules  `json:"exception_rules"`
	Rules           []PolicyRule    `json:"rules"`
}

type PolicyDefaults struct {
	EnforceOfflineOnly     bool   `json:"enforce_offline_only"`
	LLMEnabled             bool   `json:"llm_enabled"`
	ScanFreshnessHours     int    `json:"scan_freshness_hours"`
	UnknownSignalMode      string `json:"unknown_signal_mode"`
	DecisionTraceVerbosity string `json:"decision_trace_verbosity"`
}

type StageThreshold struct {
	WarnFloor  int `json:"warn_floor"`
	BlockFloor int `json:"block_floor"`
}

type StageOverrides struct {
	PR      StageThreshold `json:"pr"`
	Merge   StageThreshold `json:"merge"`
	Release StageThreshold `json:"release"`
	Deploy  StageThreshold `json:"deploy"`
}

type TrustTightening struct {
	Enabled                 bool               `json:"enabled"`
	ReleaseWarnIfTrustBelow int                `json:"release_warn_if_trust_below"`
	DeployBlockIfTrustBelow int                `json:"deploy_block_if_trust_below"`
	AdditionalRiskPenalties TrustBandPenalties `json:"additional_risk_penalties"`
}

type TrustBandPenalties struct {
	Trust60to79 int `json:"trust_60_79"`
	Trust40to59 int `json:"trust_40_59"`
	Trust20to39 int `json:"trust_20_39"`
	Trust0to19  int `json:"trust_0_19"`
}

type DomainOverrides struct {
	AdditionalHardStops []string        `json:"additional_hard_stops"`
	SeverityBoosts      []SeverityBoost `json:"severity_boosts"`
}

type SeverityBoost struct {
	DomainID  string   `json:"domain_id"`
	AddPoints int      `json:"add_points"`
	Stages    []string `json:"stages"`
}

type NoiseBudget struct {
	Enabled               bool           `json:"enabled"`
	StageLimits           map[string]int `json:"stage_limits"`
	SuppressBelowSeverity string         `json:"suppress_below_severity"`
}

type ExceptionRules struct {
	RequireSecurityApproval SecurityApprovalRules `json:"require_security_approval"`
	AllowScopeTypes         []string              `json:"allow_scope_types"`
	SecurityApproverIDs     []string              `json:"security_approver_ids"`
	SecurityApproverGroups  []string              `json:"security_approver_groups"`
}

type SecurityApprovalRules struct {
	ReleaseCritical   bool `json:"release_critical"`
	DeployHighOrAbove bool `json:"deploy_high_or_above"`
}

type PolicyRule struct {
	RuleID  string   `json:"rule_id"`
	Enabled bool     `json:"enabled"`
	When    RuleWhen `json:"when"`
	Then    RuleThen `json:"then"`
}

type RuleWhen struct {
	Stages          []string `json:"stages"`
	BranchTypes     []string `json:"branch_types"`
	Environments    []string `json:"environments"`
	RepoCriticality []string `json:"repo_criticality"`
	Exposure        []string `json:"exposure"`
	ChangeType      []string `json:"change_type"`
}

type RuleThen struct {
	AddRiskPoints         int      `json:"add_risk_points"`
	MinDecision           string   `json:"min_decision"`
	RequireTrustAtLeast   int      `json:"require_trust_at_least"`
	AddRecommendedStepIDs []string `json:"add_recommended_step_ids"`
}

type AcceptedRiskSet struct {
	SchemaVersion string               `json:"schema_version"`
	Records       []AcceptedRiskRecord `json:"records"`
}

type AcceptedRiskRecord struct {
	ID          string                  `json:"id"`
	Status      string                  `json:"status"`
	Owner       string                  `json:"owner"`
	Approvers   []string                `json:"approvers"`
	Ticket      string                  `json:"ticket"`
	Rationale   string                  `json:"rationale"`
	Scope       AcceptedRiskScope       `json:"scope"`
	Constraints AcceptedRiskConstraints `json:"constraints"`
	Timeline    AcceptedRiskTimeline    `json:"timeline"`
	Metadata    map[string]string       `json:"metadata"`
}

type AcceptedRiskScope struct {
	Type        string   `json:"type"`
	Value       string   `json:"value"`
	Scanner     string   `json:"scanner"`
	Repository  string   `json:"repository"`
	BranchTypes []string `json:"branch_types"`
	Stages      []string `json:"stages"`
}

type AcceptedRiskConstraints struct {
	MaxSeverity  string   `json:"max_severity"`
	Environments []string `json:"environments"`
}

type AcceptedRiskTimeline struct {
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	SLADays   int    `json:"sla_days"`
}

type AdapterFinding struct {
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

type UnifiedFinding struct {
	FindingID            string
	Scanner              ScannerMeta
	Artifact             UnifiedArtifact
	Class                UnifiedClassification
	Evidence             UnifiedEvidence
	DetectedAt           string
	Raw                  UnifiedRaw
	HardStop             bool
	Accepted             bool
	AcceptedRiskRecordID string
	BaselineKnown        bool
	FindingRiskScore     int
}

type UnifiedArtifact struct {
	TargetRef string
	Component string
	Location  string
}

type UnifiedClassification struct {
	Category        string
	DomainID        string
	CVE             string
	CWE             string
	Severity        string
	Confidence      string
	ExploitMaturity string
	Reachability    string
}

type UnifiedEvidence struct {
	Title       string
	Description string
	References  []string
}

type UnifiedRaw struct {
	SourceFile  string
	SourceIndex int
}

type EngineState struct {
	InputDigests       []InputDigest
	Context            Context
	Policy             Policy
	AcceptedRisk       AcceptedRiskSet
	Findings           []UnifiedFinding
	BaselineFindings   []UnifiedFinding
	ScanDetectedAt     []string
	EffectiveStage     string
	ValidationFailed   bool
	ValidationErrors   []string
	ValidationWarnings []string
	HardStopDomains    []string
	Trust              TrustResult
	Risk               RiskResult
	Decision           string
	ExitCode           int
	RecommendedSteps   []RecommendedStep
	Trace              []TraceEntry
	GovernanceSummary  GovernanceSummary
	Now                time.Time
}

type InputDigest struct {
	Kind   string `json:"kind"`
	Role   string `json:"role,omitempty"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	ReadOK bool   `json:"read_ok"`
}

type TrustPenalty struct {
	Code  string `json:"code"`
	Value int    `json:"value"`
}

type TrustResult struct {
	Score       int            `json:"score"`
	RiskPenalty int            `json:"risk_penalty"`
	Penalties   []TrustPenalty `json:"penalties"`
}

type ContextModifier struct {
	Code  string `json:"code"`
	Value int    `json:"value"`
}

type RiskResult struct {
	OverallScore     int               `json:"overall_score"`
	MaxFindingScore  int               `json:"max_finding_score"`
	ContextModifiers []ContextModifier `json:"context_modifiers"`
}

type GovernanceSummary struct {
	RecordsEvaluated int  `json:"records_evaluated"`
	RecordsApplied   int  `json:"records_applied"`
	InvalidRecords   int  `json:"invalid_records"`
	NearExpiry       bool `json:"-"`
	ApprovalUnmet    bool `json:"-"`
}

type RecommendedStep struct {
	ID       string `json:"id"`
	Priority int    `json:"priority"`
	Text     string `json:"text"`
}

type TraceEntry struct {
	Order   int                    `json:"order"`
	Phase   string                 `json:"phase"`
	Result  string                 `json:"result"`
	Details map[string]interface{} `json:"details,omitempty"`
}

type Report struct {
	SchemaVersion    string            `json:"schema_version"`
	GeneratedAt      string            `json:"generated_at"`
	RunID            string            `json:"run_id"`
	Inputs           []InputDigest     `json:"inputs"`
	Context          Context           `json:"context"`
	EffectiveStage   string            `json:"effective_stage"`
	Trust            TrustResult       `json:"trust"`
	Risk             RiskResult        `json:"risk"`
	HardStop         HardStopResult    `json:"hard_stop"`
	Decision         string            `json:"decision"`
	ExitCode         int               `json:"exit_code"`
	Findings         []ReportFinding   `json:"findings"`
	AcceptedRisk     GovernanceSummary `json:"accepted_risk"`
	RecommendedSteps []RecommendedStep `json:"recommended_next_steps"`
	DecisionTrace    []TraceEntry      `json:"decision_trace"`
	NonAuthoritative NonAuthoritative  `json:"non_authoritative"`
}

type HardStopResult struct {
	Triggered bool     `json:"triggered"`
	Domains   []string `json:"domains"`
}

type ReportFinding struct {
	FindingID        string `json:"finding_id"`
	DomainID         string `json:"domain_id"`
	Severity         string `json:"severity"`
	HardStop         bool   `json:"hard_stop"`
	Accepted         bool   `json:"accepted"`
	FindingRiskScore int    `json:"finding_risk_score"`
	SourceFile       string `json:"source_file"`
	SourceIndex      int    `json:"source_index"`
}

type NonAuthoritative struct {
	LLMEnabled bool   `json:"llm_enabled"`
	LLMText    string `json:"llm_text"`
}
