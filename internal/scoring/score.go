package scoring

import (
	"strings"
	"time"
)

type Context struct {
	BranchType      string
	PipelineStage   string
	Environment     string
	RepoCriticality string
	Exposure        string
	ChangeType      string
	ScannerVersion  string
	ArtifactSigned  string
	ProvenanceLevel string
	BuildIntegrity  string
}

type StageThreshold struct {
	WarnFloor  int
	BlockFloor int
}

type TrustBandPenalties struct {
	Trust60to79 int
	Trust40to59 int
	Trust20to39 int
	Trust0to19  int
}

type DomainSeverityBoost struct {
	DomainID  string
	AddPoints int
	Stages    []string
}

type Policy struct {
	ScanFreshnessHours int
	TrustBands         TrustBandPenalties
	SeverityBoosts     []DomainSeverityBoost
}

type Finding struct {
	DetectedAt       string
	Severity         string
	ExploitMaturity  string
	Reachability     string
	Confidence       string
	DomainID         string
	HardStop         bool
	Accepted         bool
	BaselineKnown    bool
	FindingRiskScore int
}

type TrustPenalty struct {
	Code  string
	Value int
}

type TrustResult struct {
	Score       int
	RiskPenalty int
	Penalties   []TrustPenalty
}

type ContextModifier struct {
	Code  string
	Value int
}

type RiskResult struct {
	OverallScore     int
	MaxFindingScore  int
	ContextModifiers []ContextModifier
}

var stageRank = map[string]int{
	"pr":      0,
	"merge":   1,
	"release": 2,
	"deploy":  3,
}

func EffectiveStage(ctx Context) string {
	base := "pr"
	switch normalizeToken(ctx.BranchType) {
	case "main":
		base = "merge"
	case "release":
		base = "release"
	case "dev", "feature":
		base = "pr"
	}
	cand := normalizeToken(ctx.PipelineStage)
	if _, ok := stageRank[cand]; !ok {
		cand = "pr"
	}
	envCand := ""
	if normalizeToken(ctx.Environment) == "prod" {
		envCand = "deploy"
	}
	winner := base
	if stageRank[cand] > stageRank[winner] {
		winner = cand
	}
	if envCand != "" && stageRank[envCand] > stageRank[winner] {
		winner = envCand
	}
	return winner
}

func TrustScore(ctx Context, pol Policy, findings []Finding) TrustResult {
	penalties := []TrustPenalty{}
	add := func(code string, value int) {
		penalties = append(penalties, TrustPenalty{Code: code, Value: value})
	}
	if normalizeToken(ctx.ScannerVersion) == "unknown" || strings.TrimSpace(ctx.ScannerVersion) == "" {
		add("SCANNER_VERSION_UNKNOWN", 15)
	} else if strings.Contains(strings.ToLower(ctx.ScannerVersion), "latest") || strings.Contains(strings.ToLower(ctx.ScannerVersion), "dev") {
		add("SCANNER_VERSION_UNPINNED", 10)
	}

	freshnessHours := pol.ScanFreshnessHours
	if freshnessHours <= 0 {
		freshnessHours = 24
	}
	now := time.Now().UTC()
	cutoffFuture := now.Add(5 * time.Minute)
	var newestDetected time.Time
	hasDetectedAt := false
	for _, f := range findings {
		raw := strings.TrimSpace(f.DetectedAt)
		if normalizeToken(raw) == "unknown" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			continue
		}
		if parsed.After(cutoffFuture) {
			continue
		}
		if !hasDetectedAt || parsed.After(newestDetected) {
			newestDetected = parsed
			hasDetectedAt = true
		}
	}
	if !hasDetectedAt || now.Sub(newestDetected) > time.Duration(freshnessHours)*time.Hour {
		add("SCAN_FRESHNESS_UNKNOWN_OR_STALE", 15)
	}

	signed := normalizeToken(ctx.ArtifactSigned)
	if signed == "no" {
		add("ARTIFACT_UNSIGNED", 20)
	}
	level := normalizeToken(ctx.ProvenanceLevel)
	if level == "unknown" || level == "" {
		add("PROVENANCE_UNKNOWN", 10)
	} else if level == "none" || level == "basic" {
		add("PROVENANCE_BELOW_REQUIRED", 15)
	}
	integrity := normalizeToken(ctx.BuildIntegrity)
	if integrity == "partial" || integrity == "unknown" || integrity == "" {
		add("BUILD_CONTEXT_INTEGRITY_PARTIAL", 10)
	}

	missing := 0
	fields := []string{ctx.BranchType, ctx.PipelineStage, ctx.Environment, ctx.RepoCriticality, ctx.Exposure, ctx.ChangeType}
	for _, f := range fields {
		if normalizeToken(f) == "unknown" || strings.TrimSpace(f) == "" {
			missing++
		}
	}
	if missing > 0 {
		v := missing * 5
		if v > 20 {
			v = 20
		}
		add("MISSING_REQUIRED_CONTEXT_FIELDS", v)
	}
	totalPenalty := 0
	for _, p := range penalties {
		totalPenalty += p.Value
	}
	score := clamp(100-totalPenalty, 0, 100)
	riskPenalty := TrustPenaltyBand(score, pol.TrustBands)
	return TrustResult{
		Score:       score,
		RiskPenalty: riskPenalty,
		Penalties:   penalties,
	}
}

func TrustPenaltyBand(score int, bands TrustBandPenalties) int {
	if bands.Trust60to79 == 0 && bands.Trust40to59 == 0 && bands.Trust20to39 == 0 && bands.Trust0to19 == 0 {
		bands = TrustBandPenalties{Trust60to79: 5, Trust40to59: 10, Trust20to39: 15, Trust0to19: 20}
	}
	switch {
	case score >= 80:
		return 0
	case score >= 60:
		return bands.Trust60to79
	case score >= 40:
		return bands.Trust40to59
	case score >= 20:
		return bands.Trust20to39
	default:
		return bands.Trust0to19
	}
}

func ScoreFinding(f Finding, ctx Context, pol Policy, stage string) int {
	sev := map[string]int{"critical": 70, "high": 50, "medium": 30, "low": 15, "info": 5, "unknown": 35}[normalizeToken(f.Severity)]
	expl := map[string]int{"known_exploited": 20, "poc": 10, "none": 0, "unknown": 8}[normalizeToken(f.ExploitMaturity)]
	reach := map[string]int{"reachable": 10, "potentially_reachable": 5, "not_reachable": 0, "unknown": 4}[normalizeToken(f.Reachability)]
	conf := map[string]int{"high": 0, "medium": -2, "low": -5, "unknown": 2}[normalizeToken(f.Confidence)]
	crit := map[string]int{"mission_critical": 10, "high": 6, "medium": 3, "low": 0, "unknown": 5}[normalizeToken(ctx.RepoCriticality)]
	exp := map[string]int{"internet": 10, "internal": 4, "isolated": 0, "unknown": 6}[normalizeToken(ctx.Exposure)]
	score := clamp(sev+expl+reach+conf+crit+exp, 0, 100)
	for _, b := range pol.SeverityBoosts {
		if strings.EqualFold(b.DomainID, f.DomainID) && contains(b.Stages, stage) && b.AddPoints > 0 {
			score = clamp(score+b.AddPoints, 0, 100)
		}
	}
	return score
}

func AggregateOverall(findings []Finding, ctx Context, stage string, trust TrustResult, ruleRiskPoints int, newFindingsOnly bool) RiskResult {
	maxFinding := 0
	for _, f := range findings {
		if f.HardStop || f.Accepted {
			continue
		}
		if newFindingsOnly && f.BaselineKnown {
			continue
		}
		if f.FindingRiskScore > maxFinding {
			maxFinding = f.FindingRiskScore
		}
	}
	mods := []ContextModifier{}
	change := map[string]int{
		"security_sensitive":    8,
		"infra_or_supply_chain": 6,
		"application":           2,
		"docs_or_tests":         0,
		"unknown":               5,
	}[normalizeToken(ctx.ChangeType)]
	mods = append(mods, ContextModifier{Code: "CHANGE_TYPE", Value: change})
	stageMod := map[string]int{"pr": 0, "merge": 3, "release": 6, "deploy": 10}[stage]
	mods = append(mods, ContextModifier{Code: "STAGE", Value: stageMod})
	mods = append(mods, ContextModifier{Code: "TRUST_PENALTY", Value: trust.RiskPenalty})
	if ruleRiskPoints > 0 {
		mods = append(mods, ContextModifier{Code: "POLICY_RULE_RISK_POINTS", Value: ruleRiskPoints})
	}
	overall := clamp(maxFinding+change+stageMod+trust.RiskPenalty+ruleRiskPoints, 0, 100)
	return RiskResult{OverallScore: overall, MaxFindingScore: maxFinding, ContextModifiers: mods}
}

func normalizeToken(s string) string {
	t := strings.TrimSpace(strings.ToLower(s))
	if t == "" {
		return "unknown"
	}
	return t
}

func contains(values []string, target string) bool {
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}

func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
