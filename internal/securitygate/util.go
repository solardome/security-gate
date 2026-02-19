package securitygate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	enginepolicy "github.com/solardome/security-gate/internal/policy"

	"gopkg.in/yaml.v3"
)

func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func normalizeToken(s string) string {
	t := strings.TrimSpace(strings.ToLower(s))
	if t == "" {
		return "unknown"
	}
	return t
}

func canonicalScannerID(raw string) string {
	token := normalizeToken(raw)
	switch {
	case token == "unknown":
		return "unknown"
	case token == "trivy":
		return "trivy"
	case strings.Contains(token, "snyk"):
		return "snyk"
	case strings.Contains(token, "checkmarx"), strings.HasPrefix(token, "cx"):
		return "checkmarx"
	case strings.HasPrefix(token, "sonar"):
		return "sonar"
	case token == "sarif", strings.Contains(token, "sarif"):
		return "sarif"
	default:
		return token
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
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

func severityAtMost(severity, maxSeverity string) bool {
	sr := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
	return sr[normalizeToken(severity)] <= sr[normalizeToken(maxSeverity)]
}

func fileSHA256(path string) (string, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), b, nil
}

func parseYAML(path, kind string, out interface{}) ([]byte, string, error) {
	hash, b, err := fileSHA256(path)
	if err != nil {
		return nil, "", err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, hash, fmt.Errorf("parse %s: %w", path, err)
	}
	schemaErrs := validateYAMLSchema(kind, &root)
	if len(schemaErrs) > 0 {
		return nil, hash, fmt.Errorf("%s", formatSchemaErrors(path, schemaErrs))
	}
	normalized := yamlNodeToValue(root.Content[0])
	j, err := json.Marshal(normalized)
	if err != nil {
		return nil, hash, fmt.Errorf("normalize %s: %w", path, err)
	}
	if err := json.Unmarshal(j, out); err != nil {
		return nil, hash, fmt.Errorf("decode %s: %w", path, err)
	}
	return b, hash, nil
}

func yamlNodeToValue(node *yaml.Node) interface{} {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) == 0 {
			return nil
		}
		return yamlNodeToValue(node.Content[0])
	case yaml.MappingNode:
		m := make(map[string]interface{}, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			k := node.Content[i]
			v := node.Content[i+1]
			m[k.Value] = yamlNodeToValue(v)
		}
		return m
	case yaml.SequenceNode:
		out := make([]interface{}, 0, len(node.Content))
		for _, c := range node.Content {
			out = append(out, yamlNodeToValue(c))
		}
		return out
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!bool":
			return strings.EqualFold(node.Value, "true")
		case "!!int":
			var i int64
			if _, err := fmt.Sscan(node.Value, &i); err == nil {
				return i
			}
			return node.Value
		case "!!float":
			var f float64
			if _, err := fmt.Sscan(node.Value, &f); err == nil {
				return f
			}
			return node.Value
		case "!!null":
			return nil
		default:
			return node.Value
		}
	default:
		return node.Value
	}
}

func stableRunID(inputs []InputDigest, effectiveStage string) string {
	parts := make([]string, 0, len(inputs)+1)
	for _, in := range inputs {
		parts = append(parts, in.Kind+":"+firstNonEmpty(in.Role, "-")+":"+in.Path+":"+in.SHA256)
	}
	parts = append(parts, "stage:"+effectiveStage)
	sort.Strings(parts)
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])
}

func validateContext(c Context) []string {
	var errs []string
	if _, ok := stageRank[normalizeToken(c.PipelineStage)]; !ok {
		errs = append(errs, "invalid pipeline_stage")
	}
	if _, ok := map[string]bool{"dev": true, "feature": true, "main": true, "release": true}[normalizeToken(c.BranchType)]; !ok {
		errs = append(errs, "invalid branch_type")
	}
	if _, ok := map[string]bool{"ci": true, "prod": true}[normalizeToken(c.Environment)]; !ok {
		errs = append(errs, "invalid environment")
	}
	if _, ok := map[string]bool{"low": true, "medium": true, "high": true, "mission_critical": true, "unknown": true}[normalizeToken(c.RepoCriticality)]; !ok {
		errs = append(errs, "invalid repo_criticality")
	}
	if _, ok := map[string]bool{"isolated": true, "internal": true, "internet": true, "unknown": true}[normalizeToken(c.Exposure)]; !ok {
		errs = append(errs, "invalid exposure")
	}
	if _, ok := map[string]bool{"docs_or_tests": true, "application": true, "infra_or_supply_chain": true, "security_sensitive": true, "unknown": true}[normalizeToken(c.ChangeType)]; !ok {
		errs = append(errs, "invalid change_type")
	}
	return errs
}

func validatePolicy(p Policy) []string {
	errs := enginepolicy.ValidatePolicy(enginepolicy.Policy{
		SchemaVersion: p.SchemaVersion,
		Defaults: enginepolicy.PolicyDefaults{
			EnforceOfflineOnly: p.Defaults.EnforceOfflineOnly,
		},
		StageOverrides: enginepolicy.StageOverrides{
			PR:      enginepolicy.StageThreshold{WarnFloor: p.StageOverrides.PR.WarnFloor, BlockFloor: p.StageOverrides.PR.BlockFloor},
			Merge:   enginepolicy.StageThreshold{WarnFloor: p.StageOverrides.Merge.WarnFloor, BlockFloor: p.StageOverrides.Merge.BlockFloor},
			Release: enginepolicy.StageThreshold{WarnFloor: p.StageOverrides.Release.WarnFloor, BlockFloor: p.StageOverrides.Release.BlockFloor},
			Deploy:  enginepolicy.StageThreshold{WarnFloor: p.StageOverrides.Deploy.WarnFloor, BlockFloor: p.StageOverrides.Deploy.BlockFloor},
		},
		Rules: toPolicyRules(p.Rules),
	})
	if p.Defaults.ScanFreshnessHours < 1 || p.Defaults.ScanFreshnessHours > 720 {
		errs = append(errs, "defaults.scan_freshness_hours must be in range 1..720")
	}
	switch normalizeToken(p.Defaults.UnknownSignalMode) {
	case "tighten", "block_release":
	default:
		errs = append(errs, "defaults.unknown_signal_mode must be one of: tighten, block_release")
	}
	switch normalizeToken(p.Defaults.DecisionTraceVerbosity) {
	case "minimal", "normal", "verbose":
	default:
		errs = append(errs, "defaults.decision_trace_verbosity must be one of: minimal, normal, verbose")
	}
	if p.TrustTightening.ReleaseWarnIfTrustBelow < 0 || p.TrustTightening.ReleaseWarnIfTrustBelow > 100 {
		errs = append(errs, "trust_tightening.release_warn_if_trust_below must be in range 0..100")
	}
	if p.TrustTightening.DeployBlockIfTrustBelow < 0 || p.TrustTightening.DeployBlockIfTrustBelow > 100 {
		errs = append(errs, "trust_tightening.deploy_block_if_trust_below must be in range 0..100")
	}
	penalties := p.TrustTightening.AdditionalRiskPenalties
	if penalties.Trust60to79 < 0 || penalties.Trust40to59 < 0 || penalties.Trust20to39 < 0 || penalties.Trust0to19 < 0 {
		errs = append(errs, "trust_tightening.additional_risk_penalties values must be non-negative")
	}
	allowedScopeTypes := map[string]bool{"finding_id": true, "cve": true, "component": true}
	for _, s := range p.ExceptionRules.AllowScopeTypes {
		if !allowedScopeTypes[normalizeToken(s)] {
			errs = append(errs, "exception_rules.allow_scope_types contains unsupported value")
			break
		}
	}
	for _, id := range p.ExceptionRules.SecurityApproverIDs {
		if strings.TrimSpace(id) == "" {
			errs = append(errs, "exception_rules.security_approver_ids cannot contain empty values")
			break
		}
	}
	for _, group := range p.ExceptionRules.SecurityApproverGroups {
		if strings.TrimSpace(group) == "" {
			errs = append(errs, "exception_rules.security_approver_groups cannot contain empty values")
			break
		}
	}
	if (p.ExceptionRules.RequireSecurityApproval.ReleaseCritical || p.ExceptionRules.RequireSecurityApproval.DeployHighOrAbove) &&
		len(p.ExceptionRules.SecurityApproverIDs) == 0 &&
		len(p.ExceptionRules.SecurityApproverGroups) == 0 {
		errs = append(errs, "exception_rules requires security_approver_ids or security_approver_groups when security approval is enforced")
	}
	allowedStages := map[string]bool{"pr": true, "merge": true, "release": true, "deploy": true}
	allowedBranchTypes := map[string]bool{"dev": true, "feature": true, "main": true, "release": true}
	allowedEnvironments := map[string]bool{"ci": true, "prod": true}
	allowedRepoCriticality := map[string]bool{"low": true, "medium": true, "high": true, "mission_critical": true, "unknown": true}
	allowedExposure := map[string]bool{"isolated": true, "internal": true, "internet": true, "unknown": true}
	allowedChangeType := map[string]bool{"docs_or_tests": true, "application": true, "infra_or_supply_chain": true, "security_sensitive": true, "unknown": true}
	allowedSeverity := map[string]bool{"low": true, "medium": true, "high": true}

	for _, k := range sortedStringKeys(p.NoiseBudget.StageLimits) {
		if !map[string]bool{"pr": true, "merge": true}[k] {
			errs = append(errs, "noise_budget.stage_limits supports only pr and merge")
			break
		}
	}
	if !allowedSeverity[normalizeToken(p.NoiseBudget.SuppressBelowSeverity)] {
		errs = append(errs, "noise_budget.suppress_below_severity must be one of: low, medium, high")
	}

	for _, b := range p.DomainOverrides.SeverityBoosts {
		if b.AddPoints < 0 || b.AddPoints > 30 {
			errs = append(errs, "domain_overrides.severity_boosts add_points must be in range 0..30")
		}
		for _, st := range b.Stages {
			if !allowedStages[normalizeToken(st)] {
				errs = append(errs, "domain_overrides.severity_boosts contains invalid stage")
				break
			}
		}
	}

	stepCatalog := recommendedStepCatalog()
	for _, r := range p.Rules {
		if r.Then.AddRiskPoints < 0 || r.Then.AddRiskPoints > 30 {
			errs = append(errs, "rules.then.add_risk_points must be in range 0..30")
		}
		if r.Then.RequireTrustAtLeast < 0 || r.Then.RequireTrustAtLeast > 100 {
			errs = append(errs, "rules.then.require_trust_at_least must be in range 0..100")
		}
		validateEnumList("rules.when.stages", r.When.Stages, allowedStages, &errs)
		validateEnumList("rules.when.branch_types", r.When.BranchTypes, allowedBranchTypes, &errs)
		validateEnumList("rules.when.environments", r.When.Environments, allowedEnvironments, &errs)
		validateEnumList("rules.when.repo_criticality", r.When.RepoCriticality, allowedRepoCriticality, &errs)
		validateEnumList("rules.when.exposure", r.When.Exposure, allowedExposure, &errs)
		validateEnumList("rules.when.change_type", r.When.ChangeType, allowedChangeType, &errs)
		for _, id := range r.Then.AddRecommendedStepIDs {
			if _, ok := stepCatalog[id]; !ok {
				errs = append(errs, "rules.then.add_recommended_step_ids contains unknown step id")
				break
			}
		}
	}
	sort.Strings(errs)
	return errs
}

func defaultPolicy() Policy {
	return Policy{
		SchemaVersion: "1.0",
		PolicyID:      "baseline-v1",
		PolicyName:    "Baseline local gate",
		Defaults: PolicyDefaults{
			EnforceOfflineOnly:     true,
			LLMEnabled:             false,
			ScanFreshnessHours:     24,
			UnknownSignalMode:      "tighten",
			DecisionTraceVerbosity: "normal",
		},
		StageOverrides: StageOverrides{
			PR:      StageThreshold{WarnFloor: 45, BlockFloor: 75},
			Merge:   StageThreshold{WarnFloor: 35, BlockFloor: 65},
			Release: StageThreshold{WarnFloor: 25, BlockFloor: 50},
			Deploy:  StageThreshold{WarnFloor: 15, BlockFloor: 35},
		},
		TrustTightening: TrustTightening{
			Enabled:                 true,
			ReleaseWarnIfTrustBelow: 40,
			DeployBlockIfTrustBelow: 25,
			AdditionalRiskPenalties: TrustBandPenalties{Trust60to79: 5, Trust40to59: 10, Trust20to39: 15, Trust0to19: 20},
		},
		DomainOverrides: DomainOverrides{
			AdditionalHardStops: []string{},
			SeverityBoosts:      []SeverityBoost{},
		},
		Rules: []PolicyRule{},
		NoiseBudget: NoiseBudget{
			Enabled:               true,
			StageLimits:           map[string]int{"pr": 30, "merge": 50},
			SuppressBelowSeverity: "medium",
		},
		ExceptionRules: ExceptionRules{
			RequireSecurityApproval: SecurityApprovalRules{ReleaseCritical: true, DeployHighOrAbove: true},
			AllowScopeTypes:         []string{"finding_id", "cve", "component"},
			SecurityApproverIDs:     []string{"sec-lead"},
			SecurityApproverGroups:  []string{"security"},
		},
	}
}

func validateAcceptedRiskSchema(ar AcceptedRiskSet) error {
	if ar.SchemaVersion == "" {
		return nil
	}
	if ar.SchemaVersion != "1.0" {
		return errors.New("unsupported accepted risk schema_version")
	}
	return nil
}

func addTrace(state *EngineState, phase, result string, details map[string]interface{}) {
	state.Trace = append(state.Trace, TraceEntry{
		Order:   len(state.Trace) + 1,
		Phase:   phase,
		Result:  result,
		Details: details,
	})
}

func sortedStringKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func validateEnumList(field string, values []string, allowed map[string]bool, errs *[]string) {
	for _, v := range values {
		if !allowed[normalizeToken(v)] {
			*errs = append(*errs, field+" contains unsupported value")
			return
		}
	}
}

func shouldBlockReleaseOnUnknownSignals(policy Policy, effectiveStage string) bool {
	return normalizeToken(policy.Defaults.UnknownSignalMode) == "block_release" && (effectiveStage == "release" || effectiveStage == "deploy")
}

func unknownSignalValidationErrors(ctx Context, scanDetectedAt []string) []string {
	var errs []string
	contextSignals := map[string]string{
		"context.branch_type":                        ctx.BranchType,
		"context.pipeline_stage":                     ctx.PipelineStage,
		"context.environment":                        ctx.Environment,
		"context.repo_criticality":                   ctx.RepoCriticality,
		"context.exposure":                           ctx.Exposure,
		"context.change_type":                        ctx.ChangeType,
		"context.scanner.name":                       ctx.Scanner.Name,
		"context.scanner.version":                    ctx.Scanner.Version,
		"context.provenance.artifact_signed":         ctx.Provenance.ArtifactSigned,
		"context.provenance.level":                   ctx.Provenance.Level,
		"context.provenance.build_context_integrity": ctx.Provenance.BuildContextIntegrity,
	}
	for field, v := range contextSignals {
		if normalizeToken(v) == "unknown" {
			errs = append(errs, "unknown signal in "+field)
		}
	}
	now := time.Now().UTC()
	cutoffFuture := now.Add(5 * time.Minute)
	hasKnownDetectedAt := false
	for _, raw := range scanDetectedAt {
		if normalizeToken(raw) == "unknown" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if parsed.After(cutoffFuture) {
			continue
		}
		hasKnownDetectedAt = true
		break
	}
	if !hasKnownDetectedAt {
		errs = append(errs, "unknown signal in scans.detected_at")
	}
	sort.Strings(errs)
	return errs
}
