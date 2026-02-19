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
	enginereport "github.com/solardome/security-gate/internal/report"
)

func Run(cfg Config) (Report, error) {
	if strings.TrimSpace(cfg.OutJSONPath) == "" {
		cfg.OutJSONPath = "report.json"
	}
	if strings.TrimSpace(cfg.OutHTMLPath) == "" {
		cfg.OutHTMLPath = "report.html"
	}
	if strings.TrimSpace(cfg.ChecksumsPath) == "" {
		cfg.ChecksumsPath = DefaultChecksumsPath(cfg.OutJSONPath)
	}
	if strings.TrimSpace(cfg.RunLogPath) == "" {
		cfg.RunLogPath = DefaultRunLogPath(cfg.OutJSONPath)
	}

	log, logErr := newAuditLogger(cfg.RunLogPath)
	if logErr == nil {
		defer log.close()
		log.info("run.start", map[string]interface{}{
			"scan_count":          len(cfg.ScanPaths),
			"baseline_scan_count": len(cfg.BaselineScanPaths),
			"new_findings_only":   cfg.NewFindingsOnly,
			"context_path":        cfg.ContextPath,
			"context_auto":        cfg.AutoContext,
			"policy_path":         cfg.PolicyPath,
			"accepted_risk_path":  cfg.AcceptedRiskPath,
			"out_json":            cfg.OutJSONPath,
			"out_html":            cfg.OutHTMLPath,
			"checksums":           cfg.ChecksumsPath,
		})
	}

	state := EngineState{Now: time.Now().UTC()}
	if err := loadInputs(&state, cfg); err != nil {
		if log != nil {
			log.warn("run.load_inputs.error", map[string]interface{}{"error": err.Error()})
		}
		return Report{}, err
	}
	if log != nil {
		log.info("run.load_inputs.ok", map[string]interface{}{
			"input_count":         len(state.InputDigests),
			"validation_warnings": len(state.ValidationWarnings),
			"validation_errors":   len(state.ValidationErrors),
			"normalized_findings": len(state.Findings),
		})
	}

	state.EffectiveStage = effectiveStage(state.Context)
	addTrace(&state, "stage_mapping", "ok", map[string]interface{}{
		"branch_type":     state.Context.BranchType,
		"pipeline_stage":  state.Context.PipelineStage,
		"environment":     state.Context.Environment,
		"effective_stage": state.EffectiveStage,
	})
	if log != nil {
		log.info("run.stage_mapping.ok", map[string]interface{}{"effective_stage": state.EffectiveStage})
	}
	if shouldBlockReleaseOnUnknownSignals(state.Policy, state.EffectiveStage) {
		unknownErrs := unknownSignalValidationErrors(state.Context, state.ScanDetectedAt)
		if len(unknownErrs) > 0 {
			state.ValidationErrors = append(state.ValidationErrors, unknownErrs...)
			addTrace(&state, "unknown_signal_mode", "validation_error", map[string]interface{}{
				"mode":   state.Policy.Defaults.UnknownSignalMode,
				"errors": append([]string{}, unknownErrs...),
			})
		}
	}

	hardStops := applyHardStops(state.Findings, state.Policy)
	state.HardStopDomains = hardStops
	addTrace(&state, "hard_stop", "ok", map[string]interface{}{
		"triggered": len(hardStops) > 0,
		"domains":   hardStops,
	})

	if err := validateAcceptedRiskSchema(state.AcceptedRisk); err != nil {
		state.ValidationErrors = append(state.ValidationErrors, err.Error())
	}
	applyAcceptedRisk(&state)
	addTrace(&state, "governance", "ok", map[string]interface{}{
		"records_evaluated": state.GovernanceSummary.RecordsEvaluated,
		"records_applied":   state.GovernanceSummary.RecordsApplied,
		"invalid_records":   state.GovernanceSummary.InvalidRecords,
	})
	newFindingsOnlyActive := applyNewFindingsOnlyMode(&state, cfg)

	ruleRisk, minDecision, trustFloor, ruleStepIDs := applyPolicyRules(state.Policy, state.Context, state.EffectiveStage)

	state.Trust = trustScore(state.Context, state.Policy, state.Findings)
	for i := range state.Findings {
		state.Findings[i].FindingRiskScore = scoreFinding(state.Findings[i], state.Context, state.Policy, state.EffectiveStage)
	}
	state.Risk = aggregateOverall(state.Findings, state.Context, state.EffectiveStage, state.Trust, ruleRisk, newFindingsOnlyActive)
	addTrace(&state, "scoring", "ok", map[string]interface{}{
		"trust_score":              state.Trust.Score,
		"trust_penalty":            state.Trust.RiskPenalty,
		"overall_risk_score":       state.Risk.OverallScore,
		"new_findings_only_active": newFindingsOnlyActive,
	})
	noiseSummary := computeNoiseBudgetSummary(state.Findings, state.Policy, state.EffectiveStage, len(state.HardStopDomains) > 0)
	addTrace(&state, "noise_budget", noiseBudgetTraceResult(noiseSummary), map[string]interface{}{
		"enabled":                 noiseSummary.Enabled,
		"bypassed":                noiseSummary.Bypassed,
		"stage_supported":         noiseSummary.StageSupported,
		"stage":                   noiseSummary.Stage,
		"stage_limit":             noiseSummary.StageLimit,
		"suppress_below_severity": noiseSummary.SuppressBelowSeverity,
		"total_findings":          noiseSummary.TotalFindings,
		"suppressed_by_severity":  noiseSummary.SuppressedBySeverity,
		"suppressed_by_limit":     noiseSummary.SuppressedByLimit,
		"suppressed_total":        noiseSummary.SuppressedTotal,
		"displayed_count":         noiseSummary.DisplayedCount,
	})

	for _, errMsg := range state.ValidationErrors {
		if errMsg != "" {
			state.ValidationFailed = true
		}
	}
	state.Decision = decide(&state, minDecision, trustFloor)
	state.ExitCode = decisionExitCode(state.Decision)

	steps := collectRecommendedSteps(state, ruleStepIDs)
	state.RecommendedSteps = steps

	sortFindingsDeterministically(state.Findings)
	runID := stableRunID(state.InputDigests, state.EffectiveStage)
	report := buildReport(state, runID)

	if err := writeReportJSON(cfg.OutJSONPath, report); err != nil {
		if log != nil {
			log.warn("run.report_json.error", map[string]interface{}{"error": err.Error()})
		}
		return Report{}, err
	}
	artifactPaths := []string{cfg.OutJSONPath}
	htmlWritten := false
	if cfg.WriteHTML {
		if err := writeReportHTML(cfg.OutHTMLPath, report); err != nil {
			addTrace(&state, "report_html", "error", map[string]interface{}{"error": err.Error()})
			if log != nil {
				log.warn("run.report_html.error", map[string]interface{}{"error": err.Error(), "path": cfg.OutHTMLPath})
			}
		} else {
			htmlWritten = true
			artifactPaths = append(artifactPaths, cfg.OutHTMLPath)
		}
	}
	if err := writeArtifactChecksums(cfg.ChecksumsPath, artifactPaths); err != nil {
		if log != nil {
			log.warn("run.checksums.error", map[string]interface{}{"error": err.Error()})
		}
		return Report{}, err
	}
	if log != nil {
		log.info("run.complete", map[string]interface{}{
			"decision":        report.Decision,
			"exit_code":       report.ExitCode,
			"overall_risk":    report.Risk.OverallScore,
			"trust_score":     report.Trust.Score,
			"effective_stage": report.EffectiveStage,
			"report_json":     cfg.OutJSONPath,
			"report_html":     cfg.OutHTMLPath,
			"html_written":    htmlWritten,
			"checksums":       cfg.ChecksumsPath,
		})
	}
	return report, nil
}

func loadInputs(state *EngineState, cfg Config) error {
	if len(cfg.ScanPaths) == 0 {
		return errors.New("at least one --scan path is required")
	}
	if cfg.PolicyPath == "" {
		return errors.New("--policy is required")
	}
	if cfg.ContextPath == "" && !cfg.AutoContext {
		return errors.New("--context is required unless --context-auto is enabled")
	}
	if cfg.NewFindingsOnly && len(cfg.BaselineScanPaths) == 0 {
		return errors.New("--new-findings-only requires at least one --baseline-scan")
	}

	state.Policy = defaultPolicy()

	if err := loadPolicy(state, cfg.PolicyPath); err != nil {
		state.ValidationErrors = append(state.ValidationErrors, err.Error())
	}
	if cfg.ContextPath != "" {
		if err := loadContext(state, cfg.ContextPath); err != nil {
			state.ValidationErrors = append(state.ValidationErrors, err.Error())
		}
	} else {
		if err := loadContextAuto(state); err != nil {
			state.ValidationErrors = append(state.ValidationErrors, err.Error())
		}
	}
	if cfg.AcceptedRiskPath != "" {
		if err := loadAcceptedRisk(state, cfg.AcceptedRiskPath); err != nil {
			state.ValidationErrors = append(state.ValidationErrors, err.Error())
		}
	}
	if err := loadScans(state, cfg.ScanPaths); err != nil {
		state.ValidationErrors = append(state.ValidationErrors, err.Error())
	}
	if cfg.NewFindingsOnly {
		if err := loadBaselineScans(state, cfg.BaselineScanPaths); err != nil {
			state.ValidationErrors = append(state.ValidationErrors, err.Error())
		}
	}

	ctxErrors := validateContext(state.Context)
	state.ValidationErrors = append(state.ValidationErrors, ctxErrors...)
	polErrors := validatePolicy(state.Policy)
	state.ValidationErrors = append(state.ValidationErrors, polErrors...)

	addTrace(state, "input_validation", inputValidationTraceResult(state), map[string]interface{}{
		"input_count":   len(state.InputDigests),
		"error_count":   len(state.ValidationErrors),
		"warning_count": len(state.ValidationWarnings),
		"errors":        append([]string{}, state.ValidationErrors...),
		"warnings":      append([]string{}, state.ValidationWarnings...),
	})
	return nil
}

func inputValidationTraceResult(state *EngineState) string {
	if len(state.ValidationErrors) > 0 {
		return "validation_error"
	}
	if len(state.ValidationWarnings) > 0 {
		return "validation_warn"
	}
	return "validation_ok"
}

func loadPolicy(state *EngineState, path string) error {
	var pol Policy
	_, hash, err := parseYAML(path, "policy", &pol)
	state.InputDigests = append(state.InputDigests, InputDigest{Kind: "policy_yaml", Path: path, SHA256: hash, ReadOK: err == nil})
	if err != nil {
		return fmt.Errorf("policy load failed: %w", err)
	}
	state.Policy = pol
	return nil
}

func loadContext(state *EngineState, path string) error {
	var ctx Context
	_, hash, err := parseYAML(path, "context", &ctx)
	state.InputDigests = append(state.InputDigests, InputDigest{Kind: "context_yaml", Path: path, SHA256: hash, ReadOK: err == nil})
	if err != nil {
		return fmt.Errorf("context load failed: %w", err)
	}
	state.Context = ctx
	return nil
}

func loadAcceptedRisk(state *EngineState, path string) error {
	var ar AcceptedRiskSet
	_, hash, err := parseYAML(path, "accepted_risk", &ar)
	state.InputDigests = append(state.InputDigests, InputDigest{Kind: "accepted_risk_yaml", Path: path, SHA256: hash, ReadOK: err == nil})
	if err != nil {
		return fmt.Errorf("accepted risk load failed: %w", err)
	}
	state.AcceptedRisk = ar
	return nil
}

func loadContextAuto(state *EngineState) error {
	ctx, source := autoDetectContextFromEnv(os.LookupEnv)
	state.Context = ctx
	digestPayload, err := json.Marshal(struct {
		Source  string  `json:"source"`
		Context Context `json:"context"`
	}{
		Source:  source,
		Context: ctx,
	})
	if err != nil {
		return fmt.Errorf("context auto-detect marshal failed: %w", err)
	}
	sum := sha256.Sum256(digestPayload)
	state.InputDigests = append(state.InputDigests, InputDigest{
		Kind:   "context_yaml",
		Path:   "env://context-auto/" + source,
		SHA256: hex.EncodeToString(sum[:]),
		ReadOK: true,
	})
	return nil
}

func loadScans(state *EngineState, paths []string) error {
	all := []AdapterFinding{}
	for _, p := range paths {
		hash, b, err := fileSHA256(p)
		state.InputDigests = append(state.InputDigests, InputDigest{Kind: "scan_json", Role: "primary", Path: p, SHA256: hash, ReadOK: err == nil})
		if err != nil {
			return fmt.Errorf("scan file unreadable %s: %w", p, err)
		}
		scannerName := firstNonEmpty(state.Context.Scanner.Name, "trivy")
		scannerVersion := firstNonEmpty(state.Context.Scanner.Version, "unknown")
		findings, detectedAt, err := parseScan(p, b, scannerName, scannerVersion)
		if err != nil {
			return fmt.Errorf("scan parse failed %s: %w", p, err)
		}
		state.ScanDetectedAt = append(state.ScanDetectedAt, detectedAt)
		all = append(all, findings...)
	}
	state.Findings = normalizeFindings(all)
	return nil
}

func loadBaselineScans(state *EngineState, paths []string) error {
	all := []AdapterFinding{}
	for _, p := range paths {
		hash, b, err := fileSHA256(p)
		state.InputDigests = append(state.InputDigests, InputDigest{Kind: "scan_json", Role: "baseline", Path: p, SHA256: hash, ReadOK: err == nil})
		if err != nil {
			return fmt.Errorf("baseline scan file unreadable %s: %w", p, err)
		}
		scannerName := firstNonEmpty(state.Context.Scanner.Name, "trivy")
		scannerVersion := firstNonEmpty(state.Context.Scanner.Version, "unknown")
		findings, _, err := parseScan(p, b, scannerName, scannerVersion)
		if err != nil {
			return fmt.Errorf("baseline scan parse failed %s: %w", p, err)
		}
		all = append(all, findings...)
	}
	state.BaselineFindings = normalizeFindings(all)
	return nil
}

func decide(state *EngineState, ruleMinDecision string, ruleTrustFloor int) string {
	stage := state.EffectiveStage
	if len(state.HardStopDomains) > 0 {
		addTrace(state, "decision", "hard_stop_block", nil)
		return DecisionBlock
	}
	if state.ValidationFailed {
		if stage == "release" || stage == "deploy" {
			addTrace(state, "decision", "validation_block", nil)
			return DecisionBlock
		}
		addTrace(state, "decision", "validation_warn", nil)
		return DecisionWarn
	}

	th := stateThresholds(state.Policy, stage)
	decision := DecisionAllow
	if state.Risk.OverallScore >= th.BlockFloor {
		decision = DecisionBlock
	} else if state.Risk.OverallScore >= th.WarnFloor {
		decision = DecisionWarn
	}

	releaseWarnFloor := firstIntNonZero(state.Policy.TrustTightening.ReleaseWarnIfTrustBelow, 40)
	deployBlockFloor := firstIntNonZero(state.Policy.TrustTightening.DeployBlockIfTrustBelow, 25)
	if (stage == "release" || stage == "deploy") && state.Trust.Score < releaseWarnFloor && decision == DecisionAllow {
		decision = DecisionWarn
	}
	if stage == "deploy" && state.Trust.Score < deployBlockFloor {
		decision = DecisionBlock
	}
	if ruleTrustFloor > 0 && state.Trust.Score < ruleTrustFloor && decision == DecisionAllow {
		decision = DecisionWarn
	}
	decision = tighterDecision(decision, ruleMinDecision)

	addTrace(state, "decision", "matrix", map[string]interface{}{
		"overall_risk": state.Risk.OverallScore,
		"warn_floor":   th.WarnFloor,
		"block_floor":  th.BlockFloor,
		"decision":     decision,
	})
	return decision
}

func stateThresholds(pol Policy, stage string) StageThreshold {
	switch stage {
	case "pr":
		return pol.StageOverrides.PR
	case "merge":
		return pol.StageOverrides.Merge
	case "release":
		return pol.StageOverrides.Release
	default:
		return pol.StageOverrides.Deploy
	}
}

func decisionExitCode(decision string) int {
	switch decision {
	case DecisionAllow:
		return 0
	case DecisionWarn:
		return 1
	default:
		return 2
	}
}

func tighterDecision(current, candidate string) string {
	rank := map[string]int{DecisionAllow: 0, DecisionWarn: 1, DecisionBlock: 2}
	if rank[candidate] > rank[current] {
		return candidate
	}
	return current
}

func applyPolicyRules(pol Policy, ctx Context, stage string) (int, string, int, []string) {
	return enginepolicy.ApplyRules(enginepolicy.Policy{
		Rules: toPolicyRules(pol.Rules),
	}, enginepolicy.Context{
		BranchType:      ctx.BranchType,
		Environment:     ctx.Environment,
		RepoCriticality: ctx.RepoCriticality,
		Exposure:        ctx.Exposure,
		ChangeType:      ctx.ChangeType,
	}, stage)
}

func toPolicyRules(in []PolicyRule) []enginepolicy.Rule {
	out := make([]enginepolicy.Rule, 0, len(in))
	for _, r := range in {
		out = append(out, enginepolicy.Rule{
			RuleID:  r.RuleID,
			Enabled: r.Enabled,
			When: enginepolicy.RuleWhen{
				Stages:          append([]string{}, r.When.Stages...),
				BranchTypes:     append([]string{}, r.When.BranchTypes...),
				Environments:    append([]string{}, r.When.Environments...),
				RepoCriticality: append([]string{}, r.When.RepoCriticality...),
				Exposure:        append([]string{}, r.When.Exposure...),
				ChangeType:      append([]string{}, r.When.ChangeType...),
			},
			Then: enginepolicy.RuleThen{
				AddRiskPoints:         r.Then.AddRiskPoints,
				MinDecision:           r.Then.MinDecision,
				RequireTrustAtLeast:   r.Then.RequireTrustAtLeast,
				AddRecommendedStepIDs: append([]string{}, r.Then.AddRecommendedStepIDs...),
			},
		})
	}
	return out
}

func collectRecommendedSteps(state EngineState, ruleStepIDs []string) []RecommendedStep {
	catalog := recommendedStepCatalog()
	set := map[string]bool{}
	if len(state.HardStopDomains) > 0 {
		set["FIX_HARD_STOP_IMMEDIATELY"] = true
	}
	for _, p := range state.Trust.Penalties {
		if p.Code == "ARTIFACT_UNSIGNED" {
			set["RESTORE_ARTIFACT_SIGNING"] = true
		}
		if p.Code == "SCAN_FRESHNESS_UNKNOWN_OR_STALE" {
			set["REFRESH_SCANS"] = true
		}
		if p.Code == "MISSING_REQUIRED_CONTEXT_FIELDS" {
			set["COMPLETE_MISSING_CONTEXT"] = true
		}
	}
	if state.Risk.OverallScore >= stateThresholds(state.Policy, state.EffectiveStage).WarnFloor {
		set["REMEDIATE_TOP_FINDING"] = true
	}
	if state.GovernanceSummary.NearExpiry {
		set["REVIEW_ACCEPTED_RISK_EXPIRY"] = true
	}
	if state.GovernanceSummary.ApprovalUnmet {
		set["SECURITY_APPROVAL_REQUIRED"] = true
	}
	for _, e := range state.ValidationErrors {
		if strings.Contains(strings.ToLower(e), "policy") {
			set["VALIDATE_POLICY_FILE"] = true
		}
		if strings.Contains(strings.ToLower(e), "accepted risk") {
			set["VALIDATE_ACCEPTED_RISK_FILE"] = true
		}
	}
	for _, s := range ruleStepIDs {
		set[s] = true
	}

	steps := make([]RecommendedStep, 0, len(set))
	for id := range set {
		if c, ok := catalog[id]; ok {
			steps = append(steps, c)
		}
	}
	sort.Slice(steps, func(i, j int) bool {
		if steps[i].Priority != steps[j].Priority {
			return steps[i].Priority < steps[j].Priority
		}
		return steps[i].ID < steps[j].ID
	})
	return steps
}

func buildReport(state EngineState, runID string) Report {
	findings := make([]ReportFinding, 0, len(state.Findings))
	for _, f := range state.Findings {
		findings = append(findings, ReportFinding{
			FindingID:        f.FindingID,
			DomainID:         f.Class.DomainID,
			Severity:         f.Class.Severity,
			HardStop:         f.HardStop,
			Accepted:         f.Accepted,
			FindingRiskScore: f.FindingRiskScore,
			SourceFile:       f.Raw.SourceFile,
			SourceIndex:      f.Raw.SourceIndex,
		})
	}
	report := Report{
		SchemaVersion:  "1.0.0",
		GeneratedAt:    "1970-01-01T00:00:00Z",
		RunID:          runID,
		Inputs:         state.InputDigests,
		Context:        state.Context,
		EffectiveStage: state.EffectiveStage,
		Trust:          state.Trust,
		Risk:           state.Risk,
		HardStop: HardStopResult{
			Triggered: len(state.HardStopDomains) > 0,
			Domains:   state.HardStopDomains,
		},
		Decision:         state.Decision,
		ExitCode:         state.ExitCode,
		Findings:         findings,
		AcceptedRisk:     state.GovernanceSummary,
		RecommendedSteps: state.RecommendedSteps,
		DecisionTrace:    applyTraceVerbosity(state.Trace, state.Policy.Defaults.DecisionTraceVerbosity),
		NonAuthoritative: NonAuthoritative{
			LLMEnabled: state.Policy.Defaults.LLMEnabled,
			LLMText:    "",
		},
	}
	return report
}

func writeReportJSON(path string, report Report) error {
	return enginereport.WriteJSON(path, report)
}

func firstIntNonZero(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

func applyTraceVerbosity(trace []TraceEntry, verbosity string) []TraceEntry {
	out := make([]TraceEntry, 0, len(trace))
	mode := normalizeToken(verbosity)
	for _, t := range trace {
		entry := t
		if mode == "minimal" {
			entry.Details = nil
		}
		out = append(out, entry)
	}
	return out
}

func noiseBudgetTraceResult(s noiseBudgetSummary) string {
	if s.Bypassed {
		return "bypassed"
	}
	if !s.Enabled {
		return "disabled"
	}
	if !s.StageSupported {
		return "not_applicable"
	}
	return "presentation_only"
}
