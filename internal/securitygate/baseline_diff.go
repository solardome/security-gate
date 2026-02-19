package securitygate

import "strings"

func applyNewFindingsOnlyMode(state *EngineState, cfg Config) bool {
	if !cfg.NewFindingsOnly {
		return false
	}
	if state.EffectiveStage != "pr" && state.EffectiveStage != "merge" {
		state.ValidationErrors = append(state.ValidationErrors, "new findings only mode is supported only for pr/merge stages")
		addTrace(state, "baseline_diff", "validation_error", map[string]interface{}{
			"new_findings_only": true,
			"effective_stage":   state.EffectiveStage,
			"reason":            "unsupported_stage",
		})
		return false
	}

	baselineSet := make(map[string]bool, len(state.BaselineFindings))
	for _, f := range state.BaselineFindings {
		baselineSet[baselineDiffKey(f)] = true
	}

	matched := 0
	newCount := 0
	for i := range state.Findings {
		f := &state.Findings[i]
		if f.HardStop {
			continue
		}
		if baselineSet[baselineDiffKey(*f)] {
			f.BaselineKnown = true
			matched++
		} else {
			newCount++
		}
	}

	addTrace(state, "baseline_diff", "ok", map[string]interface{}{
		"new_findings_only":         true,
		"effective_stage":           state.EffectiveStage,
		"baseline_findings":         len(state.BaselineFindings),
		"current_findings":          len(state.Findings),
		"matched_non_hard_stop":     matched,
		"new_non_hard_stop":         newCount,
		"hard_stop_always_enforced": true,
	})
	return true
}

func baselineDiffKey(f UnifiedFinding) string {
	parts := []string{
		normPart(f.FindingID),
		normPart(f.Scanner.Name),
		normPart(f.Artifact.TargetRef),
		normPart(f.Artifact.Location),
		normPart(f.Class.DomainID),
		normPart(f.Class.Severity),
		normPart(f.Class.CVE),
		normPart(f.Class.Category),
		normPart(f.Evidence.Title),
	}
	return strings.Join(parts, "|")
}

func normPart(v string) string {
	return strings.TrimSpace(strings.ToLower(v))
}
