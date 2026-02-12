package policy

import (
	"fmt"
	"time"

	"github.com/solardome/security-gate/internal/domain"
	"github.com/solardome/security-gate/internal/llm"
	"github.com/solardome/security-gate/internal/scoring"
)

// PolicyError indicates fatal configuration issues encountered during policy evaluation.
type PolicyError struct {
	Message string
}

func (e PolicyError) Error() string {
	return fmt.Sprintf("policy error: %s", e.Message)
}

// ApplyPolicy orchestrates the evaluation order and produces the final decision artifact.
func Evaluate(input EvaluationInput) (DecisionArtifact, error) {
	if input.Now.IsZero() {
		input.Now = time.Now().UTC()
	}

	stage := input.Stage
	if stage == "" {
		stage = StagePR
	}

	artifact := DecisionArtifact{}
	if events := applyProvenanceHardStops(&input); len(events) > 0 {
		input.ScoreResult.Trace = append(input.ScoreResult.Trace, events...)
	}
	traceEvents := convertTrace(input.ScoreResult.Trace)

	governance := runGovernance(input, stage)
	input.ScoreResult.Findings = append([]scoring.ScoredFinding(nil), governance.allFindings...)
	traceEvents = append(traceEvents, governance.events...)

	noiseBudgetK, noiseRule, err := determineNoiseBudget(input.Policy.Rules, stage)
	if err != nil {
		return artifact, err
	}

	consideredSet, noiseEvent := applyNoiseBudget(stage, governance.scoringSet, noiseBudgetK, noiseRule, input.Now)
	if noiseEvent != nil {
		traceEvents = append(traceEvents, *noiseEvent)
	}

	maxFindingRisk := computeMaxRisk(consideredSet)
	stageMod := stageModifier(stage)
	exposureMod := exposureModifier(input.Exposure)
	changeMod := changeModifier(input.ChangeType)
	trustMod := input.ScoreResult.TrustModifier
	releaseRisk := clamp(maxFindingRisk+stageMod+exposureMod+changeMod+trustMod, 0, 100)

	baseStatus := baseStageDecision(stage, releaseRisk, input.ScoreResult.TrustScore)
	decision := PolicyDecision{Status: baseStatus, ExitCode: decisionExitCode(PolicyDecision{Status: baseStatus}), Rationale: fmt.Sprintf("stage=%s release_risk=%d trust_score=%d", stage, releaseRisk, input.ScoreResult.TrustScore)}

	policyResult, err := applyPolicyRules(decision, input, stage, releaseRisk, maxFindingRisk, consideredSet, governance.scoringSet, governance.coverage, governance.appliedRiskIDs, governance.fingerprintCoverage)
	if err != nil {
		return artifact, err
	}

	policyResult.evaluation.AcceptedRisksApplied = append([]string{}, governance.appliedRiskIDs...)
	policyResult.evaluation.AcceptedRisksCoverage = copyCoverage(governance.coverage)
	policyResult.evaluation.ExceptionsApplied = append([]string{}, governance.exceptionsApplied...)
	policyResult.evaluation.PolicyVersion = input.Policy.PolicyVersion

	traceEvents = append(traceEvents, policyResult.events...)

	prodEvent, allowWarnUsed := applyProdWarnEscalation(&policyResult.decision, stage, governance.scoringSet, governance.allowWarnCoverage, input.Now)
	if prodEvent != nil {
		traceEvents = append(traceEvents, *prodEvent)
	}
	policyResult.evaluation.AllowWarnInProdApplied = allowWarnUsed

	if governance.warnFloor && policyResult.decision.Status == domain.DecisionAllow {
		policyResult.decision.Status = domain.DecisionWarn
		policyResult.decision.ExitCode = 1
		policyResult.decision.Rationale += "; warn floor enforced"
	}

	if governance.expiredWarnFloor && (stage == StagePR || stage == StageMain) && policyResult.decision.Status == domain.DecisionAllow {
		policyResult.decision.Status = domain.DecisionWarn
		policyResult.decision.ExitCode = 1
		policyResult.decision.Rationale += "; expired accepted risk warn floor enforced"
		traceEvents = append(traceEvents, newDecisionTraceEvent("governance.expired_warn_floor", map[string]any{"reason": "expired accepted risk would have covered HIGH/CRITICAL"}, input.Now))
	}

	if governance.expiredEscalation && (stage == StageRelease || stage == StageProd) {
		policyResult.decision.Status = domain.DecisionBlock
		policyResult.decision.ExitCode = 2
		traceEvents = append(traceEvents, newDecisionTraceEvent("governance.expired_escalation", map[string]any{"reason": "expired accepted risk would have covered HIGH/CRITICAL"}, input.Now))
	}

	if hasHardStop(input.ScoreResult.Findings) {
		policyResult.decision.Status = domain.DecisionBlock
		policyResult.decision.ExitCode = 2
		policyResult.decision.Rationale = "hard-stop condition"
	}

	traceEvents = append(traceEvents, newDecisionTraceEvent("decision.final", map[string]any{"status": policyResult.decision.Status, "release_risk": releaseRisk, "trust_score": input.ScoreResult.TrustScore}, input.Now))

	artifact.Inputs = makeDecisionInputs(input)
	artifact.Trust = TrustResult{TrustScore: input.ScoreResult.TrustScore, TrustSignals: input.ScoreResult.TrustSignals, TrustModifier: trustMod}
	artifact.Findings = makeFindingsSummary(governance.allFindings, consideredSet)
	artifact.Scoring = ScoringSummary{ReleaseRisk: releaseRisk, Modifiers: Modifiers{StageModifier: stageMod, ExposureModifier: exposureMod, ChangeModifier: changeMod, TrustModifier: trustMod}}
	artifact.Decision = policyResult.decision
	artifact.Policy = policyResult.evaluation
	artifact.RecommendedSteps = mergeRecommendedSteps(input, policyResult.extraSteps)

	llmCounts := llm.LLMCounts{
		Total:          artifact.Findings.TotalCount,
		HardStop:       artifact.Findings.HardStopCount,
		MaxFindingRisk: maxFindingRisk,
	}
	llmContext := llm.LLMContext{
		Stage:      string(stage),
		Exposure:   input.Exposure,
		ChangeType: input.ChangeType,
	}
	findingSummaries := make([]llm.LLMFindingSummary, 0, len(input.ScoreResult.Findings))
	for _, scored := range input.ScoreResult.Findings {
		findingSummaries = append(findingSummaries, llm.LLMFindingSummary{
			FindingID:   scored.Finding.FindingID,
			Fingerprint: scored.Finding.Fingerprint,
			Title:       scored.Finding.Title,
			Domain:      scored.Finding.Domain,
			Severity:    scored.Finding.Severity,
		})
	}
	traceEventIDs := make([]string, 0, len(traceEvents))
	for _, event := range traceEvents {
		if event.EventID != "" {
			traceEventIDs = append(traceEventIDs, event.EventID)
		}
	}
	sanitized := llm.BuildSanitizedRequest(llm.LLMInputParams{
		DecisionStatus:    string(policyResult.decision.Status),
		DecisionRationale: policyResult.decision.Rationale,
		Counts:            llmCounts,
		RecommendedSteps:  artifact.RecommendedSteps,
		Context:           llmContext,
		FindingSummaries:  findingSummaries,
		TraceEventIDs:     traceEventIDs,
		Timestamp:         input.Now,
	})

	redactionEvents := make([]DecisionTraceRedactionEvent, 0, len(sanitized.Redactions))
	for _, record := range sanitized.Redactions {
		redactionEvents = append(redactionEvents, DecisionTraceRedactionEvent{
			EventID:       record.EventID,
			Timestamp:     record.Timestamp,
			RedactedField: record.RedactedField,
			Reason:        record.Reason,
			SanitizedRef:  record.SanitizedRef,
			OriginalHash:  record.OriginalHash,
		})
	}

	var redactionMeta *DecisionTraceRedaction
	if len(redactionEvents) > 0 {
		redactionMeta = &DecisionTraceRedaction{Events: redactionEvents}
	}

	artifact.LLMExplanation = LLMExplanation{
		Enabled:          input.LLMEnabled,
		NonAuthoritative: true,
		ContentRef:       sanitized.ContentRef,
		SanitizedPrompt:  sanitized.Prompt,
		References:       sanitized.References,
	}
	artifact.Trace = DecisionTrace{
		Events:    traceEvents,
		Redaction: redactionMeta,
	}

	return artifact, nil
}

type policyResult struct {
	decision   PolicyDecision
	evaluation PolicyEvaluation
	events     []DecisionTraceEvent
	extraSteps []string
}
