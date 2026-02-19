package securitygate

import enginescoring "github.com/solardome/security-gate/internal/scoring"

func effectiveStage(ctx Context) string {
	return enginescoring.EffectiveStage(toScoringContext(ctx))
}

func trustScore(ctx Context, pol Policy, findings []UnifiedFinding) TrustResult {
	sf := make([]enginescoring.Finding, 0, len(findings))
	for _, f := range findings {
		sf = append(sf, toScoringFinding(f))
	}
	res := enginescoring.TrustScore(toScoringContext(ctx), toScoringPolicy(pol), sf)
	penalties := make([]TrustPenalty, 0, len(res.Penalties))
	for _, p := range res.Penalties {
		penalties = append(penalties, TrustPenalty{Code: p.Code, Value: p.Value})
	}
	return TrustResult{
		Score:       res.Score,
		RiskPenalty: res.RiskPenalty,
		Penalties:   penalties,
	}
}

func trustPenaltyBand(score int, pol Policy) int {
	return enginescoring.TrustPenaltyBand(score, toScoringPolicy(pol).TrustBands)
}

func scoreFinding(f UnifiedFinding, ctx Context, pol Policy, stage string) int {
	return enginescoring.ScoreFinding(toScoringFinding(f), toScoringContext(ctx), toScoringPolicy(pol), stage)
}

func aggregateOverall(findings []UnifiedFinding, ctx Context, stage string, trust TrustResult, ruleRiskPoints int, newFindingsOnly bool) RiskResult {
	sf := make([]enginescoring.Finding, 0, len(findings))
	for _, f := range findings {
		sf = append(sf, enginescoring.Finding{
			HardStop:         f.HardStop,
			Accepted:         f.Accepted,
			BaselineKnown:    f.BaselineKnown,
			FindingRiskScore: f.FindingRiskScore,
		})
	}
	res := enginescoring.AggregateOverall(
		sf,
		toScoringContext(ctx),
		stage,
		enginescoring.TrustResult{
			Score:       trust.Score,
			RiskPenalty: trust.RiskPenalty,
		},
		ruleRiskPoints,
		newFindingsOnly,
	)
	mods := make([]ContextModifier, 0, len(res.ContextModifiers))
	for _, m := range res.ContextModifiers {
		mods = append(mods, ContextModifier{Code: m.Code, Value: m.Value})
	}
	return RiskResult{
		OverallScore:     res.OverallScore,
		MaxFindingScore:  res.MaxFindingScore,
		ContextModifiers: mods,
	}
}

func toScoringContext(ctx Context) enginescoring.Context {
	return enginescoring.Context{
		BranchType:      ctx.BranchType,
		PipelineStage:   ctx.PipelineStage,
		Environment:     ctx.Environment,
		RepoCriticality: ctx.RepoCriticality,
		Exposure:        ctx.Exposure,
		ChangeType:      ctx.ChangeType,
		ScannerVersion:  ctx.Scanner.Version,
		ArtifactSigned:  ctx.Provenance.ArtifactSigned,
		ProvenanceLevel: ctx.Provenance.Level,
		BuildIntegrity:  ctx.Provenance.BuildContextIntegrity,
	}
}

func toScoringPolicy(pol Policy) enginescoring.Policy {
	boosts := make([]enginescoring.DomainSeverityBoost, 0, len(pol.DomainOverrides.SeverityBoosts))
	for _, b := range pol.DomainOverrides.SeverityBoosts {
		boosts = append(boosts, enginescoring.DomainSeverityBoost{
			DomainID:  b.DomainID,
			AddPoints: b.AddPoints,
			Stages:    append([]string{}, b.Stages...),
		})
	}
	return enginescoring.Policy{
		ScanFreshnessHours: pol.Defaults.ScanFreshnessHours,
		TrustBands: enginescoring.TrustBandPenalties{
			Trust60to79: pol.TrustTightening.AdditionalRiskPenalties.Trust60to79,
			Trust40to59: pol.TrustTightening.AdditionalRiskPenalties.Trust40to59,
			Trust20to39: pol.TrustTightening.AdditionalRiskPenalties.Trust20to39,
			Trust0to19:  pol.TrustTightening.AdditionalRiskPenalties.Trust0to19,
		},
		SeverityBoosts: boosts,
	}
}

func toScoringFinding(f UnifiedFinding) enginescoring.Finding {
	return enginescoring.Finding{
		DetectedAt:       f.DetectedAt,
		Severity:         f.Class.Severity,
		ExploitMaturity:  f.Class.ExploitMaturity,
		Reachability:     f.Class.Reachability,
		Confidence:       f.Class.Confidence,
		DomainID:         f.Class.DomainID,
		HardStop:         f.HardStop,
		Accepted:         f.Accepted,
		BaselineKnown:    f.BaselineKnown,
		FindingRiskScore: f.FindingRiskScore,
	}
}
