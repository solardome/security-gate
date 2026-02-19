package securitygate

type noiseBudgetSummary struct {
	Enabled               bool
	Bypassed              bool
	StageSupported        bool
	Stage                 string
	StageLimit            int
	SuppressBelowSeverity string
	TotalFindings         int
	SuppressedBySeverity  int
	SuppressedByLimit     int
	SuppressedTotal       int
	DisplayedCount        int
}

func computeNoiseBudgetSummary(findings []UnifiedFinding, pol Policy, stage string, hardStopTriggered bool) noiseBudgetSummary {
	s := noiseBudgetSummary{
		Enabled:               pol.NoiseBudget.Enabled,
		Stage:                 stage,
		StageLimit:            pol.NoiseBudget.StageLimits[stage],
		SuppressBelowSeverity: normalizeToken(pol.NoiseBudget.SuppressBelowSeverity),
		TotalFindings:         len(findings),
		StageSupported:        stage == "pr" || stage == "merge",
	}
	if s.SuppressBelowSeverity == "unknown" {
		s.SuppressBelowSeverity = "low"
	}
	if hardStopTriggered {
		s.Bypassed = true
		s.DisplayedCount = s.TotalFindings
		return s
	}
	if !s.Enabled || !s.StageSupported {
		s.DisplayedCount = s.TotalFindings
		return s
	}

	eligibleForLimit := 0
	for _, f := range findings {
		if f.HardStop {
			continue
		}
		if shouldSuppressBySeverity(f.Class.Severity, s.SuppressBelowSeverity) {
			s.SuppressedBySeverity++
			continue
		}
		eligibleForLimit++
	}
	if s.StageLimit > 0 && eligibleForLimit > s.StageLimit {
		s.SuppressedByLimit = eligibleForLimit - s.StageLimit
	}
	s.SuppressedTotal = s.SuppressedBySeverity + s.SuppressedByLimit
	s.DisplayedCount = s.TotalFindings - s.SuppressedTotal
	if s.DisplayedCount < 0 {
		s.DisplayedCount = 0
	}
	return s
}

func shouldSuppressBySeverity(severity, suppressBelow string) bool {
	sev := normalizeToken(severity)
	if sev == "unknown" || sev == "critical" || sev == "high" {
		return false
	}
	switch normalizeToken(suppressBelow) {
	case "high":
		return sev == "medium" || sev == "low" || sev == "info"
	case "medium":
		return sev == "low" || sev == "info"
	default:
		return false
	}
}
