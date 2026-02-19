package securitygate

func recommendedStepCatalog() map[string]RecommendedStep {
	return map[string]RecommendedStep{
		"FIX_HARD_STOP_IMMEDIATELY": {
			ID:       "FIX_HARD_STOP_IMMEDIATELY",
			Priority: 100,
			Text:     "Remove or remediate all hard-stop findings before rerun.",
		},
		"RESTORE_ARTIFACT_SIGNING": {
			ID:       "RESTORE_ARTIFACT_SIGNING",
			Priority: 20,
			Text:     "Rebuild and sign artifact with approved local signing workflow.",
		},
		"REFRESH_SCANS": {
			ID:       "REFRESH_SCANS",
			Priority: 300,
			Text:     "Re-run scanners and provide fresh local JSON artifacts.",
		},
		"COMPLETE_MISSING_CONTEXT": {
			ID:       "COMPLETE_MISSING_CONTEXT",
			Priority: 40,
			Text:     "Populate missing context values in context YAML and rerun.",
		},
		"REMEDIATE_TOP_FINDING": {
			ID:       "REMEDIATE_TOP_FINDING",
			Priority: 50,
			Text:     "Fix highest-risk unaccepted finding first.",
		},
		"REVIEW_ACCEPTED_RISK_EXPIRY": {
			ID:       "REVIEW_ACCEPTED_RISK_EXPIRY",
			Priority: 60,
			Text:     "Renew, close, or remediate accepted findings before SLA breach.",
		},
		"SECURITY_APPROVAL_REQUIRED": {
			ID:       "SECURITY_APPROVAL_REQUIRED",
			Priority: 70,
			Text:     "Obtain required local security approval record for scoped exception.",
		},
		"VALIDATE_POLICY_FILE": {
			ID:       "VALIDATE_POLICY_FILE",
			Priority: 80,
			Text:     "Correct policy YAML schema violations and rerun.",
		},
		"VALIDATE_ACCEPTED_RISK_FILE": {
			ID:       "VALIDATE_ACCEPTED_RISK_FILE",
			Priority: 90,
			Text:     "Correct accepted risk file and rerun.",
		},
	}
}
