package securitygate

import "testing"

func TestRecommendedStepCatalogPriorityScale(t *testing.T) {
	catalog := recommendedStepCatalog()

	if got := catalog["FIX_HARD_STOP_IMMEDIATELY"].Priority; got != 100 {
		t.Fatalf("FIX_HARD_STOP_IMMEDIATELY priority=%d want=100", got)
	}
	if got := catalog["REFRESH_SCANS"].Priority; got != 300 {
		t.Fatalf("REFRESH_SCANS priority=%d want=300", got)
	}
}

func TestCollectRecommendedStepsOrdering(t *testing.T) {
	state := EngineState{
		Policy:         defaultPolicy(),
		EffectiveStage: "merge",
		HardStopDomains: []string{
			"HS_POLICY_INTEGRITY_BROKEN",
		},
		Trust: TrustResult{
			Penalties: []TrustPenalty{
				{Code: "SCAN_FRESHNESS_UNKNOWN_OR_STALE", Value: 15},
			},
		},
	}

	steps := collectRecommendedSteps(state, nil)
	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(steps))
	}
	if steps[0].ID != "FIX_HARD_STOP_IMMEDIATELY" || steps[0].Priority != 100 {
		t.Fatalf("step[0]=%+v want FIX_HARD_STOP_IMMEDIATELY priority=100", steps[0])
	}
	if steps[1].ID != "REFRESH_SCANS" || steps[1].Priority != 300 {
		t.Fatalf("step[1]=%+v want REFRESH_SCANS priority=300", steps[1])
	}
}
