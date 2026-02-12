package llm

import "testing"

func TestValidateLLMOutput(t *testing.T) {
	allowed := []string{"ROTATE_SECRET", "ADD_ACCEPTED_RISK"}
	good := LLMOutput{
		NonAuthoritative:     true,
		DecisionStatus:       "WARN",
		Explanation:          "Non-authoritative explanation. System stayed deterministic.",
		RecommendedNextSteps: []string{"ROTATE_SECRET"},
	}
	if err := ValidateLLMOutput(good, allowed, "WARN"); err != nil {
		t.Fatalf("expected valid output, got %v", err)
	}

	badFlag := good
	badFlag.NonAuthoritative = false
	if err := ValidateLLMOutput(badFlag, allowed, "WARN"); err == nil {
		t.Fatalf("expected failure when non_authoritative=false")
	}

	missingLabel := good
	missingLabel.Explanation = "Everything is fine."
	if err := ValidateLLMOutput(missingLabel, allowed, "WARN"); err == nil {
		t.Fatalf("expected failure when explanation lacks label")
	}

	extraStep := good
	extraStep.RecommendedNextSteps = []string{"ROTATE_SECRET", "FIX_VULN"}
	if err := ValidateLLMOutput(extraStep, allowed, "WARN"); err == nil {
		t.Fatalf("expected failure when recommended step not allowed")
	}
}
