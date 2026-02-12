package llm

import (
	"fmt"
	"strings"
)

// LLMOutput represents the minimal schema produced by the explanation assistant.
type LLMOutput struct {
	NonAuthoritative     bool     `json:"non_authoritative"`
	DecisionStatus       string   `json:"decision_status"`
	Explanation          string   `json:"explanation"`
	RecommendedNextSteps []string `json:"recommended_next_steps"`
	References           []string `json:"references"`
}

// ValidationError captures deterministic mismatches in LLM outputs.
type ValidationError struct {
	Reason string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("llm validation failed: %s", e.Reason)
}

// ValidateLLMOutput enforces the boundary: no new actions, required warning text, and correct status.
func ValidateLLMOutput(output LLMOutput, allowedSteps []string, expectedStatus string) error {
	if !output.NonAuthoritative {
		return ValidationError{Reason: "non_authoritative flag must be true"}
	}
	if !strings.Contains(output.Explanation, "Non-authoritative explanation.") {
		return ValidationError{Reason: "explanation must include 'Non-authoritative explanation.'"}
	}
	if output.DecisionStatus != expectedStatus {
		return ValidationError{Reason: fmt.Sprintf("decision_status mismatch: expected %s got %s", expectedStatus, output.DecisionStatus)}
	}
	allowed := make(map[string]struct{}, len(allowedSteps))
	for _, step := range allowedSteps {
		allowed[step] = struct{}{}
	}
	for _, step := range output.RecommendedNextSteps {
		if _, ok := allowed[step]; !ok {
			return ValidationError{Reason: fmt.Sprintf("recommended step %s not allowed", step)}
		}
	}
	return nil
}
